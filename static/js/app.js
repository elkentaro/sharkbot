const sessionId = document.body.dataset.sessionId;
const messagesEl = document.getElementById('messages');
const promptEl = document.getElementById('prompt');
const composerEl = document.getElementById('composer');
const clearBtnEl = document.getElementById('clearBtn');
const reconfigureAiBtnEl = document.getElementById('reconfigureAiBtn');
const contextBoxEl = document.getElementById('contextBox');
const providerSelectEl = document.getElementById('providerSelect');
const modelSelectEl = document.getElementById('modelSelect');
const saveSettingsBtnEl = document.getElementById('saveSettingsBtn');
const themeSelectEl = document.getElementById('themeSelect');

let currentProviders = [];
let currentSettings = null;
let requestInFlight = false;
let backendCardForcedOpen = false;

function applyTheme(theme) {
  const chosen = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = chosen;
  try { localStorage.setItem('smartFilterTheme', chosen); } catch (err) {}
  if (themeSelectEl) themeSelectEl.value = chosen;
}

function loadTheme() {
  let saved = 'dark';
  try { saved = localStorage.getItem('smartFilterTheme') || 'dark'; } catch (err) {}
  applyTheme(saved);
}


async function getJSON(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
  return res.json();
}

function escapeHtml(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}


function appendOptimisticExchange(text) {
  const userBubble = document.createElement('div');
  userBubble.className = 'msg user_message optimistic-user';
  userBubble.innerHTML = `<span class="label">You</span>${escapeHtml(text)}`;
  messagesEl.appendChild(userBubble);

  const assistantBubble = document.createElement('div');
  assistantBubble.className = 'msg assistant_text typing-indicator optimistic-assistant';
  assistantBubble.innerHTML = `<span class="label">Assistant</span><div class="typing-dots"><span>.</span><span>.</span><span>.</span></div>`;
  messagesEl.appendChild(assistantBubble);

  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function clearOptimisticExchange() {
  messagesEl.querySelectorAll('.optimistic-user, .optimistic-assistant').forEach((el) => el.remove());
}


function renderRichText(text) {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  let html = '';
  let inList = false;

  function closeList() {
    if (inList) {
      html += '</ul>';
      inList = false;
    }
  }

  function looksLikeFilterLine(s) {
    const trimmed = String(s || '').trim();
    if (!trimmed) return false;
    if (trimmed.length > 160) return false;
    if (/[:.]$/.test(trimmed)) return false;
    if (/^(summary|why it matters|what looks normal or unusual|useful next steps|normal|note)$/i.test(trimmed)) return false;
    return /(?:==|!=|&&|\|\||\b(?:eth|ip|ipv6|tcp|udp|dns|http|tls|arp|icmp|frame)\.[a-z_]+|\bframe\.number\b)/i.test(trimmed);
  }

  function fmtInline(s) {
    return escapeHtml(s)
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, (_, codeText) => {
        const className = looksLikeFilterLine(codeText) ? 'rich-filter-inline' : '';
        return `<code class="${className}">${codeText}</code>`;
      });
  }

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line.trim()) {
      closeList();
      continue;
    }

    const bulletMatch = line.match(/^[-*]\s+(.*)$/);
    const numberedMatch = line.match(/^\d+\.\s+(.*)$/);
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);

    if (bulletMatch || numberedMatch) {
      if (!inList) {
        html += '<ul class="rich-list">';
        inList = true;
      }
      const content = bulletMatch ? bulletMatch[1] : numberedMatch[1];
      html += `<li>${fmtInline(content)}</li>`;
      continue;
    }

    closeList();

    if (headingMatch) {
      const level = Math.min(headingMatch[1].length, 6);
      html += `<div class="rich-heading level-${level}">${fmtInline(headingMatch[2])}</div>`;
      continue;
    }

    // Treat bold headings like **Summary:** as section labels.
    if (/^\*\*.+\*\*:?$/.test(line.trim())) {
      html += `<div class="rich-heading">${fmtInline(line)}</div>`;
      continue;
    }

    if (looksLikeFilterLine(line)) {
      html += `<div class="rich-filter-line">${fmtInline(line)}</div>`;
      continue;
    }

    html += `<p class="rich-paragraph">${fmtInline(line)}</p>`;
  }
  closeList();
  return html || `<p class="rich-paragraph">${fmtInline(source)}</p>`;
}

function renderContext(context) {
  const lines = [
    `Frame: ${context.frame_number || '(none)'}`,
    `Protocol: ${context.packet_protocol || context.protocol_hint || '(unknown)'}`,
    `Source: ${context.ip_src || context.ipv6_src || context.eth_src || '(none)'}`,
    `Destination: ${context.ip_dst || context.ipv6_dst || context.eth_dst || '(none)'}`,
    `Selected IP: ${context.selected_ip || context.selected_ipv6 || '(none)'}`,
    `Selected MAC: ${context.selected_mac || '(none)'}`,
    `Current filter: ${context.current_filter || '(empty)'}`,
  ];
  contextBoxEl.textContent = lines.join('\n');
}

function fillProviderControls(providers, settings) {
  if (!providerSelectEl || !modelSelectEl) return;
  providerSelectEl.innerHTML = '';
  (providers || [])
    .filter((provider) => provider.id === 'rule_based' || provider.available !== false)
    .forEach((provider) => {
      const opt = document.createElement('option');
      opt.value = provider.id;
      opt.textContent = provider.label || provider.name || providerDisplayName(provider.id);
      if (provider.id === (settings?.provider || 'rule_based')) opt.selected = true;
      providerSelectEl.appendChild(opt);
    });
  rebuildModelSelect();
  if (settings?.model) modelSelectEl.value = settings.model;
}

function rebuildModelSelect() {
  if (!providerSelectEl || !modelSelectEl) return;
  const selectedProvider = providerSelectEl.value;
  const provider = (currentProviders || []).find((item) => item.id === selectedProvider);
  modelSelectEl.innerHTML = '';
  (provider?.models || ['builtin']).forEach((model) => {
    const opt = document.createElement('option');
    opt.value = model;
    opt.textContent = model;
    modelSelectEl.appendChild(opt);
  });
}

function makeChip(label, onClick) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'option-chip';
  btn.textContent = label;
  btn.addEventListener('click', onClick);
  return btn;
}

async function runSuggestedAction(prompt) {
  await sendMessage(prompt);
}

function composerShouldBeLocked(state) {
  return Boolean(state?.providers?.some((provider) => provider.id !== 'rule_based' && provider.available !== false)) && !state?.backend_confirmed;
}

function hasConfiguredAiProviders(state) {
  return Boolean(state?.providers?.some((provider) => provider.id !== 'rule_based' && provider.available !== false));
}

function syncComposerLock(state) {
  const locked = composerShouldBeLocked(state);
  if (promptEl) {
    promptEl.disabled = locked;
    promptEl.placeholder = locked
      ? 'Set the background AI backend to start this session...'
      : 'Ask about this packet or ask for a Wireshark display filter...';
  }
  const submitBtn = composerEl?.querySelector('button[type="submit"]');
  if (submitBtn) submitBtn.disabled = locked;
  if (composerEl) composerEl.classList.toggle('locked', locked);
}

function syncHeaderActions(state) {
  if (!reconfigureAiBtnEl) return;
  const canConfigure = hasConfiguredAiProviders(state);
  reconfigureAiBtnEl.hidden = !canConfigure;
  reconfigureAiBtnEl.textContent = backendCardForcedOpen ? 'Close AI Setup' : 'Reconfigure AI';
}

function renderMessage(message) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg ${message.type}`;
  if (message.type === 'system_notice') {
    wrapper.innerHTML = `<span class="label label-system">System</span>${escapeHtml(message.text)}`;
  } else if (message.type === 'assistant_text') {
    wrapper.innerHTML = `<span class="label">Assistant</span>${escapeHtml(message.text)}`;
  } else if (message.type === 'user_message' || message.type === 'user_choice') {
    wrapper.innerHTML = `<span class="label">You</span>${escapeHtml(message.text)}`;
  } else if (message.type === 'packet_summary') {
    const s = message.summary;
    wrapper.innerHTML = `<span class="label label-packet">Packet</span>
      Frame ${escapeHtml(s.frame)} · ${escapeHtml(s.protocol)}<br>
      Source: ${escapeHtml(s.source)}<br>
      Destination: ${escapeHtml(s.destination)}<br>
      Selected IP: ${escapeHtml(s.selected_ip)}<br>
      Selected MAC: ${escapeHtml(s.selected_mac)}<div class="meta-line">AI backend: ${escapeHtml(message.provider)} / ${escapeHtml(message.model)}</div>`;
  } else if (message.type === 'clarification') {
    wrapper.innerHTML = `<span class="label">Assistant</span>${escapeHtml(message.question)}`;
    const row = document.createElement('div');
    row.className = 'option-row';
    message.options.forEach((option) => row.appendChild(makeChip(option.label, async () => answerClarification(option.id))));
    wrapper.appendChild(row);
  } else if (message.type === 'filter_result') {
    const sourceLabel = message.response_source === 'fallback' ? 'AI failed, used fallback' : (message.response_source === 'rule_based' ? 'Rule-based filter' : 'Assistant');
    const labelClass = message.response_source === 'fallback'
      ? 'label label-error'
      : (message.response_source === 'rule_based' ? 'label label-rule' : 'label label-ai');
    wrapper.innerHTML = `<span class="${labelClass}">${escapeHtml(sourceLabel)}</span>${escapeHtml(message.explanation || 'Proposed filter')}`;
    const block = document.createElement('div');
    block.className = 'filter-block';
    block.textContent = message.filter;
    wrapper.appendChild(block);
    const row = document.createElement('div');
    row.className = 'option-row';
    row.appendChild(makeChip('Copy filter', async () => {
      await navigator.clipboard.writeText(message.filter);
    }));
    wrapper.appendChild(row);
    if (message.source_note) {
      const meta = document.createElement('div');
      meta.className = 'meta-line';
      meta.textContent = message.source_note;
      wrapper.appendChild(meta);
    }
    if (message.upgrade_suggestions?.length) {
      const title = document.createElement('div');
      title.className = 'upgrade-title';
      title.textContent = message.upgrade_title || 'Try an AI-assisted follow-up';
      wrapper.appendChild(title);
      const upgrades = document.createElement('div');
      upgrades.className = 'option-row';
      message.upgrade_suggestions.forEach((item) => upgrades.appendChild(makeChip(item.label, async () => runSuggestedAction(item.prompt))));
      wrapper.appendChild(upgrades);
    }
    wrapper.innerHTML += `<div class="meta-line">Backend: ${escapeHtml(message.provider || '')} / ${escapeHtml(message.model || '')}</div>`;
  } else if (message.type === 'explanation') {
    const sourceMap = { ai: 'AI-assisted answer', rule_based: 'Rule-based answer', fallback: 'AI failed, used fallback' };
    const labelClass = message.response_source === 'fallback'
      ? 'label label-error'
      : (message.response_source === 'rule_based' ? 'label label-rule' : 'label label-ai');
    wrapper.innerHTML = `<span class="${labelClass}">${escapeHtml(sourceMap[message.response_source] || 'Assistant')}</span>${escapeHtml(message.title || 'Packet explanation')}`;
    const block = document.createElement('div');
    block.className = 'rich-block';
    block.innerHTML = renderRichText(message.text);
    wrapper.appendChild(block);
    if (message.source_note) {
      const meta = document.createElement('div');
      meta.className = 'meta-line';
      meta.textContent = message.source_note;
      wrapper.appendChild(meta);
    }
    if (message.upgrade_suggestions?.length) {
      const title = document.createElement('div');
      title.className = 'upgrade-title';
      title.textContent = message.upgrade_title || 'Try an AI-assisted follow-up';
      wrapper.appendChild(title);
      const upgrades = document.createElement('div');
      upgrades.className = 'option-row';
      message.upgrade_suggestions.forEach((item) => upgrades.appendChild(makeChip(item.label, async () => runSuggestedAction(item.prompt))));
      wrapper.appendChild(upgrades);
    }
    if (message.suggested_actions?.length) {
      const title = document.createElement('div');
      title.className = 'upgrade-title';
      title.textContent = 'Based on this analysis';
      wrapper.appendChild(title);
      const row = document.createElement('div');
      row.className = 'option-row';
      message.suggested_actions.forEach((item) => row.appendChild(makeChip(item.label, async () => runSuggestedAction(item.prompt))));
      wrapper.appendChild(row);
    }
    const meta = document.createElement('div');
    meta.className = 'meta-line';
    meta.textContent = `Backend: ${message.provider || ''} / ${message.model || ''}`;
    wrapper.appendChild(meta);
  } else if (message.type === 'suggested_actions') {
    wrapper.innerHTML = `<span class="label">Assistant</span>${escapeHtml(message.title || 'Suggested actions')}`;
    const row = document.createElement('div');
    row.className = 'option-row';
    message.items.forEach((item) => row.appendChild(makeChip(item.label, async () => runSuggestedAction(item.prompt))));
    wrapper.appendChild(row);
  } else if (message.type === 'error') {
    wrapper.innerHTML = `<span class="label">Assistant</span>${escapeHtml(message.text)}`;
  } else {
    wrapper.innerHTML = `<span class="label">Assistant</span>${escapeHtml(JSON.stringify(message))}`;
  }
  return wrapper;
}

function renderMessages(messages) {
  messagesEl.innerHTML = '';
  messages.forEach((msg) => messagesEl.appendChild(renderMessage(msg)));
  messagesEl.scrollTop = messagesEl.scrollHeight;
}


function providerDisplayName(providerId) {
  const map = {
    rule_based: 'Rule-based',
    openai: 'OpenAI',
    anthropic: 'Claude',
    gemini: 'Gemini',
    ollama: 'Ollama',
  };
  return map[providerId] || providerId || 'Unknown';
}

function makeBackendOnboardingCard(settings, providers) {
  const currentProvider = settings?.provider || 'rule_based';
  const currentModel = settings?.model || 'builtin';
  const aiProviders = (providers || []).filter((provider) => provider.id !== 'rule_based' && provider.available !== false);

  const wrapper = document.createElement('div');
  wrapper.className = 'msg backend-onboarding';

  const label = document.createElement('span');
  label.className = 'label';
  label.textContent = 'Assistant';
  wrapper.appendChild(label);

  const title = document.createElement('div');
  title.className = 'backend-card-title';
  wrapper.appendChild(title);

  const body = document.createElement('div');
  body.className = 'backend-card-body';
  wrapper.appendChild(body);

  if (!aiProviders.length) {
    title.textContent = 'No configured AI backends found';
    body.textContent = 'Replies will stay rule-based until you add an API key or local backend configuration for OpenAI, Claude, Gemini, or Ollama.';
    return wrapper;
  }

  let chosenProviderId = (aiProviders.find((p) => p.id === currentProvider) || aiProviders[0]).id;
  let chosenModel = currentModel;

  const controls = document.createElement('div');
  controls.className = 'backend-inline-controls';

  const providerLabel = document.createElement('label');
  providerLabel.className = 'field-label';
  providerLabel.textContent = 'Provider';
  providerLabel.setAttribute('for', 'inlineProviderSelect');
  controls.appendChild(providerLabel);

  const providerSelect = document.createElement('select');
  providerSelect.id = 'inlineProviderSelect';
  providerSelect.className = 'inline-select';
  aiProviders.forEach((provider) => {
    const opt = document.createElement('option');
    opt.value = provider.id;
    opt.textContent = provider.label || provider.name || providerDisplayName(provider.id);
    if (provider.id === chosenProviderId) opt.selected = true;
    providerSelect.appendChild(opt);
  });
  controls.appendChild(providerSelect);

  const modelLabel = document.createElement('label');
  modelLabel.className = 'field-label';
  modelLabel.textContent = 'Model';
  modelLabel.setAttribute('for', 'inlineModelSelect');
  controls.appendChild(modelLabel);

  const modelSelect = document.createElement('select');
  modelSelect.id = 'inlineModelSelect';
  modelSelect.className = 'inline-select';
  controls.appendChild(modelSelect);

  function refreshCopy() {
    const alreadyConfigured = currentProvider !== 'rule_based';
    title.textContent = alreadyConfigured
      ? `Reconfigure background AI assistance: ${providerDisplayName(chosenProviderId)} / ${chosenModel}`
      : `Set background AI assistance: ${providerDisplayName(chosenProviderId)} / ${chosenModel}`;
    body.textContent = alreadyConfigured
      ? 'Choose a different provider or model, then save to update the session backend. Rule-based replies still stay the default unless you use +AI or a provider suffix.'
      : 'Pick one of the configured AI backends to start this session. The packet summary and suggested next steps will appear after you confirm it.';
  }

  function rebuildModels() {
    modelSelect.innerHTML = '';
    const provider = aiProviders.find((p) => p.id === providerSelect.value) || aiProviders[0];
    chosenProviderId = provider.id;
    const models = provider.models || ['builtin'];
    if (!models.includes(chosenModel)) chosenModel = models[0] || 'builtin';
    models.forEach((model) => {
      const opt = document.createElement('option');
      opt.value = model;
      opt.textContent = model;
      if (model === chosenModel) opt.selected = true;
      modelSelect.appendChild(opt);
    });
    refreshCopy();
  }

  rebuildModels();
  providerSelect.addEventListener('change', rebuildModels);
  modelSelect.addEventListener('change', () => {
    chosenModel = modelSelect.value;
    refreshCopy();
  });

  wrapper.appendChild(controls);

  const actions = document.createElement('div');
  actions.className = 'backend-inline-actions';
  const saveBtn = document.createElement('button');
  saveBtn.type = 'button';
  saveBtn.className = 'chip primary-chip';
  saveBtn.textContent = 'Use this backend';
  saveBtn.addEventListener('click', async () => {
    if (providerSelectEl) providerSelectEl.value = providerSelect.value;
    if (typeof rebuildModelSelect === 'function') rebuildModelSelect();
    if (modelSelectEl) modelSelectEl.value = modelSelect.value;
    await saveSettings();
  });
  actions.appendChild(saveBtn);
  wrapper.appendChild(actions);

  return wrapper;
}

function appendRenderedMessage(message) {
  messagesEl.appendChild(renderMessage(message));
}


function renderState(state) {
  messagesEl.innerHTML = '';
  renderContext(state.context);
  currentProviders = state.providers || currentProviders;
  currentSettings = state.settings || currentSettings;
  fillProviderControls(currentProviders, currentSettings);
  syncComposerLock(state);
  syncHeaderActions(state);

  const messages = state.messages || [];
  const systemNotice = messages.find((m) => m.type === 'system_notice');
  const rest = messages.filter((m) => m.type !== 'system_notice');

  if (systemNotice) appendRenderedMessage(systemNotice);
  if (backendCardForcedOpen || composerShouldBeLocked(state) || !hasConfiguredAiProviders(state)) {
    messagesEl.appendChild(makeBackendOnboardingCard(currentSettings || state.settings || {}, currentProviders || []));
  }
  rest.forEach((message) => appendRenderedMessage(message));

  messagesEl.scrollTop = messagesEl.scrollHeight;
}

async function loadSession() {
  const state = await getJSON(`/api/session/${sessionId}`);
  renderState(state);
}

async function sendMessage(text) {
  const value = String(text || '').trim();
  if (!value || requestInFlight) return;

  requestInFlight = true;
  promptEl.value = '';
  composerEl.classList.add('busy');

  appendOptimisticExchange(value);

  setTimeout(async () => {
    try {
      const state = await getJSON(`/api/session/${sessionId}/message`, {
        method: 'POST',
        body: JSON.stringify({ text: value }),
      });
      clearOptimisticExchange();
      renderState(state);
    } catch (err) {
      clearOptimisticExchange();
      console.error(err);
    } finally {
      requestInFlight = false;
      composerEl.classList.remove('busy');
      promptEl.focus();
    }
  }, 0);
}

async function answerClarification(optionId) {
  if (requestInFlight) return;
  requestInFlight = true;
  composerEl.classList.add('busy');

  const chosen = document.createElement('div');
  chosen.className = 'msg user_choice optimistic-user';
  chosen.innerHTML = `<span class="label">You</span>${escapeHtml(optionId)}`;
  messagesEl.appendChild(chosen);

  const assistantBubble = document.createElement('div');
  assistantBubble.className = 'msg assistant_text typing-indicator optimistic-assistant';
  assistantBubble.innerHTML = `<span class="label">Assistant</span><div class="typing-dots"><span>.</span><span>.</span><span>.</span></div>`;
  messagesEl.appendChild(assistantBubble);
  messagesEl.scrollTop = messagesEl.scrollHeight;

  setTimeout(async () => {
    try {
      const state = await getJSON(`/api/session/${sessionId}/clarification`, {
        method: 'POST',
        body: JSON.stringify({ option_id: optionId }),
      });
      clearOptimisticExchange();
      renderState(state);
    } catch (err) {
      clearOptimisticExchange();
      console.error(err);
    } finally {
      requestInFlight = false;
      composerEl.classList.remove('busy');
      promptEl.focus();
    }
  }, 0);
}

async function saveSettings() {
  if (!providerSelectEl || !modelSelectEl) return;
  const chosenProvider = providerSelectEl.value;
  const chosenModel = modelSelectEl.value;
  const state = await getJSON(`/api/session/${sessionId}/settings`, {
    method: 'POST',
    body: JSON.stringify({ provider: chosenProvider, model: chosenModel }),
  });
  backendCardForcedOpen = false;
  renderState(state);
}

composerEl.addEventListener('submit', async (event) => {
  event.preventDefault();
  const text = promptEl.value.trim();
  if (!text) return;
  await sendMessage(text);
});

if (providerSelectEl) providerSelectEl.addEventListener('change', rebuildModelSelect);
if (saveSettingsBtnEl) saveSettingsBtnEl.addEventListener('click', saveSettings);
if (reconfigureAiBtnEl) {
  reconfigureAiBtnEl.addEventListener('click', async () => {
    backendCardForcedOpen = !backendCardForcedOpen;
    renderState(await getJSON(`/api/session/${sessionId}`));
  });
}
clearBtnEl.addEventListener('click', async () => renderState(await getJSON(`/api/session/${sessionId}/clear`, { method: 'POST' })));
if (themeSelectEl) themeSelectEl.addEventListener('change', () => applyTheme(themeSelectEl.value));

loadTheme();
loadSession().catch((err) => {
  messagesEl.innerHTML = `<div class="msg error"><span class="label">Assistant</span>${escapeHtml(String(err))}</div>`;
});
