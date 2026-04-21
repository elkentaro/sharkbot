const sessionId = document.body.dataset.sessionId;
const messagesEl = document.getElementById('messages');
const promptEl = document.getElementById('prompt');
const composerEl = document.getElementById('composer');
const clearBtnEl = document.getElementById('clearBtn');
const reconfigureAiBtnEl = document.getElementById('reconfigureAiBtn');
const copySessionIdBtnEl = document.getElementById('copySessionIdBtn');
const exportChatBtnEl = document.getElementById('exportChatBtn');
const playbookStatusEl = document.getElementById('playbookStatus');
const providerSelectEl = document.getElementById('providerSelect');
const modelSelectEl = document.getElementById('modelSelect');
const saveSettingsBtnEl = document.getElementById('saveSettingsBtn');
const themeSelectEl = document.getElementById('themeSelect');

const PREFERRED_BACKEND_COOKIE = 'sharkbot_preferred_backend';

let currentProviders = [];
let currentSettings = null;
let requestInFlight = false;
let backendCardForcedOpen = false;
let preferredBackendAutoApplied = false;

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

function getCookie(name) {
  const encoded = encodeURIComponent(name) + '=';
  const parts = document.cookie.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith(encoded)) {
      return decodeURIComponent(trimmed.slice(encoded.length));
    }
  }
  return '';
}

function setCookie(name, value, maxAgeSeconds) {
  document.cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}; path=/; max-age=${maxAgeSeconds}; SameSite=Lax`;
}

function loadPreferredBackend() {
  const raw = getCookie(PREFERRED_BACKEND_COOKIE);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    if (typeof parsed.provider !== 'string' || typeof parsed.model !== 'string') return null;
    return { provider: parsed.provider, model: parsed.model };
  } catch (err) {
    return null;
  }
}

function savePreferredBackend(provider, model) {
  if (!provider || provider === 'rule_based') return;
  setCookie(PREFERRED_BACKEND_COOKIE, JSON.stringify({ provider, model }), 60 * 60 * 24 * 180);
}

function resolvePreferredBackend(state) {
  const preferred = loadPreferredBackend();
  if (!preferred) return null;
  const provider = (state?.providers || []).find((item) => item.id === preferred.provider && item.id !== 'rule_based' && item.available !== false);
  if (!provider) return null;
  const model = (provider.models || []).includes(preferred.model) ? preferred.model : (provider.models || [])[0];
  if (!model) return null;
  return { provider: provider.id, model };
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
  return context;
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

function splitPlaybookAction(items) {
  const source = Array.isArray(items) ? items : [];
  const playbookAction = source.find((item) => item?.kind === 'playbook_open' || item?.id === 'use_playbook') || null;
  const remaining = source.filter((item) => item !== playbookAction);
  return { playbookAction, remaining };
}

function appendPlaybookCta(wrapper, item) {
  if (!item) return;
  const cta = document.createElement('div');
  cta.className = 'playbook-cta-card';

  const title = document.createElement('div');
  title.className = 'playbook-cta-title';
  title.textContent = 'Guided Analysis';
  cta.appendChild(title);

  const body = document.createElement('div');
  body.className = 'playbook-cta-body';
  body.textContent = 'Use a playbook to switch from general packet help into guided investigation steps tailored to a specific analysis style.';
  cta.appendChild(body);

  const actions = document.createElement('div');
  actions.className = 'playbook-cta-actions';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'playbook-cta-button';
  btn.textContent = item.label || 'Use Playbook';
  btn.addEventListener('click', async () => runSuggestedAction(item));
  actions.appendChild(btn);
  cta.appendChild(actions);

  wrapper.appendChild(cta);
}

function appendSourceNote(wrapper, message) {
  if (!message?.source_note) return;
  const row = document.createElement('div');
  row.className = 'meta-pill-row';

  const pill = document.createElement('span');
  pill.className = message.response_source === 'fallback'
    ? 'label label-error'
    : (message.response_source === 'rule_based' ? 'label label-rule' : 'label label-ai');
  pill.textContent = message.response_source === 'fallback'
    ? 'Fallback note'
    : (message.response_source === 'rule_based' ? 'Built-in logic' : 'AI note');
  row.appendChild(pill);

  const text = document.createElement('span');
  text.className = 'meta-note';
  text.textContent = message.source_note;
  row.appendChild(text);
  wrapper.appendChild(row);
}

async function runSuggestedAction(prompt) {
  if (typeof prompt === 'string') return sendMessage(prompt);
  const item = prompt || {};
  return sendActionItem(item);
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

function syncPlaybookStatus(state) {
  if (!playbookStatusEl) return;
  const playbook = state?.playbook;
  if (!playbook) {
    playbookStatusEl.hidden = true;
    playbookStatusEl.innerHTML = '';
    return;
  }
  playbookStatusEl.hidden = false;
  playbookStatusEl.innerHTML = `
    <div class="playbook-status-title">Playbook Active</div>
    <div class="playbook-status-name">${escapeHtml(playbook.name || 'Guided Analysis')}</div>
    <div class="playbook-status-desc">${escapeHtml(playbook.description || 'Guided playbook analysis is active for this investigation.')}</div>`;
}

async function maybeApplyPreferredBackend(state) {
  if (preferredBackendAutoApplied) return state;
  preferredBackendAutoApplied = true;
  if (!composerShouldBeLocked(state)) return state;

  const preferred = resolvePreferredBackend(state);
  if (!preferred) return state;

  try {
    return await getJSON(`/api/session/${sessionId}/settings`, {
      method: 'POST',
      body: JSON.stringify(preferred),
    });
  } catch (err) {
    console.error(err);
    return state;
  }
}

async function copySessionId() {
  try {
    await navigator.clipboard.writeText(sessionId);
    if (copySessionIdBtnEl) {
      const previous = copySessionIdBtnEl.textContent;
      copySessionIdBtnEl.textContent = 'Copied';
      setTimeout(() => {
        copySessionIdBtnEl.textContent = previous;
      }, 1200);
    }
  } catch (err) {
    console.error(err);
  }
}

function downloadInvestigation() {
  window.location.href = `/api/session/${sessionId}/export`;
}

async function sendActionItem(item) {
  if (requestInFlight) return;
  const action = item || {};
  if (!action.prompt && !action.kind) return;

  requestInFlight = true;
  composerEl.classList.add('busy');
  appendOptimisticExchange(action.label || action.prompt || 'Action');

  setTimeout(async () => {
    try {
      const state = await getJSON(`/api/session/${sessionId}/action`, {
        method: 'POST',
        body: JSON.stringify(action),
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

function renderMessage(message) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg ${message.type}`;
  if (message.type === 'system_notice') {
    wrapper.innerHTML = `<span class="label label-system">System</span>${escapeHtml(message.text)}`;
  } else if (message.type === 'assistant_text') {
    wrapper.innerHTML = `<span class="label label-assistant">Assistant</span>${escapeHtml(message.text)}`;
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
    wrapper.innerHTML = `<span class="label label-assistant">Assistant</span>${escapeHtml(message.question)}`;
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
    row.appendChild(makeChip('Explain filter +AI', async () => runSuggestedAction({
      kind: 'filter_explain_ai',
      label: 'Explain filter +AI',
      prompt: message.filter,
    })));
    wrapper.appendChild(row);
    if (message.request_mode === 'playbook' && message.playbook) {
      const confirm = document.createElement('div');
      confirm.className = 'filter-confirm';
      const confirmTitle = document.createElement('div');
      confirmTitle.className = 'filter-confirm-title';
      confirmTitle.textContent = `Playbook checkpoint: ${message.playbook.name}`;
      confirm.appendChild(confirmTitle);

      const confirmNote = document.createElement('div');
      confirmNote.className = 'filter-confirm-note';
      confirmNote.textContent = 'After you apply this filter in Wireshark, confirm it here and SharkBot will suggest the next playbook step.';
      confirm.appendChild(confirmNote);

      const noteInput = document.createElement('input');
      noteInput.type = 'text';
      noteInput.className = 'filter-confirm-input';
      noteInput.placeholder = 'Optional: what did you notice after applying it?';
      confirm.appendChild(noteInput);

      const confirmActions = document.createElement('div');
      confirmActions.className = 'option-row';
      confirmActions.appendChild(makeChip('I applied this filter', async () => runSuggestedAction({
        kind: 'filter_applied',
        label: 'I applied this filter',
        prompt: message.filter,
        origin_prompt: message.origin_prompt || '',
        note: noteInput.value.trim(),
      })));
      confirm.appendChild(confirmActions);
      wrapper.appendChild(confirm);
    }
    appendSourceNote(wrapper, message);
    if (message.upgrade_suggestions?.length) {
      const title = document.createElement('div');
      title.className = 'upgrade-title';
      title.textContent = message.upgrade_title || 'Try an AI-assisted follow-up';
      wrapper.appendChild(title);
      const upgrades = document.createElement('div');
      upgrades.className = 'option-row';
      message.upgrade_suggestions.forEach((item) => upgrades.appendChild(makeChip(item.label, async () => runSuggestedAction(item))));
      wrapper.appendChild(upgrades);
    }
    const backendMeta = document.createElement('div');
    backendMeta.className = 'meta-line';
    backendMeta.textContent = `Backend: ${message.provider || ''} / ${message.model || ''}`;
    wrapper.appendChild(backendMeta);
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
    appendSourceNote(wrapper, message);
    if (message.upgrade_suggestions?.length) {
      const title = document.createElement('div');
      title.className = 'upgrade-title';
      title.textContent = message.upgrade_title || 'Try an AI-assisted follow-up';
      wrapper.appendChild(title);
      const upgrades = document.createElement('div');
      upgrades.className = 'option-row';
      message.upgrade_suggestions.forEach((item) => upgrades.appendChild(makeChip(item.label, async () => runSuggestedAction(item))));
      wrapper.appendChild(upgrades);
    }
    if (message.suggested_actions?.length) {
      const title = document.createElement('div');
      title.className = 'upgrade-title';
      title.textContent = 'Based on this analysis';
      wrapper.appendChild(title);
      const row = document.createElement('div');
      row.className = 'option-row';
      message.suggested_actions.forEach((item) => row.appendChild(makeChip(item.label, async () => runSuggestedAction(item))));
      if (message.suggested_actions.length) wrapper.appendChild(row);
    }
    const meta = document.createElement('div');
    meta.className = 'meta-line';
    meta.textContent = `Backend: ${message.provider || ''} / ${message.model || ''}`;
    wrapper.appendChild(meta);
  } else if (message.type === 'suggested_actions') {
    wrapper.innerHTML = `<span class="label label-assistant">Assistant</span>${escapeHtml(message.title || 'Suggested actions')}`;
    if (message.text) {
      const body = document.createElement('div');
      body.className = 'playbook-inline-body';
      body.textContent = message.text;
      wrapper.appendChild(body);
    }
    const { playbookAction, remaining } = splitPlaybookAction(message.items);
    const showDedicatedPlaybookCta = /based on this analysis|back to generic guidance|continue this investigation/i.test(message.title || '');
    if (showDedicatedPlaybookCta) appendPlaybookCta(wrapper, playbookAction);
    const row = document.createElement('div');
    row.className = 'option-row';
    remaining.forEach((item) => row.appendChild(makeChip(item.label, async () => runSuggestedAction(item))));
    if (remaining.length) wrapper.appendChild(row);
  } else if (message.type === 'playbook_selector') {
    wrapper.classList.add('playbook-inline-card');
    wrapper.innerHTML = `<span class="label label-assistant">Assistant</span>${escapeHtml(message.title || 'Choose a playbook')}`;
    const body = document.createElement('div');
    body.className = 'playbook-inline-body';
    body.textContent = message.text || 'Choose a playbook to guide the investigation.';
    wrapper.appendChild(body);

    const playbooks = message.playbooks || [];
    if (playbooks.length) {
      const recommendedId = message.recommended_playbook?.id || message.active_playbook?.id || playbooks[0]?.id || '';

      const selectLabel = document.createElement('label');
      selectLabel.className = 'field-label';
      selectLabel.textContent = 'Playbook';
      wrapper.appendChild(selectLabel);

      const select = document.createElement('select');
      select.className = 'inline-select playbook-inline-select';
      playbooks.forEach((playbook) => {
        const opt = document.createElement('option');
        opt.value = playbook.id;
        opt.textContent = playbook.name;
        if (playbook.id === recommendedId) opt.selected = true;
        select.appendChild(opt);
      });
      wrapper.appendChild(select);

      const preview = playbooks.find((item) => item.id === recommendedId) || playbooks[0];
      const summary = document.createElement('div');
      summary.className = 'playbook-inline-body';
      summary.textContent = preview?.description || '';
      wrapper.appendChild(summary);

      const actions = document.createElement('div');
      actions.className = 'playbook-inline-actions';

      const useBtn = document.createElement('button');
      useBtn.type = 'button';
      useBtn.className = 'secondary';
      const syncSelectorControls = () => {
        const selectedId = select.value;
        useBtn.textContent = message.active_playbook?.id === selectedId ? 'Playbook Active' : 'Use Playbook';
        useBtn.disabled = message.active_playbook?.id === selectedId;
      };
      syncSelectorControls();
      useBtn.addEventListener('click', async () => savePlaybookSelection(select.value));
      actions.appendChild(useBtn);

      if (message.active_playbook) {
        const clearBtn = document.createElement('button');
        clearBtn.type = 'button';
        clearBtn.className = 'secondary';
        clearBtn.textContent = 'Clear Playbook';
        clearBtn.addEventListener('click', async () => runSuggestedAction({ kind: 'playbook_clear', label: 'Clear Playbook' }));
        actions.appendChild(clearBtn);
      }
      wrapper.appendChild(actions);

      select.addEventListener('change', () => {
        const next = playbooks.find((item) => item.id === select.value);
        summary.textContent = next?.description || '';
        syncSelectorControls();
      });
    }
  } else if (message.type === 'error') {
    wrapper.innerHTML = `<span class="label label-assistant">Assistant</span>${escapeHtml(message.text)}`;
  } else {
    wrapper.innerHTML = `<span class="label label-assistant">Assistant</span>${escapeHtml(JSON.stringify(message))}`;
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

async function savePlaybookSelection(playbookId) {
  if (!playbookId) return;
  const state = await getJSON(`/api/session/${sessionId}/playbook`, {
    method: 'POST',
    body: JSON.stringify({ playbook_id: playbookId }),
  });
  renderState(state);
}

async function clearPlaybookSelection() {
  const state = await getJSON(`/api/session/${sessionId}/playbook`, {
    method: 'POST',
    body: JSON.stringify({ playbook_id: '' }),
  });
  renderState(state);
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
  syncPlaybookStatus(state);

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
  let state = await getJSON(`/api/session/${sessionId}`);
  state = await maybeApplyPreferredBackend(state);
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
  savePreferredBackend(chosenProvider, chosenModel);
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
if (copySessionIdBtnEl) copySessionIdBtnEl.addEventListener('click', copySessionId);
if (exportChatBtnEl) exportChatBtnEl.addEventListener('click', downloadInvestigation);
clearBtnEl.addEventListener('click', async () => renderState(await getJSON(`/api/session/${sessionId}/clear`, { method: 'POST' })));
if (themeSelectEl) themeSelectEl.addEventListener('change', () => applyTheme(themeSelectEl.value));

loadTheme();
loadSession().catch((err) => {
  messagesEl.innerHTML = `<div class="msg error"><span class="label">Assistant</span>${escapeHtml(String(err))}</div>`;
});
