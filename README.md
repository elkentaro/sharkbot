<img src="sharkbot.jpeg" width="200">

# SharkBot

SharkBot is a Wireshark companion app for packet explanation and display-filter generation.

Current release: `v1.7.2`

Workflow:

1. The user selects a packet in Wireshark.
2. The Lua helper sends packet context to the Python receiver.
3. The receiver opens a browser session for that packet.
4. The browser asks the user to choose a configured AI backend.
5. The user works from suggested actions, packet explanations, and generated filters until they get the view they need.

The app keeps rule-based behavior as the default path for normal questions. AI is only used when the user explicitly asks for it with `+AI` or a provider suffix like `+Claude`.

The default AI prompt profile is `specialist`, which combines packet-analysis depth with incident-response triage thinking while acting as a training aid for developing analysts.

## What SharkBot Is For

SharkBot is meant to help a user work through a packet capture in Wireshark without needing to already know the next correct filter, protocol pivot, or triage step.

It is designed for:

- explaining the currently selected packet in plain analyst terms
- suggesting the next safe Wireshark filter or investigation step
- guiding a beginner through a packet-analysis workflow
- helping a SOC L1-style analyst scope traffic before deciding whether something is normal, broken, or suspicious

It is not meant to magically solve an incident from one packet. The intended workflow is iterative: inspect a packet, narrow the traffic, confirm what changed, and keep moving through the capture.

## Example Scenario

Example: a user opens a PCAP because a workstation had slow HTTPS connections and a few users reported timeouts.

1. In Wireshark, the user selects one TCP packet from the affected host.
2. They launch SharkBot from the packet menu.
3. SharkBot explains what the selected packet is and suggests the next step, such as showing the TCP conversation.
4. The user applies that filter in Wireshark and checks whether the stream shows retransmissions, duplicate ACKs, resets, or just normal traffic.
5. The user returns to SharkBot, confirms what they applied, and follows the next guided step.
6. If the flow stops being obvious, SharkBot can use AI to recommend and teach the next Wireshark action rather than just giving a conclusion.
7. The user keeps narrowing scope until they can answer a basic question such as:
   - is this one conversation or a broader host problem?
   - is the traffic normal, noisy, misconfigured, or suspicious?
   - what should I inspect next in the PCAP?

This is the intended use model for the app: SharkBot helps the user learn the workflow while they analyze the capture.

## Setup

### Requirements

- Python 3.11 or newer
- Wireshark with Lua enabled
- `curl` on the machine running Wireshark
- a browser on the machine running Wireshark

Optional:

- OpenAI API key
- Anthropic API key
- Gemini API key
- Ollama running locally or remotely

### Python Receiver

From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.toml.example config.toml
```

The receiver reads `config.toml` from the current directory by default.

To use a different config file:

```bash
SMART_FILTER_CONFIG=/path/to/config.toml python receiver_app.py
```

### Receiver Configuration

Example `config.toml`:

```toml
[receiver]
host = "127.0.0.1"
# bind_host = "0.0.0.0"
# public_base_url = "http://192.168.1.50:8765"
port = 8765

[defaults]
provider = "rule_based"
model = "builtin"

[assistant]
profile = "specialist"
name = "SharkBot"
# custom_instructions = """
# Prioritize suspicious east-west traffic and give Wireshark filters on their own lines.
# """
# prompt_file = "assistant_prompt.txt"

[providers.openai]
api_key = ""

[providers.anthropic]
api_key = ""

[providers.gemini]
api_key = ""

[providers.ollama]
# Uncomment if you want Ollama available in the UI and for automatic fallback.
# base_url = "http://127.0.0.1:11434"

[advanced]
timeout_seconds = 45
```

Receiver keys:

- `host`: legacy/default receiver host value
- `bind_host`: interface Flask should listen on
- `public_base_url`: URL the Wireshark machine should open in its browser
- `port`: receiver port

If the configured default provider is unavailable, the app falls back to `rule_based`.

### Assistant Profiles

Supported built-in profiles:

- `specialist`: training-first packet analyst plus incident-response triage
- `packet_analyst`: training-first packet/protocol interpretation focus
- `incident_response`: training-first incident scoping, compromise indicators, and containment-oriented guidance

Optional prompt tuning:

- `name`: assistant name used in the AI priming instructions
- `custom_instructions`: inline local guidance appended to the built-in profile
- `prompt_file`: path to a text file with longer custom instructions

Keep custom prompt tuning aligned with the training-aid approach:

- teach the user why a step comes next, not just the answer
- prefer Wireshark workflows such as Follow Stream, Conversations, Endpoints, and Protocol Hierarchy when they are better learning pivots than another narrow filter
- separate confirmed packet evidence from inference

### AI Provider Setup

OpenAI:

```toml
[providers.openai]
api_key = "YOUR_OPENAI_KEY"
```

Anthropic:

```toml
[providers.anthropic]
api_key = "YOUR_ANTHROPIC_KEY"
```

Gemini:

```toml
[providers.gemini]
api_key = "YOUR_GEMINI_KEY"
```

Ollama:

```toml
[providers.ollama]
base_url = "http://127.0.0.1:11434"
```

If you use Ollama locally:

```bash
ollama pull llama3.1
```

### Wireshark Lua Client

Copy [`smart_filter.lua`](smart_filter.lua) into a Wireshark Lua plugin directory and restart Wireshark.

Common notes:

- macOS app-bundle testing often uses `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`
- personal plugin directories vary by OS and install method

At the top of the Lua file:

```lua
local RECEIVER_BASE = os.getenv("SMART_FILTER_RECEIVER") or "http://127.0.0.1:8765"
```

You can either:

- edit `RECEIVER_BASE` directly
- or set `SMART_FILTER_RECEIVER` in the Wireshark launch environment

Remote receiver note:

- do not use `0.0.0.0` in the Lua client
- use a real reachable URL such as `http://192.168.1.50:8765`

The Lua client posts packet context to `/api/session`, receives `session_id` plus `web_url`, and opens the returned browser URL.

## Run

### Local

```bash
source .venv/bin/activate
python receiver_app.py
```

The receiver starts on the configured host and port. Debug mode is off by default.

If you explicitly want Flask debug mode while developing:

```bash
python receiver_app.py --debug
```

### Remote / Headless Receiver

Use separate bind and browser-facing addresses:

```toml
[receiver]
host = "127.0.0.1"
bind_host = "0.0.0.0"
public_base_url = "http://192.168.1.50:8765"
port = 8765
```

Important:

- `bind_host = "0.0.0.0"` is for listening, not for the client URL
- `public_base_url` must be reachable from the Wireshark machine
- the Lua client must point to the same reachable receiver

### Basic Checks

Useful quick checks:

```bash
python3 -m py_compile receiver_app.py core/config.py core/providers/*.py
curl -sS http://127.0.0.1:8765/api/providers
```

## Usage

### Session Flow

1. Start the receiver.
2. Open Wireshark.
3. Select a packet.
4. Right-click the packet and choose `SharkBot: New Investigation`.
5. Let the Lua helper open the browser session.
6. Choose a configured AI backend in the browser.
7. Ask questions or click suggested actions until you get the explanation or filter you need.
8. After narrowing the capture in Wireshark, select a new packet and use a continue action to keep working in the same investigation.

### Chat Behavior

- if one or more AI backends are configured, the chat stays locked until the user confirms one backend
- after backend selection, the UI shows the AI-ready notice, usage guidance, the target packet card, and suggested next steps
- normal questions still default to rule-based logic
- AI is used only for prompts ending in `+AI`, `+OpenAI`, `+Claude`, `+Gemini`, or `+Ollama`
- if a live AI call fails, the app falls back to rule-based output and labels that clearly

### Continuing An Investigation

SharkBot investigation sessions are kept in memory on the receiver. That means you can move back and forth between Wireshark and the companion app during one running investigation, as long as the receiver process stays up.

New Lua actions are available for this:

- `SharkBot: New Investigation`
- `SharkBot: Continue Current Investigation`
- `SharkBot: Continue Investigation by ID`

The bottom-left sidebar usage section shows the investigation ID along with `Copy ID` and `Download Chat`. If Wireshark no longer remembers the current investigation ID, copy it from that section and use `Continue Investigation by ID`.

When you continue an investigation from Wireshark, the server appends:

- a context-updated notice
- a new packet summary card
- refreshed suggested next steps

The previous chat history stays intact.

### Downloading The Investigation

Use `Download Chat` in the bottom-left sidebar usage section to export the current investigation as a Markdown file for reference.

Examples:

```text
Explain this packet
Explain this packet +AI
Explain this packet +Claude
Show all traffic involving this IP
Show related traffic
Show DNS traffic except mDNS
```

### UI Notes

- the packet card is visually separated from normal chat messages
- the bottom-left sidebar usage section keeps the investigation ID, `Copy ID`, and `Download Chat` available while you work
- AI-assisted, rule-based, system, and packet labels use different colors
- filter expressions are highlighted so they stand out in both light and dark themes
- stale or expired session URLs return a friendly `Session not found` page instead of a traceback

### Troubleshooting

Browser does not open:

- confirm `curl` is installed on the Wireshark machine
- confirm the receiver is running
- verify `RECEIVER_BASE` in the Lua client

Wireshark cannot connect to the receiver:

- check `bind_host`
- verify firewall and routing
- make sure the Lua URL is a real reachable host, not `0.0.0.0`

Wrong browser URL opens:

- set `public_base_url`
- make sure it matches the URL the Wireshark machine should open

AI provider does not work:

- confirm the key exists in `config.toml`
- confirm the selected model is valid for that provider
- confirm outbound network access is available
- for Ollama, confirm the base URL is correct and the model is pulled

### Security Notes

- `config.toml` may contain API keys
- do not commit live keys to a public repository
- for service deployments, prefer a dedicated system user and locked-down file permissions

## Systemd

A sample unit file is included at [`deploy/systemd/sharkbot.service`](deploy/systemd/sharkbot.service).

The sample assumes:

- the app is installed at `/opt/sharkbot`
- the virtual environment is at `/opt/sharkbot/.venv`
- the runtime config is `/opt/sharkbot/config.toml`
- the service runs as user `sharkbot`

Adjust those paths and the user before installing it.

Install steps:

```bash
sudo cp deploy/systemd/sharkbot.service /etc/systemd/system/sharkbot.service
sudo systemctl daemon-reload
sudo systemctl enable --now sharkbot.service
sudo systemctl status sharkbot.service
```

After editing the unit:

```bash
sudo systemctl daemon-reload
sudo systemctl restart sharkbot.service
```

## Change Log

Project history is tracked in [`CHANGELOG.md`](CHANGELOG.md).
