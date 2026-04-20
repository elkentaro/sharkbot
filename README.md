<img src="sharkbot.jpeg" width="200">

# Smart Filter Assistant

Smart Filter Assistant is a Wireshark companion app.

The workflow is:

1. In Wireshark, the user selects a packet and launches the Lua helper from the packet menu.
2. The Lua helper sends packet context to the Python receiver.
3. The receiver opens a browser session for that packet.
4. The browser UI asks the user to choose a configured AI backend.
5. After backend selection, the app shows the target packet, explains how to use rule-based vs AI-assisted replies, and suggests next actions.
6. The user keeps asking questions until they get the filter or explanation they need.

The app is intentionally split into two modes:

- Rule-based mode for fast, deterministic packet explanations and display-filter generation
- AI-assisted mode for deeper packet analysis when the user explicitly asks for it with `+AI` or a provider suffix like `+Claude`

## What It Does

- Launches from Wireshark through a Lua plugin
- Captures packet context such as frame number, IPs, MACs, ports, DNS name, HTTP host, and current display filter
- Creates a browser-based chat session for the selected packet
- Lets the user choose a background AI backend from only the providers that are actually configured
- Keeps rule-based logic as the default for normal questions
- Uses AI only when explicitly requested with:
  - `+AI`
  - `+OpenAI`
  - `+Claude`
  - `+Gemini`
  - `+Ollama`
- Builds common Wireshark display filters from packet context
- Falls back to rule-based answers if a live AI request fails

## Repository Layout

```text
core/
  config.py
  providers/
receiver_app.py
smart_filter.lua
templates/
static/
config.toml
config.toml.example
requirements.txt
```

## Requirements

- Python 3.11 or newer
- Wireshark with Lua enabled
- `curl` available on the machine running Wireshark
- A browser on the machine running Wireshark

Optional:

- OpenAI API key
- Anthropic API key
- Gemini API key
- Ollama running locally or remotely

## Python Setup

From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.toml.example config.toml
python receiver_app.py
```

The receiver reads `config.toml` from the current directory by default.

You can point to a different config file:

```bash
SMART_FILTER_CONFIG=/path/to/config.toml python receiver_app.py
```

## Receiver Configuration

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

[providers.openai]
api_key = ""

[providers.anthropic]
api_key = ""

[providers.gemini]
api_key = ""

[providers.ollama]
base_url = "http://127.0.0.1:11434"

[advanced]
timeout_seconds = 45
```

### Receiver Settings

- `host`: legacy/default receiver host value
- `bind_host`: actual interface Flask should listen on
- `public_base_url`: URL the Wireshark machine should open in its browser
- `port`: receiver port

### Defaults

- `provider`: startup backend for the session state
- `model`: startup model for that provider

If the configured default provider is unavailable, the app falls back to `rule_based`.

## Local Setup

For a local setup where Wireshark and the receiver run on the same machine, the default config is usually enough:

```toml
[receiver]
host = "127.0.0.1"
port = 8765
```

And in the Lua plugin:

```lua
local RECEIVER_BASE = os.getenv("SMART_FILTER_RECEIVER") or "http://127.0.0.1:8765"
```

## Remote / Headless Receiver Setup

For a receiver running on a remote headless box, separate the bind address from the browser URL:

```toml
[receiver]
host = "127.0.0.1"
bind_host = "0.0.0.0"
public_base_url = "http://192.168.1.50:8765"
port = 8765
```

Important:

- `bind_host = "0.0.0.0"` allows the receiver to listen on the network
- `public_base_url` must be reachable from the Wireshark machine
- the Lua client must point to that same reachable receiver
- do not use `0.0.0.0` as the Lua client URL

Example Lua receiver setting for a remote receiver:

```lua
local RECEIVER_BASE = os.getenv("SMART_FILTER_RECEIVER") or "http://192.168.1.50:8765"
```

## AI Provider Setup

### OpenAI

```toml
[providers.openai]
api_key = "YOUR_OPENAI_KEY"
```

### Anthropic

```toml
[providers.anthropic]
api_key = "YOUR_ANTHROPIC_KEY"
```

### Gemini

```toml
[providers.gemini]
api_key = "YOUR_GEMINI_KEY"
```

### Ollama

```toml
[providers.ollama]
base_url = "http://127.0.0.1:11434"
```

If you use Ollama locally, start it and pull at least one model:

```bash
ollama pull llama3.1
```

## Installing the Lua Client

Copy `smart_filter.lua` into a Wireshark Lua plugin directory.

Common locations:

- macOS app bundle testing:
  - `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`
- Personal plugin directories depend on OS and Wireshark install style

If you are unsure where Wireshark loads Lua plugins from, check Wireshark preferences and Lua/plugin paths on your system.

After copying the file, restart Wireshark.

### Lua Client Notes

At the top of [smart_filter.lua](/mnt/usb/sharkbot/smart_filter.lua:1):

```lua
local RECEIVER_BASE = os.getenv("SMART_FILTER_RECEIVER") or "http://127.0.0.1:8765"
```

You can either:

- edit `RECEIVER_BASE` directly
- or set `SMART_FILTER_RECEIVER` in the Wireshark launch environment

The Lua client:

- posts packet context to `/api/session`
- receives `session_id` and `web_url`
- opens the returned browser URL
- falls back to `RECEIVER_BASE/session/<id>` if the returned URL is unusable

## Running the System

1. Start the Python receiver.
2. Open Wireshark.
3. Select a packet.
4. Right-click the packet and choose `Smart Filter Assistant`.
5. The Lua client sends packet context to the receiver and opens a browser session.
6. In the browser, choose the AI backend you want to keep available for `+AI`.
7. Ask questions or click suggestions until you get the explanation or filter you need.

## Chat Behavior

The app currently behaves like this:

- If one or more AI backends are configured, the chat stays locked until the user selects a backend for the session
- After backend selection, the app shows:
  - `AI backend ready: ...`
  - usage guidance for rule-based vs AI-assisted replies
  - the packet summary card
  - suggested next steps
- Normal questions still default to rule-based logic
- AI is used only when the prompt explicitly ends with `+AI` or a provider suffix

Examples:

```text
Explain this packet
Explain this packet +AI
Explain this packet +Claude
Show all traffic involving this IP
Show DNS traffic except mDNS
```

## Rule-Based vs AI-Assisted

### Rule-based

Used by default for:

- straightforward packet explanations
- common filter generation
- packet-context suggestions

### AI-assisted

Used only for the current message when the user asks for it explicitly:

- `+AI` uses the selected backend
- `+OpenAI`, `+Claude`, `+Gemini`, `+Ollama` force a specific backend

If the AI request fails, the UI labels the response as fallback and shows the rule-based answer instead.

## UI Notes

The browser UI currently includes:

- theme switcher
- packet context card in the sidebar
- backend onboarding card in chat
- colored response labels for:
  - system
  - packet
  - AI-assisted answers
  - rule-based answers
  - fallback/error states
- highlighted filter snippets in AI explanations

## Troubleshooting

### The browser does not open

- make sure `curl` is installed on the Wireshark machine
- make sure the receiver is running
- verify `RECEIVER_BASE` in `smart_filter.lua`
- for remote receivers, confirm the receiver is reachable from the Wireshark machine

### Wireshark can launch the plugin but cannot connect

- check that the receiver is listening on the right interface
- for remote setups, use `bind_host = "0.0.0.0"`
- verify firewalls and routing
- make sure the Lua URL is a real reachable host, not `0.0.0.0`

### The wrong browser URL opens

- set `public_base_url` in `config.toml`
- make sure it matches the URL that should open on the Wireshark machine

### The chat says to set the background AI backend first

- that is expected when at least one AI provider is configured
- choose a backend in the onboarding card to unlock the session

### An AI provider does not work

- confirm its key is present in `config.toml`
- confirm the selected model name is valid for that provider
- confirm outbound network access is available
- for Ollama, confirm the base URL is correct and Ollama is running
- restart the receiver after editing config

## Security Notes

- `config.toml` may contain API keys
- do not commit real keys to a public repository
- prefer using environment-specific config handling if you deploy this beyond local/private use

## Development Notes

- The receiver is a Flask app in [receiver_app.py](/mnt/usb/sharkbot/receiver_app.py:1)
- Provider integrations live under [core/providers](/mnt/usb/sharkbot/core/providers/__init__.py:1)
- The browser UI lives in [templates/index.html](/mnt/usb/sharkbot/templates/index.html:1), [static/js/app.js](/mnt/usb/sharkbot/static/js/app.js:1), and [static/css/app.css](/mnt/usb/sharkbot/static/css/app.css:1)
- The Wireshark entry point is [smart_filter.lua](/mnt/usb/sharkbot/smart_filter.lua:1)
