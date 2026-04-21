# Change Log

## v1.7.1 - 2026-04-21

- cleaned up chat bubble spacing so labels and message text no longer run together
- changed user message headers from pill labels to plain `YOU:` text for clearer attribution
- switched assistant and status labels to flat pills without drop shadows
- made assistant titles render on a new line with bold headings for playbook and next-step messages

## v1.7.0 - 2026-04-21

- promoted the codebase to the `v1.7.0` release line
- strengthened beginner and SOC L1 triage guidance across playbooks and generic packet-analysis flow
- improved protocol-aware scoping for Wi-Fi and BTLE device-focused filters
- added AI coaching prompts so AI next-step guidance teaches workflow instead of only returning an answer
- aligned built-in AI prompt profiles with the training-aid approach
- completed a gold-master decision test pass and documented release strengths and weaknesses in `docs/v1.7-gold-master-decision-test.md`

## v1.6.0 - 2026-04-20

- added a reusable `systemd` service template under `deploy/systemd/sharkbot.service`
- reorganized the README into setup, run, usage, systemd, and change-log sections
- changed the receiver startup so debug mode is off by default and only enabled with `--debug`
- added in-memory investigation continuation so Wireshark can push new packet context into an existing chat session
- added a downloadable Markdown investigation export from the browser UI
- moved investigation ID and export controls into a persistent bottom-left sidebar usage section
- added specialist AI prompt profiles:
  - `specialist`
  - `packet_analyst`
  - `incident_response`
- improved AI provider routing so normal filter requests stay rule-based unless AI is explicitly requested
- added Anthropic overload handling with retry/backoff for HTTP `529`
- improved missing-session handling so stale browser reloads show a friendly error page instead of a traceback
- improved remote/headless receiver support with separate bind and public browser URLs
- refined the UI onboarding flow, AI reconfiguration flow, packet card styling, response labeling, and filter highlighting
