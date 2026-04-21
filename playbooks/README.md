# How To Build A SharkBot Playbook

This directory is for SharkBot playbooks.

The long-term goal is:

- built-in playbooks ship with SharkBot
- users can define their own playbooks
- one playbook can be applied to an investigation session

## Design Goal

A playbook should help SharkBot guide an investigation, not just answer one question.

A good playbook should define:

- what kind of problem the user is trying to solve
- what SharkBot should prioritize
- what actions SharkBot should suggest next
- what rule-based shortcuts or filters are especially relevant
- what AI guidance bias should be applied

## Recommended File Format

Use TOML for playbooks.

That keeps them:

- readable
- editable by hand
- easy to validate
- consistent with the rest of SharkBot config

## Minimum Playbook Shape

Recommended fields:

```toml
id = "tcp_issue"
name = "TCP Issue"
description = "Guide investigations of broken, slow, or suspicious TCP sessions."
built_in = false

system_guidance = """
Act like a TCP troubleshooting specialist.
Prioritize retransmissions, resets, duplicate ACKs, zero-window behavior, and stream isolation.
"""

prompt_hints = [
  "Explain this TCP packet",
  "Show this TCP conversation",
  "Show retransmissions",
]

rule_hints = [
  "tcp",
  "tcp.analysis.retransmission",
  "tcp.analysis.duplicate_ack",
  "tcp.flags.reset == 1",
]

suggested_actions = [
  { label = "Explain this TCP packet", prompt = "Explain this TCP packet" },
  { label = "Show this TCP conversation", prompt = "Show this TCP conversation" },
  { label = "Show retransmissions", prompt = "Show retransmissions" },
]
```

## Field Meanings

`id`
- stable internal identifier
- use lowercase and underscores
- should not change once the playbook is in use

`name`
- user-facing label shown in the UI

`description`
- one short explanation of what the playbook is for

`built_in`
- `true` for shipped templates
- `false` for user-authored playbooks

`system_guidance`
- extra analyst instructions used to bias the AI behavior for this investigation

`prompt_hints`
- common prompts SharkBot can surface or use for suggestion ranking

`rule_hints`
- rule-based filter expressions or protocol hints that should be preferred

`suggested_actions`
- visible next steps for the user
- each item should have:
  - `label`
  - `prompt`

## Good Playbook Characteristics

A good playbook:

- is narrow enough to guide decisions
- suggests 3 to 6 strong next actions
- uses prompts that SharkBot can actually resolve
- reflects real Wireshark workflow

Examples of good playbook themes:

- suspicious traffic
- TCP issue
- TLS decryption
- DNS investigation
- conversation tracing
- BTLE investigation
- 802.11 / Wi-Fi investigation

## Bad Playbook Characteristics

Avoid playbooks that are:

- too vague
- only a persona with no workflow
- overloaded with too many suggested actions
- full of prompts SharkBot cannot deterministically support

## Authoring Guidance

When writing a playbook:

1. define the investigation goal
2. define the top failure modes or pivots
3. define the next best suggested actions
4. define any important rule-based filters
5. define any AI guidance bias

If the playbook cannot answer the question:

- it should still guide the user to the next best Wireshark pivot

## Suggested Directory Structure

Recommended layout:

```text
playbooks/
  README.md
  btle-investigation.toml
  wifi-investigation.toml
  suspicious-traffic.toml
  tcp-issue.toml
  template-playbook.toml
```

## Next Planned Implementation

The planned `v1.7` behavior is:

- load built-in playbooks
- load user-defined playbooks from files
- let the user select one active playbook per investigation
- use that playbook to influence suggested actions, AI guidance, and rule-based prioritization
