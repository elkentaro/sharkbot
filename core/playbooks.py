from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
import tomllib


@dataclass(frozen=True)
class Playbook:
    playbook_id: str
    name: str
    description: str
    built_in: bool
    system_guidance: str
    prompt_hints: List[str]
    rule_hints: List[str]
    suggested_actions: List[Dict[str, str]]
    source_path: str

    def payload(self) -> Dict[str, Any]:
        return {
            "id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "built_in": self.built_in,
            "prompt_hints": self.prompt_hints,
            "rule_hints": self.rule_hints,
            "suggested_actions": self.suggested_actions,
            "source_path": self.source_path,
        }


def load_playbook_registry(playbooks_dir: str = "playbooks") -> Dict[str, Playbook]:
    root = Path(playbooks_dir)
    if not root.exists():
        return {}

    registry: Dict[str, Playbook] = {}
    for path in sorted(root.glob("*.toml")):
        # Keep the starter template in the repo, but do not expose it as a live selectable playbook.
        if path.name == "template-playbook.toml":
            continue
        playbook = _load_playbook(path)
        registry[playbook.playbook_id] = playbook
    return registry


def _load_playbook(path: Path) -> Playbook:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    playbook_id = _require_string(data, "id", path)
    name = _require_string(data, "name", path)
    description = _require_string(data, "description", path)
    built_in = bool(data.get("built_in", False))
    system_guidance = _require_string(data, "system_guidance", path)
    prompt_hints = _string_list(data.get("prompt_hints", []), "prompt_hints", path)
    rule_hints = _string_list(data.get("rule_hints", []), "rule_hints", path)
    suggested_actions = _action_list(data.get("suggested_actions", []), path)
    if not suggested_actions:
        raise ValueError(f"{path}: expected at least one [[suggested_actions]] entry")
    return Playbook(
        playbook_id=playbook_id,
        name=name,
        description=description,
        built_in=built_in,
        system_guidance=system_guidance.strip(),
        prompt_hints=prompt_hints,
        rule_hints=rule_hints,
        suggested_actions=suggested_actions,
        source_path=str(path),
    )


def _require_string(data: Dict[str, Any], key: str, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path}: expected non-empty string for {key}")
    return value.strip()


def _string_list(value: Any, key: str, path: Path) -> List[str]:
    if not isinstance(value, list):
        raise ValueError(f"{path}: expected list for {key}")
    cleaned: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{path}: expected only non-empty strings in {key}")
        cleaned.append(item.strip())
    return cleaned


def _action_list(value: Any, path: Path) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError(f"{path}: expected list for suggested_actions")
    cleaned: List[Dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: each suggested action must be a table")
        label = item.get("label")
        prompt = item.get("prompt")
        if not isinstance(label, str) or not label.strip():
            raise ValueError(f"{path}: suggested action missing label")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(f"{path}: suggested action missing prompt")
        cleaned.append({"label": label.strip(), "prompt": prompt.strip()})
    return cleaned
