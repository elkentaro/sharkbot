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
    preferred_guidance: List[str]
    fallback_guidance: List[str]
    suggested_actions: List[Dict[str, str]]
    handrail_reason: str
    handrail_rules: List[Dict[str, Any]]
    handrail_alternates: List[Dict[str, Any]]
    next_step_rules: List[Dict[str, Any]]
    filter_step_rules: List[Dict[str, Any]]
    source_path: str

    def payload(self) -> Dict[str, Any]:
        return {
            "id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "built_in": self.built_in,
            "prompt_hints": self.prompt_hints,
            "rule_hints": self.rule_hints,
            "preferred_guidance": self.preferred_guidance,
            "fallback_guidance": self.fallback_guidance,
            "suggested_actions": self.suggested_actions,
            "handrail_reason": self.handrail_reason,
            "handrail_rules": self.handrail_rules,
            "handrail_alternates": self.handrail_alternates,
            "next_step_rules": self.next_step_rules,
            "filter_step_rules": self.filter_step_rules,
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
    preferred_guidance = _string_list(data.get("preferred_guidance", []), "preferred_guidance", path)
    fallback_guidance = _string_list(data.get("fallback_guidance", []), "fallback_guidance", path)
    suggested_actions = _action_list(data.get("suggested_actions", []), path)
    handrail_reason = _optional_string(data.get("handrail_reason", ""), "handrail_reason", path)
    handrail_rules = _handrail_rule_list(data.get("handrail_rules", []), path)
    handrail_alternates = _handrail_step_list(data.get("handrail_alternates", []), path, key_name="handrail_alternates")
    next_step_rules = _guided_action_rule_list(data.get("next_step_rules", []), path, key_name="next_step_rules")
    filter_step_rules = _guided_action_rule_list(data.get("filter_step_rules", []), path, key_name="filter_step_rules")
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
        preferred_guidance=preferred_guidance,
        fallback_guidance=fallback_guidance,
        suggested_actions=suggested_actions,
        handrail_reason=handrail_reason,
        handrail_rules=handrail_rules,
        handrail_alternates=handrail_alternates,
        next_step_rules=next_step_rules,
        filter_step_rules=filter_step_rules,
        source_path=str(path),
    )


def _require_string(data: Dict[str, Any], key: str, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path}: expected non-empty string for {key}")
    return value.strip()


def _optional_string(value: Any, key: str, path: Path) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{path}: expected string for {key}")
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
        kind = item.get("kind", "")
        if not isinstance(label, str) or not label.strip():
            raise ValueError(f"{path}: suggested action missing label")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(f"{path}: suggested action missing prompt")
        entry = {"label": label.strip(), "prompt": prompt.strip()}
        if kind:
            if not isinstance(kind, str) or not kind.strip():
                raise ValueError(f"{path}: suggested action kind must be a non-empty string when provided")
            entry["kind"] = kind.strip()
        cleaned.append(entry)
    return cleaned


def _bool_field(value: Any, key: str, path: Path, table_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path}: {table_name}.{key} must be a boolean")
    return value


def _string_list_field(item: Dict[str, Any], key: str, path: Path, table_name: str) -> List[str]:
    return _string_list(item.get(key, []), f"{table_name}.{key}", path)


def _handrail_rule_list(value: Any, path: Path) -> List[Dict[str, Any]]:
    return _handrail_step_list(value, path, key_name="handrail_rules", allow_conditions=True)


def _handrail_step_list(
    value: Any,
    path: Path,
    *,
    key_name: str,
    allow_conditions: bool = False,
) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{path}: expected list for {key_name}")
    cleaned: List[Dict[str, Any]] = []
    required_keys = ["step_id", "title", "kind", "rationale", "instructions", "look_for"]
    optional_keys = ["expected_outcome", "common_mistake", "alternate_path"]
    condition_keys = ["observation", "context_flags_all", "context_flags_any", "current_filter_present"]

    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: each {key_name} entry must be a table")
        entry = {key: _require_string(item, key, path) for key in required_keys}
        for key in optional_keys:
            if key in item:
                entry[key] = _optional_string(item.get(key), f"{key_name}.{key}", path)
        if allow_conditions:
            if "observation" in item:
                entry["observation"] = _optional_string(item.get("observation"), f"{key_name}.observation", path)
            if "context_flags_all" in item:
                entry["context_flags_all"] = _string_list_field(item, "context_flags_all", path, key_name)
            if "context_flags_any" in item:
                entry["context_flags_any"] = _string_list_field(item, "context_flags_any", path, key_name)
            if "current_filter_present" in item:
                entry["current_filter_present"] = _bool_field(item.get("current_filter_present"), "current_filter_present", path, key_name)
        unknown = set(item) - set(required_keys) - set(optional_keys) - (set(condition_keys) if allow_conditions else set())
        if unknown:
            raise ValueError(f"{path}: unknown keys in {key_name} entry: {', '.join(sorted(unknown))}")
        cleaned.append(entry)
    return cleaned


def _guided_action_rule_list(value: Any, path: Path, *, key_name: str) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{path}: expected list for {key_name}")
    cleaned: List[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: each {key_name} entry must be a table")
        label = _require_string(item, "label", path)
        prompt = _require_string(item, "prompt", path)
        entry: Dict[str, Any] = {
            "label": label,
            "prompt": prompt,
        }
        if "id" in item:
            entry["id"] = _optional_string(item.get("id"), f"{key_name}.id", path)
        if "kind" in item:
            entry["kind"] = _optional_string(item.get("kind"), f"{key_name}.kind", path)
        if "context_flags_all" in item:
            entry["context_flags_all"] = _string_list_field(item, "context_flags_all", path, key_name)
        if "context_flags_any" in item:
            entry["context_flags_any"] = _string_list_field(item, "context_flags_any", path, key_name)
        if "current_filter_present" in item:
            entry["current_filter_present"] = _bool_field(item.get("current_filter_present"), "current_filter_present", path, key_name)
        if "filter_tags_any" in item:
            entry["filter_tags_any"] = _string_list_field(item, "filter_tags_any", path, key_name)
        if "filter_tags_all" in item:
            entry["filter_tags_all"] = _string_list_field(item, "filter_tags_all", path, key_name)
        if "filter_tags_none" in item:
            entry["filter_tags_none"] = _string_list_field(item, "filter_tags_none", path, key_name)
        unknown = set(item) - {
            "id",
            "label",
            "prompt",
            "kind",
            "context_flags_all",
            "context_flags_any",
            "current_filter_present",
            "filter_tags_any",
            "filter_tags_all",
            "filter_tags_none",
        }
        if unknown:
            raise ValueError(f"{path}: unknown keys in {key_name} entry: {', '.join(sorted(unknown))}")
        cleaned.append(entry)
    return cleaned
