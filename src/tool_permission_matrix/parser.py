from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

from tool_permission_matrix.models import Policy, ToolRecord
from tool_permission_matrix.patterns import infer_capabilities_from_command


LOG_TOOL_KEYS = ("tool", "tool_name", "name", "recipient_name")
COMMAND_KEYS = ("command", "cmd")
URL_KEYS = ("url", "uri")
PATH_KEYS = ("path", "file", "target_path")
READ_KEYS = ("read_path", "input_path", "source_path")
WRITE_KEYS = ("write_path", "output_path", "destination_path")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_json_lines(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                parsed = parse_plain_log_line(line)
                if parsed:
                    yield parsed
                continue
            if isinstance(value, dict):
                yield value


def parse_plain_log_line(line: str) -> Optional[Dict[str, Any]]:
    tool_match = re.search(r"\btool[=:](?P<tool>[A-Za-z0-9_.-]+)", line)
    command_match = re.search(r"\b(command|cmd)[=:](?P<command>.+)$", line)
    url_match = re.search(r"\burl[=:](?P<url>\S+)", line)
    path_match = re.search(r"\bpath[=:](?P<path>\S+)", line)
    if not any([tool_match, command_match, url_match, path_match]):
        return None
    payload: Dict[str, Any] = {}
    if tool_match:
        payload["tool"] = tool_match.group("tool")
    if command_match:
        payload["command"] = command_match.group("command").strip()
    if url_match:
        payload["url"] = url_match.group("url")
    if path_match:
        payload["path"] = path_match.group("path")
    return payload


def parse_tool_inventory(paths: Sequence[Path]) -> List[ToolRecord]:
    tools: Dict[str, ToolRecord] = {}
    for path in paths:
        payload = load_json(path)
        for item in _iter_tool_entries(payload):
            record = normalize_tool_entry(item, source=str(path))
            existing = tools.get(record.name)
            if existing:
                existing.merge(record)
            else:
                tools[record.name] = record
    return sorted(tools.values(), key=lambda item: item.name)


def _iter_tool_entries(payload: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, Mapping):
                yield item
        return
    if isinstance(payload, Mapping):
        if "tools" in payload and isinstance(payload["tools"], list):
            for item in payload["tools"]:
                if isinstance(item, Mapping):
                    yield item
            return
        if "name" in payload or "tool" in payload:
            yield payload


def normalize_tool_entry(entry: Mapping[str, Any], source: str) -> ToolRecord:
    name = str(entry.get("name") or entry.get("tool") or entry.get("id") or "unknown")
    capabilities = set()
    capabilities.update(_as_list(entry.get("capabilities")))

    permissions = entry.get("permissions")
    if isinstance(permissions, Mapping):
        for key, value in permissions.items():
            if value and key in {"network", "browse", "file_read", "file_write", "process_execute"}:
                capabilities.add(key)

    if entry.get("network"):
        capabilities.add("network")
    if entry.get("browse"):
        capabilities.add("browse")
    if entry.get("read") or entry.get("file_read"):
        capabilities.add("file_read")
    if entry.get("write") or entry.get("file_write"):
        capabilities.add("file_write")
    if entry.get("process") or entry.get("process_execute"):
        capabilities.add("process_execute")

    commands = _collect_string_list(entry, "commands", "command_patterns", "allow_patterns")
    read_paths = _collect_string_list(entry, "read_paths", "reads", "allowed_read_paths")
    write_paths = _collect_string_list(entry, "write_paths", "writes", "allowed_write_paths")
    urls = _collect_string_list(entry, "urls", "hosts")

    for command in commands:
        capabilities.update(infer_capabilities_from_command(command))

    return ToolRecord(
        name=name,
        source=str(entry.get("source") or entry.get("kind") or source),
        capabilities=capabilities,
        commands=commands,
        read_paths=read_paths,
        write_paths=write_paths,
        urls=urls,
        metadata={k: v for k, v in entry.items() if k not in {"name", "tool", "id"}},
    )


def parse_log_records(paths: Sequence[Path]) -> List[ToolRecord]:
    tools: Dict[str, ToolRecord] = {}
    for path in paths:
        for event in load_json_lines(path):
            record = normalize_log_event(event, source=str(path))
            existing = tools.get(record.name)
            if existing:
                existing.merge(record)
            else:
                tools[record.name] = record
    return sorted(tools.values(), key=lambda item: item.name)


def normalize_log_event(event: Mapping[str, Any], source: str) -> ToolRecord:
    name = _find_first(event, LOG_TOOL_KEYS) or _derive_tool_name(event)
    name = str(name or "unknown")
    capabilities = set()
    commands: List[str] = []
    read_paths: List[str] = []
    write_paths: List[str] = []
    urls: List[str] = []

    command = _find_nested_string(event, COMMAND_KEYS)
    if command:
        commands.append(command)
        capabilities.update(infer_capabilities_from_command(command))

    url = _find_nested_string(event, URL_KEYS)
    if url:
        urls.append(url)
        capabilities.update({"network", "browse"})

    for key in PATH_KEYS:
        value = _find_nested_string(event, (key,))
        if value:
            read_paths.append(value)
            capabilities.add("file_read")

    for key in READ_KEYS:
        value = _find_nested_string(event, (key,))
        if value:
            read_paths.append(value)
            capabilities.add("file_read")

    for key in WRITE_KEYS:
        value = _find_nested_string(event, (key,))
        if value:
            write_paths.append(value)
            capabilities.add("file_write")

    action = str(event.get("event") or event.get("type") or event.get("action") or "").lower()
    tool_name = name.lower()
    if "browser" in tool_name or "search" in tool_name or "web" in tool_name:
        capabilities.update({"network", "browse"})
    if "shell" in tool_name or "exec" in tool_name or "terminal" in tool_name:
        capabilities.add("process_execute")
    if any(token in action for token in ["write", "patch", "edit"]):
        capabilities.add("file_write")
    if any(token in action for token in ["read", "open", "view"]):
        capabilities.add("file_read")

    return ToolRecord(
        name=name,
        source=source,
        capabilities=capabilities,
        commands=commands,
        read_paths=_dedupe(read_paths),
        write_paths=_dedupe(write_paths),
        urls=_dedupe(urls),
        metadata={"event": dict(event)},
    )


def parse_policy(path: Optional[Path]) -> Policy:
    if path is None:
        return Policy()
    payload = load_json(path)
    return Policy(
        path_rules=dict(payload.get("path_rules") or {"read_allow": [], "write_allow": [], "deny": []}),
        network=dict(payload.get("network") or {"allow": False, "hosts": []}),
        shell=dict(payload.get("shell") or {"allow_patterns": [], "deny_patterns": []}),
        exemptions=list(payload.get("exemptions") or []),
        check_threshold=str(payload.get("check_threshold") or "error"),
    )


def parse_shell_config(paths: Sequence[Path]) -> Dict[str, List[str]]:
    merged = {"allow_patterns": [], "deny_patterns": []}
    for path in paths:
        payload = load_json(path)
        shell = payload.get("shell") if isinstance(payload, Mapping) else None
        data = shell if isinstance(shell, Mapping) else payload
        allow_items = _as_list(data.get("allow_patterns")) if isinstance(data, Mapping) else []
        deny_items = _as_list(data.get("deny_patterns")) if isinstance(data, Mapping) else []
        for item in allow_items:
            if item not in merged["allow_patterns"]:
                merged["allow_patterns"].append(item)
        for item in deny_items:
            if item not in merged["deny_patterns"]:
                merged["deny_patterns"].append(item)
    return merged


def discover_inputs(root: Path) -> Dict[str, List[Path]]:
    found = {"tools": [], "logs": [], "policies": [], "shell_configs": []}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        lowered = path.name.lower()
        if lowered.endswith(".jsonl") or lowered.endswith(".log"):
            found["logs"].append(path)
            continue
        if lowered.endswith(".policy.json") or "policy" in lowered:
            found["policies"].append(path)
            continue
        if "shell" in lowered and lowered.endswith(".json"):
            found["shell_configs"].append(path)
            continue
        if lowered.endswith(".json") and any(token in lowered for token in ["tool", "mcp", "manifest", "inventory"]):
            found["tools"].append(path)
    return found


def _find_first(event: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _find_nested_string(event: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    value = _find_first(event, keys)
    if value:
        return value
    for nested_key in ("args", "input", "payload", "parameters"):
        nested = event.get(nested_key)
        if isinstance(nested, Mapping):
            inner = _find_first(nested, keys)
            if inner:
                return inner
            for key in keys:
                items = nested.get(key)
                if isinstance(items, list):
                    return " ".join(str(item) for item in items)
    argv = event.get("argv")
    if isinstance(argv, list) and "command" in keys:
        return " ".join(str(item) for item in argv)
    return None


def _derive_tool_name(event: Mapping[str, Any]) -> str:
    action = str(event.get("event") or event.get("type") or event.get("action") or "")
    return action or "unknown"


def _collect_string_list(entry: Mapping[str, Any], *keys: str) -> List[str]:
    values: List[str] = []
    for key in keys:
        for item in _as_list(entry.get(key)):
            if item not in values:
                values.append(item)
    return values


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def _dedupe(items: Sequence[str]) -> List[str]:
    output: List[str] = []
    for item in items:
        if item not in output:
            output.append(item)
    return output
