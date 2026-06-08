from __future__ import annotations

import fnmatch
from datetime import date
from pathlib import Path
from typing import Iterable, List, Sequence

from tool_permission_matrix.models import Finding, Policy


SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 2)


def apply_exemptions(findings: Sequence[Finding], policy: Policy, today: date | None = None) -> List[Finding]:
    current_day = today or date.today()
    updated: List[Finding] = []
    for finding in findings:
        clone = Finding(**finding.to_dict())
        for exemption in policy.exemptions:
            if not _exemption_active(exemption, current_day):
                continue
            if _matches_exemption(clone, exemption):
                clone.exempted = True
                clone.exemption_reason = str(exemption.get("reason") or "policy exemption")
                break
        updated.append(clone)
    return updated


def filter_effective_findings(findings: Iterable[Finding], threshold: str | None = None) -> List[Finding]:
    items = [item for item in findings if not item.exempted]
    if threshold is None:
        return items
    return [item for item in items if severity_at_least(item.severity, threshold)]


def summarize_exemptions(findings: Iterable[Finding]) -> int:
    return sum(1 for item in findings if item.exempted)


def path_matches_any(path_value: str, patterns: Sequence[str], repo_root: Path) -> bool:
    if not patterns:
        return False
    normalized = path_value.replace("\\", "/")
    repo_root_text = str(repo_root).replace("\\", "/")
    candidate_values = {normalized}
    if normalized.startswith(repo_root_text):
        candidate_values.add(normalized[len(repo_root_text) :].lstrip("/"))
    for pattern in patterns:
        clean_pattern = pattern.replace("\\", "/")
        for candidate in candidate_values:
            if fnmatch.fnmatch(candidate, clean_pattern):
                return True
    return False


def _matches_exemption(finding: Finding, exemption: dict) -> bool:
    if exemption.get("rule_id") and exemption["rule_id"] != finding.rule_id:
        return False
    if exemption.get("tool") and exemption["tool"] != finding.tool:
        return False
    command_pattern = exemption.get("command_pattern")
    if command_pattern and not fnmatch.fnmatch(finding.command or "", command_pattern):
        return False
    path_pattern = exemption.get("path_pattern")
    if path_pattern and not fnmatch.fnmatch((finding.path or "").replace("\\", "/"), path_pattern.replace("\\", "/")):
        return False
    return True


def _exemption_active(exemption: dict, current_day: date) -> bool:
    expires_on = exemption.get("expires_on")
    if not expires_on:
        return True
    try:
        expiry = date.fromisoformat(str(expires_on))
    except ValueError:
        return False
    return expiry >= current_day
