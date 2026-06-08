from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class CommandRule:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    pattern: re.Pattern[str]


COMMAND_RULES = [
    CommandRule(
        "remote_script_execution",
        "remote_execution",
        "error",
        "Remote script execution",
        "Downloads content from the network and pipes it into a shell or evaluator.",
        re.compile(
            r"(?i)((curl|wget).+\|\s*(sh|bash|zsh|pwsh|powershell))|"
            r"((Invoke-WebRequest|irm).+\|\s*(iex|Invoke-Expression))"
        ),
    ),
    CommandRule(
        "recursive_delete",
        "destructive_file_operation",
        "error",
        "Recursive delete",
        "Recursively deletes files or directories and is risky in shared workspaces.",
        re.compile(
            r"(?i)(\brm\s+-[^\n]*r[^\n]*f)|(\bRemove-Item\b.+-Recurse.+-Force)|"
            r"(\brmdir\b.+(/[sq]|--ignore-fail-on-non-empty))|(\bdel\b.+/[fqs])"
        ),
    ),
    CommandRule(
        "git_history_rewrite",
        "vcs_mutation",
        "error",
        "Git history rewrite",
        "Rewrites git state or deletes untracked files, which can erase work.",
        re.compile(r"(?i)\bgit\s+(reset\s+--hard|clean\s+-[^\n]*f|checkout\s+--)\b"),
    ),
    CommandRule(
        "privilege_escalation",
        "privilege",
        "warning",
        "Privilege escalation",
        "Requests elevated privileges or changes the execution policy.",
        re.compile(r"(?i)\b(sudo|su|runas|Set-ExecutionPolicy)\b"),
    ),
    CommandRule(
        "network_transfer",
        "network",
        "warning",
        "Network transfer",
        "Transfers data over the network and may bypass repository-only workflows.",
        re.compile(r"(?i)\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b"),
    ),
    CommandRule(
        "package_install",
        "dependency_mutation",
        "warning",
        "Package install",
        "Installs or upgrades dependencies during agent execution.",
        re.compile(r"(?i)\b(pip|pip3|uv|poetry|npm|pnpm|yarn|apt|brew|choco)\s+(install|add|upgrade)\b"),
    ),
    CommandRule(
        "git_push_or_commit",
        "vcs_mutation",
        "warning",
        "Git write operation",
        "Creates commits, tags, or pushes changes to a remote.",
        re.compile(r"(?i)\bgit\s+(commit|push|tag|merge|rebase|switch|checkout)\b"),
    ),
    CommandRule(
        "process_termination",
        "process_control",
        "warning",
        "Process termination",
        "Stops running processes and can interrupt other developer activity.",
        re.compile(r"(?i)\b(kill|pkill|taskkill|Stop-Process)\b"),
    ),
]


def classify_command(command: str) -> Optional[CommandRule]:
    for rule in COMMAND_RULES:
        if rule.pattern.search(command):
            return rule
    return None


def infer_capabilities_from_command(command: str) -> List[str]:
    lowered = command.lower()
    capabilities = ["process_execute"]
    if any(token in lowered for token in ["curl", "wget", "invoke-webrequest", "invoke-restmethod", "irm"]):
        capabilities.append("network")
    if any(token in lowered for token in ["rm ", "remove-item", "del ", "mv ", "move-item", "cp ", "copy-item", "git commit", "git clean", "git reset", "pip install", "npm install", "yarn add"]):
        capabilities.append("file_write")
    if any(token in lowered for token in ["cat ", "type ", "get-content", "ls ", "dir ", "find ", "git diff", "git status"]):
        capabilities.append("file_read")
    return sorted(set(capabilities))
