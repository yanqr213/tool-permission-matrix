from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set

from tool_permission_matrix.models import Finding, OverlapEntry, Policy, Recommendation, Report, ToolRecord
from tool_permission_matrix.patterns import classify_command
from tool_permission_matrix.policy import apply_exemptions, filter_effective_findings, path_matches_any, summarize_exemptions


def build_report(
    tools: Sequence[ToolRecord],
    repo_root: Path,
    policy: Policy | None = None,
    shell_config: Dict[str, List[str]] | None = None,
    sources: Sequence[str] | None = None,
) -> Report:
    active_policy = policy or Policy()
    active_shell = merge_shell_config(active_policy.shell, shell_config or {})
    findings = analyze_tools(tools, repo_root, active_policy, active_shell)
    findings = apply_exemptions(findings, active_policy)
    overlaps = build_overlap_matrix(tools)
    recommendations = build_recommendations(tools, findings, active_policy, active_shell)
    effective_findings = filter_effective_findings(findings)

    summary = {
        "tool_count": len(tools),
        "effective_finding_count": len(effective_findings),
        "warning_count": sum(1 for item in effective_findings if item.severity == "warning"),
        "error_count": sum(1 for item in effective_findings if item.severity == "error"),
        "exempted_count": summarize_exemptions(findings),
        "capabilities": summarize_capabilities(tools),
    }

    return Report(
        summary=summary,
        tools=tools,
        findings=findings,
        overlaps=overlaps,
        recommendations=recommendations,
        policy=active_policy,
        sources=list(sources or []),
    )


def analyze_tools(
    tools: Sequence[ToolRecord],
    repo_root: Path,
    policy: Policy,
    shell_config: Dict[str, List[str]],
) -> List[Finding]:
    findings: List[Finding] = []
    repo_root = repo_root.resolve()

    for tool in tools:
        if "network" in tool.capabilities and not policy.network.get("allow", False):
            findings.append(
                Finding(
                    rule_id="unexpected_network_access",
                    severity="warning",
                    title="Network permission enabled",
                    description="The tool can access the network even though policy.network.allow is false.",
                    tool=tool.name,
                    capability="network",
                )
            )

        findings.extend(analyze_paths(tool, repo_root, policy))
        findings.extend(analyze_commands(tool, shell_config))

        if "browse" in tool.capabilities and "network" not in tool.capabilities:
            findings.append(
                Finding(
                    rule_id="implicit_network_from_browser",
                    severity="warning",
                    title="Browser capability implies network",
                    description="Browsing tools should be treated as network-capable during review.",
                    tool=tool.name,
                    capability="browse",
                )
            )

    return findings


def analyze_paths(tool: ToolRecord, repo_root: Path, policy: Policy) -> List[Finding]:
    findings: List[Finding] = []
    deny_patterns = policy.path_rules.get("deny", [])
    read_allow = policy.path_rules.get("read_allow", [])
    write_allow = policy.path_rules.get("write_allow", [])

    for path_value in tool.read_paths:
        scope = classify_path_scope(path_value, repo_root)
        if scope in {"outside_repo", "workspace_wide", "system_wide"}:
            findings.append(
                Finding(
                    rule_id="broad_read_scope",
                    severity="warning",
                    title="Broad read scope",
                    description=f"Read path '{path_value}' is not limited to the repository root.",
                    tool=tool.name,
                    path=path_value,
                    capability="file_read",
                )
            )
        if deny_patterns and path_matches_any(path_value, deny_patterns, repo_root):
            findings.append(
                Finding(
                    rule_id="path_matches_deny_rule",
                    severity="error",
                    title="Path matches deny rule",
                    description=f"Path '{path_value}' is covered by a deny rule in policy.path_rules.deny.",
                    tool=tool.name,
                    path=path_value,
                    capability="file_read",
                )
            )
        if read_allow and not path_matches_any(path_value, read_allow, repo_root):
            findings.append(
                Finding(
                    rule_id="path_outside_read_allowlist",
                    severity="warning",
                    title="Read path outside allowlist",
                    description=f"Path '{path_value}' is not included in policy.path_rules.read_allow.",
                    tool=tool.name,
                    path=path_value,
                    capability="file_read",
                )
            )

    for path_value in tool.write_paths:
        scope = classify_path_scope(path_value, repo_root)
        severity = "error" if scope in {"outside_repo", "workspace_wide", "system_wide"} else "warning"
        if scope != "repo_scoped":
            findings.append(
                Finding(
                    rule_id="broad_write_scope",
                    severity=severity,
                    title="Broad write scope",
                    description=f"Write path '{path_value}' is not limited to the repository root.",
                    tool=tool.name,
                    path=path_value,
                    capability="file_write",
                )
            )
        if deny_patterns and path_matches_any(path_value, deny_patterns, repo_root):
            findings.append(
                Finding(
                    rule_id="path_matches_deny_rule",
                    severity="error",
                    title="Path matches deny rule",
                    description=f"Path '{path_value}' is covered by a deny rule in policy.path_rules.deny.",
                    tool=tool.name,
                    path=path_value,
                    capability="file_write",
                )
            )
        if write_allow and not path_matches_any(path_value, write_allow, repo_root):
            findings.append(
                Finding(
                    rule_id="path_outside_write_allowlist",
                    severity="error",
                    title="Write path outside allowlist",
                    description=f"Path '{path_value}' is not included in policy.path_rules.write_allow.",
                    tool=tool.name,
                    path=path_value,
                    capability="file_write",
                )
            )

    return findings


def analyze_commands(tool: ToolRecord, shell_config: Dict[str, List[str]]) -> List[Finding]:
    findings: List[Finding] = []
    allow_patterns = shell_config.get("allow_patterns", [])
    deny_patterns = shell_config.get("deny_patterns", [])

    for command in tool.commands:
        rule = classify_command(command)
        if rule:
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    tool=tool.name,
                    command=command,
                    capability="process_execute",
                )
            )
        if deny_patterns and any(_pattern_matches(command, pattern) for pattern in deny_patterns):
            findings.append(
                Finding(
                    rule_id="command_matches_deny_rule",
                    severity="error",
                    title="Command matches deny rule",
                    description="Shell command matches a deny pattern from shell policy.",
                    tool=tool.name,
                    command=command,
                    capability="process_execute",
                )
            )
        if allow_patterns and not any(_pattern_matches(command, pattern) for pattern in allow_patterns):
            findings.append(
                Finding(
                    rule_id="command_outside_allowlist",
                    severity="warning",
                    title="Command outside allowlist",
                    description="Shell command is not covered by shell.allow_patterns.",
                    tool=tool.name,
                    command=command,
                    capability="process_execute",
                )
            )
    return findings


def classify_path_scope(path_value: str, repo_root: Path) -> str:
    normalized = path_value.replace("\\", "/")
    repo_normalized = str(repo_root).replace("\\", "/")

    if normalized in {"/", "~"} or normalized.lower().startswith("c:/"):
        if normalized.rstrip("/").lower() in {"c:", "c:/"} or normalized == "/":
            return "system_wide"
    if normalized.startswith("/") and not normalized.startswith(repo_normalized):
        return "outside_repo"
    if any(token in normalized for token in ["**", "*", "?"]):
        return "workspace_wide"
    if normalized.startswith("../") or "/../" in normalized:
        return "outside_repo"
    if normalized.startswith(repo_normalized):
        return "repo_scoped"
    if Path(path_value).is_absolute():
        return "outside_repo"
    return "repo_scoped"


def build_overlap_matrix(tools: Sequence[ToolRecord]) -> List[OverlapEntry]:
    overlaps: List[OverlapEntry] = []
    ordered = sorted(tools, key=lambda item: item.name)
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            shared = sorted(left.capabilities & right.capabilities)
            if not shared:
                continue
            overlaps.append(
                OverlapEntry(
                    tool_a=left.name,
                    tool_b=right.name,
                    shared_capabilities=shared,
                    read_scope_overlap=bool(set(left.read_paths) & set(right.read_paths)),
                    write_scope_overlap=bool(set(left.write_paths) & set(right.write_paths)),
                )
            )
    return overlaps


def build_recommendations(
    tools: Sequence[ToolRecord],
    findings: Sequence[Finding],
    policy: Policy,
    shell_config: Dict[str, List[str]],
) -> List[Recommendation]:
    recommendations: List[Recommendation] = []
    effective_findings = filter_effective_findings(findings)
    finding_index = {item.rule_id for item in effective_findings}

    if "unexpected_network_access" in finding_index:
        recommendations.append(
            Recommendation(
                priority="high",
                title="Disable unused network access",
                details="Set policy.network.allow to false for agents that only need local repository access, or split browsing into a separate read-only agent.",
            )
        )

    if any(item.rule_id == "broad_write_scope" for item in effective_findings):
        recommendations.append(
            Recommendation(
                priority="high",
                title="Constrain write paths to repo-owned directories",
                details="Limit write permissions to explicit workspace subpaths such as src/, tests/, or outputs/ and deny home or system roots.",
            )
        )

    if any(item.rule_id == "command_outside_allowlist" for item in effective_findings) or (
        any("process_execute" in tool.capabilities for tool in tools) and not shell_config.get("allow_patterns")
    ):
        recommendations.append(
            Recommendation(
                priority="medium",
                title="Create a shell allowlist",
                details="Define shell.allow_patterns for read-only commands first, then add narrowly scoped mutation commands only when review requires them.",
                tool="shell",
            )
        )

    writable_tools = [tool for tool in tools if "file_write" in tool.capabilities]
    if len(writable_tools) > 1:
        recommendations.append(
            Recommendation(
                priority="medium",
                title="Reduce overlapping writer tools",
                details="Keep a single primary writer when possible; overlapping write-capable tools make review and rollback harder.",
            )
        )

    if any(item.rule_id in {"recursive_delete", "remote_script_execution", "git_history_rewrite"} for item in effective_findings):
        recommendations.append(
            Recommendation(
                priority="high",
                title="Block destructive shell patterns by default",
                details="Add deny patterns for recursive deletes, remote script execution, and history rewrites unless the workspace is disposable.",
                tool="shell",
            )
        )

    if not recommendations:
        recommendations.append(
            Recommendation(
                priority="low",
                title="Current permissions look constrained",
                details="No high-signal issues were detected. Keep reviewing newly added tools and log sources as the agent surface grows.",
            )
        )

    return recommendations


def summarize_capabilities(tools: Sequence[ToolRecord]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for tool in tools:
        for capability in tool.capabilities:
            counts[capability] = counts.get(capability, 0) + 1
    return dict(sorted(counts.items()))


def explain_command(command: str) -> Dict[str, str]:
    rule = classify_command(command)
    if rule is None:
        return {
            "command": command,
            "category": "general_shell",
            "severity": "info",
            "title": "No specific rule matched",
            "description": "The command executes a process but did not match a built-in high-signal risk rule.",
        }
    return {
        "command": command,
        "category": rule.category,
        "severity": rule.severity,
        "title": rule.title,
        "description": rule.description,
        "rule_id": rule.rule_id,
    }


def _pattern_matches(command: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(command, pattern)


def merge_shell_config(
    policy_shell: Dict[str, List[str]] | None,
    shell_config: Dict[str, List[str]] | None,
) -> Dict[str, List[str]]:
    merged = {"allow_patterns": [], "deny_patterns": []}
    for source in (policy_shell or {}, shell_config or {}):
        for key in ("allow_patterns", "deny_patterns"):
            for item in source.get(key, []):
                if item not in merged[key]:
                    merged[key].append(item)
    return merged
