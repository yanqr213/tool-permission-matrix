from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Set, Tuple

from tool_permission_matrix.models import Finding, Recommendation, RemediationItem, Report
from tool_permission_matrix.policy import filter_effective_findings


PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
STATUS_ORDER = {"todo": 0, "proposed": 1, "deferred": 2}
SEVERITY_PRIORITY = {"error": "high", "warning": "medium", "info": "low"}


def build_remediation_plan(report: Report) -> List[RemediationItem]:
    """Build a deterministic queue of concrete least-privilege remediation tasks."""
    items: List[RemediationItem] = []
    seen: Set[Tuple[str, str, Optional[str], Optional[str]]] = set()

    for finding in filter_effective_findings(report.findings):
        item = remediation_for_finding(finding)
        key = (item.action, item.target, item.tool, item.finding_rule_id)
        if key in seen:
            continue
        seen.add(key)
        items.append(item)

    for item in recommendation_backlog(report.recommendations, report.findings):
        key = (item.action, item.target, item.tool, item.finding_rule_id)
        if key in seen:
            continue
        seen.add(key)
        items.append(item)

    items.sort(
        key=lambda item: (
            PRIORITY_ORDER.get(item.priority, 99),
            STATUS_ORDER.get(item.status, 99),
            item.tool or "",
            item.action,
            item.target,
        )
    )
    for index, item in enumerate(items, start=1):
        item.id = f"rem-{index:03d}"
    return items


def remediation_summary(report: Report, items: Sequence[RemediationItem]) -> Dict[str, object]:
    by_priority: Dict[str, int] = defaultdict(int)
    by_status: Dict[str, int] = defaultdict(int)
    for item in items:
        by_priority[item.priority] += 1
        by_status[item.status] += 1
    return {
        "tool_count": report.summary.get("tool_count", len(report.tools)),
        "effective_finding_count": report.summary.get("effective_finding_count", len(filter_effective_findings(report.findings))),
        "remediation_count": len(items),
        "high_priority_count": by_priority.get("high", 0),
        "medium_priority_count": by_priority.get("medium", 0),
        "low_priority_count": by_priority.get("low", 0),
        "status_counts": dict(sorted(by_status.items())),
    }


def remediation_for_finding(finding: Finding) -> RemediationItem:
    builders = {
        "remote_script_execution": _remote_script_execution,
        "recursive_delete": _recursive_delete,
        "git_history_rewrite": _git_history_rewrite,
        "command_matches_deny_rule": _command_matches_deny_rule,
        "command_outside_allowlist": _command_outside_allowlist,
        "unexpected_network_access": _unexpected_network_access,
        "implicit_network_from_browser": _implicit_network_from_browser,
        "broad_write_scope": _broad_write_scope,
        "path_outside_write_allowlist": _path_outside_write_allowlist,
        "path_matches_deny_rule": _path_matches_deny_rule,
        "broad_read_scope": _broad_read_scope,
        "path_outside_read_allowlist": _path_outside_read_allowlist,
        "package_install": _package_install,
        "network_transfer": _network_transfer,
        "git_push_or_commit": _git_push_or_commit,
        "privilege_escalation": _privilege_escalation,
        "process_termination": _process_termination,
    }
    builder = builders.get(finding.rule_id, _generic_finding)
    return builder(finding)


def recommendation_backlog(
    recommendations: Sequence[Recommendation],
    findings: Sequence[Finding],
) -> List[RemediationItem]:
    effective_rules = {finding.rule_id for finding in filter_effective_findings(findings)}
    covered_by_title = {
        "Disable unused network access": {"unexpected_network_access"},
        "Constrain write paths to repo-owned directories": {"broad_write_scope", "path_outside_write_allowlist"},
        "Create a shell allowlist": {"command_outside_allowlist"},
        "Block destructive shell patterns by default": {
            "command_matches_deny_rule",
            "git_history_rewrite",
            "recursive_delete",
            "remote_script_execution",
        },
    }
    items: List[RemediationItem] = []
    for recommendation in recommendations:
        if recommendation.title == "Current permissions look constrained":
            continue
        if effective_rules & covered_by_title.get(recommendation.title, set()):
            continue
        items.append(
            RemediationItem(
                priority=_normalize_priority(recommendation.priority),
                status="proposed",
                action="review_recommendation",
                title=recommendation.title,
                details=recommendation.details,
                target="review_queue",
                tool=recommendation.tool,
                evidence={"recommendation": recommendation.title},
                suggested_change={"type": "manual_review", "details": recommendation.details},
            )
        )
    return items


def render_remediation_markdown(report: Report) -> str:
    items = _plan(report)
    summary = remediation_summary(report, items)
    lines = [
        "# Tool Permission Remediation Plan",
        "",
        "## Summary",
        "",
        f"- Tools: {summary['tool_count']}",
        f"- Effective findings: {summary['effective_finding_count']}",
        f"- Remediation items: {summary['remediation_count']}",
        f"- High priority: {summary['high_priority_count']}",
        f"- Medium priority: {summary['medium_priority_count']}",
        f"- Low priority: {summary['low_priority_count']}",
        "",
        "## Queue",
        "",
        "| ID | Priority | Status | Action | Tool | Finding | Target | Suggested change |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    if not items:
        lines.append("| - | - | - | No remediation needed | - | - | - | Current permissions look constrained |")
    for item in items:
        lines.append(
            "| {id} | {priority} | {status} | {action} | {tool} | {finding} | {target} | {change} |".format(
                id=item.id,
                priority=item.priority,
                status=item.status,
                action=_escape_markdown_cell(item.action),
                tool=_escape_markdown_cell(item.tool or "-"),
                finding=_escape_markdown_cell(item.finding_rule_id or "-"),
                target=_escape_markdown_cell(item.target),
                change=_escape_markdown_cell(_suggested_change_text(item)),
            )
        )

    if items:
        lines.extend(["", "## Details", ""])
        for item in items:
            lines.extend(
                [
                    f"### {item.id} {item.title}",
                    "",
                    f"- Priority: {item.priority}",
                    f"- Status: {item.status}",
                    f"- Tool: {item.tool or '-'}",
                    f"- Finding: {item.finding_rule_id or '-'}",
                    f"- Target: {item.target}",
                    f"- Action: {item.action}",
                    f"- Details: {item.details}",
                    f"- Suggested change: `{_suggested_change_text(item)}`",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def render_remediation_json(report: Report) -> str:
    import json

    items = _plan(report)
    payload = {
        "summary": remediation_summary(report, items),
        "remediation_plan": [item.to_dict() for item in items],
        "sources": list(report.sources),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _plan(report: Report) -> Sequence[RemediationItem]:
    if report.remediation_plan:
        return report.remediation_plan
    return build_remediation_plan(report)


def _base_finding_item(
    finding: Finding,
    *,
    action: str,
    title: str,
    details: str,
    target: str,
    suggested_change: Dict[str, object],
    priority: Optional[str] = None,
    status: str = "todo",
) -> RemediationItem:
    return RemediationItem(
        priority=priority or SEVERITY_PRIORITY.get(finding.severity, "low"),
        status=status,
        action=action,
        title=title,
        details=details,
        target=target,
        tool=finding.tool,
        finding_rule_id=finding.rule_id,
        severity=finding.severity,
        evidence={
            "command": finding.command,
            "path": finding.path,
            "capability": finding.capability,
            "description": finding.description,
        },
        suggested_change=suggested_change,
    )


def _remote_script_execution(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="block_shell_pattern",
        title="Block remote script execution",
        details="Add an explicit deny rule for commands that pipe downloaded content into a shell or evaluator.",
        target="shell.deny_patterns",
        suggested_change={"operation": "append", "value": "curl *| sh*", "alternatives": ["wget *| sh*", "irm *| iex*"]},
        priority="high",
    )


def _recursive_delete(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="block_shell_pattern",
        title="Block recursive deletes by default",
        details="Deny recursive force-delete commands unless the workspace is disposable and the command is reviewed.",
        target="shell.deny_patterns",
        suggested_change={"operation": "append", "value": "rm -rf *", "alternatives": ["Remove-Item * -Recurse -Force"]},
        priority="high",
    )


def _git_history_rewrite(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="block_shell_pattern",
        title="Block git history rewrites",
        details="Deny commands that erase local git state or untracked work.",
        target="shell.deny_patterns",
        suggested_change={"operation": "append", "value": "git reset --hard*", "alternatives": ["git clean -f*", "git checkout --*"]},
        priority="high",
    )


def _command_matches_deny_rule(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="remove_or_isolate_command",
        title="Remove command matched by deny policy",
        details="A command already matches the deny policy; remove it from the agent flow or run it only in a disposable sandbox.",
        target=finding.tool or "shell",
        suggested_change={"operation": "remove_command", "command": finding.command},
        priority="high",
    )


def _command_outside_allowlist(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="review_shell_allowlist",
        title="Review shell command allowlist",
        details="Decide whether this command is required. Prefer a narrower allow pattern over broad shell access.",
        target="shell.allow_patterns",
        suggested_change={"operation": "review_append", "value": _command_to_allow_pattern(finding.command)},
        priority="medium",
    )


def _unexpected_network_access(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="disable_or_split_network",
        title="Disable unexpected network access",
        details="Set policy.network.allow to false for local-only agents, or split browsing into a separate read-only tool.",
        target="policy.network.allow",
        suggested_change={"operation": "set", "value": False},
        priority="medium",
    )


def _implicit_network_from_browser(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="label_browser_network",
        title="Treat browser capability as network access",
        details="Mark browser tools as network-capable so policy review and CI gates see their real boundary.",
        target=f"tools.{finding.tool}.capabilities",
        suggested_change={"operation": "append", "value": "network"},
        priority="medium",
    )


def _broad_write_scope(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="narrow_write_scope",
        title="Constrain write scope",
        details="Replace broad or repo-external write paths with explicit repo-owned subdirectories.",
        target="path_rules.write_allow",
        suggested_change={"operation": "replace_or_review", "current": finding.path, "recommended_values": ["src/**", "tests/**", "outputs/**"]},
        priority="high" if finding.severity == "error" else "medium",
    )


def _path_outside_write_allowlist(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="align_write_allowlist",
        title="Align write path with allowlist",
        details="Move the write target into an allowed directory or add a narrow, reviewed write allow pattern.",
        target="path_rules.write_allow",
        suggested_change={"operation": "review_append", "value": finding.path},
        priority="high",
    )


def _path_matches_deny_rule(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="remove_denied_path",
        title="Remove denied path access",
        details="The path is covered by a deny rule; remove it from tool configuration or replace it with a safe fixture path.",
        target=f"tools.{finding.tool}.paths",
        suggested_change={"operation": "remove_path", "value": finding.path},
        priority="high",
    )


def _broad_read_scope(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="narrow_read_scope",
        title="Constrain read scope",
        details="Replace broad read access with the smallest paths needed for the task.",
        target="path_rules.read_allow",
        suggested_change={"operation": "replace_or_review", "current": finding.path, "recommended_values": ["src/**", "tests/**", "README.md"]},
        priority="medium",
    )


def _path_outside_read_allowlist(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="align_read_allowlist",
        title="Align read path with allowlist",
        details="Move the read target into an allowed directory or add a narrow, reviewed read allow pattern.",
        target="path_rules.read_allow",
        suggested_change={"operation": "review_append", "value": finding.path},
        priority="medium",
    )


def _package_install(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="pin_dependency_mutation",
        title="Constrain package install commands",
        details="Move dependency installation to a reviewed setup step with lockfiles, or add a narrow allow pattern for the exact command.",
        target="shell.allow_patterns",
        suggested_change={"operation": "review_append", "value": _command_to_allow_pattern(finding.command)},
        priority="medium",
    )


def _network_transfer(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="review_network_transfer",
        title="Review network transfer command",
        details="Require a known host, checksum, or separate read-only network tool for network transfer commands.",
        target="policy.network.hosts",
        suggested_change={"operation": "review_host_allowlist", "command": finding.command},
        priority="medium",
    )


def _git_push_or_commit(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="gate_vcs_mutation",
        title="Gate git write operations",
        details="Require human review or a dedicated release workflow before agent commits, tags, merges, or pushes.",
        target="shell.allow_patterns",
        suggested_change={"operation": "review_append", "value": _command_to_allow_pattern(finding.command)},
        priority="medium",
    )


def _privilege_escalation(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="block_privilege_escalation",
        title="Block privilege escalation",
        details="Deny commands that request elevated privileges in shared developer workspaces.",
        target="shell.deny_patterns",
        suggested_change={"operation": "append", "value": "sudo *", "alternatives": ["runas *", "Set-ExecutionPolicy *"]},
        priority="medium",
    )


def _process_termination(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="review_process_termination",
        title="Review process termination command",
        details="Require explicit owner approval before agents terminate processes that may belong to another developer or service.",
        target="shell.allow_patterns",
        suggested_change={"operation": "review_append", "value": _command_to_allow_pattern(finding.command)},
        priority="medium",
    )


def _generic_finding(finding: Finding) -> RemediationItem:
    return _base_finding_item(
        finding,
        action="review_finding",
        title=f"Review {finding.title}",
        details=finding.description,
        target=finding.tool or finding.capability or finding.rule_id,
        suggested_change={"operation": "manual_review"},
        priority=SEVERITY_PRIORITY.get(finding.severity, "low"),
    )


def _normalize_priority(priority: str) -> str:
    return priority if priority in PRIORITY_ORDER else "low"


def _command_to_allow_pattern(command: Optional[str]) -> str:
    if not command:
        return "<exact command pattern>"
    stripped = " ".join(command.split())
    if len(stripped) > 80:
        return stripped[:77].rstrip() + "*"
    return stripped


def _suggested_change_text(item: RemediationItem) -> str:
    if not item.suggested_change:
        return "-"
    operation = item.suggested_change.get("operation", "review")
    value = item.suggested_change.get("value")
    if value is not None:
        return f"{operation}: {value}"
    current = item.suggested_change.get("current")
    if current is not None:
        return f"{operation}: {current}"
    command = item.suggested_change.get("command")
    if command is not None:
        return f"{operation}: {command}"
    details = item.suggested_change.get("details")
    if details is not None:
        return f"{operation}: {details}"
    return str(operation)


def _escape_markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
