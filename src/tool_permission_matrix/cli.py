from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Sequence

from tool_permission_matrix import __version__
from tool_permission_matrix.analysis import build_report, explain_command
from tool_permission_matrix.models import Policy, Report
from tool_permission_matrix.parser import (
    discover_inputs,
    parse_log_records,
    parse_policy,
    parse_shell_config,
    parse_tool_inventory,
)
from tool_permission_matrix.policy import filter_effective_findings, severity_at_least
from tool_permission_matrix.reporting import render_report, write_output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tool-permission-matrix")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a workspace for tool manifests, logs, policies, and shell configs.")
    scan.add_argument("path", nargs="?", default=".", help="Workspace root to scan.")
    scan.add_argument("--repo-root", default=".", help="Repository root used for path scope analysis.")
    scan.add_argument("--tools", nargs="*", default=None, help="Explicit tool manifest JSON files.")
    scan.add_argument("--log", nargs="*", default=None, help="Explicit JSONL or log files.")
    scan.add_argument("--policy", default=None, help="Policy JSON file.")
    scan.add_argument("--shell-config", nargs="*", default=None, help="Shell config JSON files.")
    add_report_args(scan)

    from_log = subparsers.add_parser("from-log", help="Build a report from one or more agent logs.")
    from_log.add_argument("logs", nargs="+", help="JSONL or plain-text log files.")
    from_log.add_argument("--repo-root", default=".", help="Repository root used for path scope analysis.")
    from_log.add_argument("--tools", nargs="*", default=None, help="Optional tool manifest JSON files to merge.")
    from_log.add_argument("--policy", default=None, help="Policy JSON file.")
    from_log.add_argument("--shell-config", nargs="*", default=None, help="Shell config JSON files.")
    add_report_args(from_log)

    init_policy = subparsers.add_parser("init-policy", help="Write a starter policy file.")
    init_policy.add_argument("--output", required=True, help="Destination JSON file.")
    init_policy.add_argument("--force", action="store_true", help="Overwrite the destination if it already exists.")

    explain = subparsers.add_parser("explain", help="Explain a command rule or tool from a JSON report.")
    explain_group = explain.add_mutually_exclusive_group(required=True)
    explain_group.add_argument("--command-text", help="Shell command to classify and explain.")
    explain_group.add_argument("--report", help="Existing JSON report to inspect.")
    explain.add_argument("--tool", help="Tool name to explain when using --report.")

    check = subparsers.add_parser("check", help="Fail CI when a JSON report contains findings at or above a threshold.")
    check.add_argument("--report", required=True, help="JSON report produced by scan or from-log.")
    check.add_argument("--threshold", choices=("warning", "error"), default="error", help="Fail on warning or error.")

    return parser


def add_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "csv", "sarif", "remediation-json", "remediation-markdown"),
        default="markdown",
    )
    parser.add_argument("--output", default=None, help="Write report to a file; parent directories are created automatically.")
    parser.add_argument("--check", choices=("warning", "error"), default=None, help="Exit non-zero if findings at or above the threshold remain after exemptions.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)
    if args.command == "from-log":
        return run_from_log(args)
    if args.command == "init-policy":
        return run_init_policy(args)
    if args.command == "explain":
        return run_explain(args)
    if args.command == "check":
        return run_check(args)
    parser.error("Unknown command")
    return 2


def run_scan(args: argparse.Namespace) -> int:
    scan_root = Path(args.path).resolve()
    repo_root = Path(args.repo_root).resolve()
    discovered = discover_inputs(scan_root)
    tool_paths = _coerce_paths(args.tools) if args.tools is not None else discovered["tools"]
    log_paths = _coerce_paths(args.log) if args.log is not None else discovered["logs"]
    policy_path = Path(args.policy).resolve() if args.policy else (discovered["policies"][0] if discovered["policies"] else None)
    shell_paths = _coerce_paths(args.shell_config) if args.shell_config is not None else discovered["shell_configs"]

    tools = []
    if tool_paths:
        tools.extend(parse_tool_inventory(tool_paths))
    if log_paths:
        tools = _merge_tools(tools, parse_log_records(log_paths))

    report = build_report(
        tools=tools,
        repo_root=repo_root,
        policy=parse_policy(policy_path),
        shell_config=parse_shell_config(shell_paths),
        sources=[str(item) for item in [*tool_paths, *log_paths] if item],
    )
    return emit_report(report, args.format, args.output, args.check)


def run_from_log(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve()
    log_paths = _coerce_paths(args.logs)
    tools = parse_log_records(log_paths)
    if args.tools:
        tools = _merge_tools(tools, parse_tool_inventory(_coerce_paths(args.tools)))
    policy_path = Path(args.policy).resolve() if args.policy else None
    shell_paths = _coerce_paths(args.shell_config)
    report = build_report(
        tools=tools,
        repo_root=repo_root,
        policy=parse_policy(policy_path),
        shell_config=parse_shell_config(shell_paths),
        sources=[str(item) for item in log_paths],
    )
    return emit_report(report, args.format, args.output, args.check)


def run_init_policy(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    if output.exists() and not args.force:
        print(f"Refusing to overwrite existing file: {output}", file=sys.stderr)
        return 1
    starter = Policy(
        path_rules={
            "read_allow": ["src/**", "tests/**", "README.md"],
            "write_allow": ["src/**", "tests/**", "outputs/**"],
            "deny": [".git/**", ".env", "**/secrets/**"],
        },
        network={"allow": False, "hosts": []},
        shell={
            "allow_patterns": ["git status*", "git diff*", "python -m unittest*"],
            "deny_patterns": ["rm -rf *", "curl *| sh*", "git reset --hard*"],
        },
        exemptions=[
            {
                "rule_id": "command_outside_allowlist",
                "tool": "shell",
                "command_pattern": "python -m build*",
                "reason": "Packaging step in release workflow",
                "expires_on": "2027-12-31",
            }
        ],
        check_threshold="error",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(starter.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


def run_explain(args: argparse.Namespace) -> int:
    if args.command_text:
        print(json.dumps(explain_command(args.command_text), ensure_ascii=False, indent=2))
        return 0
    report_path = Path(args.report).resolve()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not args.tool:
        print(json.dumps(payload.get("summary", {}), ensure_ascii=False, indent=2))
        return 0
    tools = payload.get("tools", [])
    findings = payload.get("findings", [])
    remediation_plan = payload.get("remediation_plan", [])
    selected_tools = [item for item in tools if item.get("name") == args.tool]
    selected_findings = [item for item in findings if item.get("tool") == args.tool]
    selected_remediation = [item for item in remediation_plan if item.get("tool") == args.tool]
    output = {"tool": selected_tools, "findings": selected_findings, "remediation_plan": selected_remediation}
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def run_check(args: argparse.Namespace) -> int:
    report_path = Path(args.report).resolve()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    findings = payload.get("findings", [])
    effective = [item for item in findings if not item.get("exempted") and severity_at_least(item.get("severity", "info"), args.threshold)]
    if effective:
        print(json.dumps({"status": "fail", "threshold": args.threshold, "count": len(effective)}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "pass", "threshold": args.threshold, "count": 0}, ensure_ascii=False))
    return 0


def emit_report(report: Report, output_format: str, output_path: str | None, threshold: str | None) -> int:
    text = render_report(report, output_format)
    destination = Path(output_path).resolve() if output_path else None
    if destination:
        write_output(text, destination)
        print(destination)
    else:
        print(text, end="")

    if threshold is None:
        return 0
    remaining = filter_effective_findings(report.findings, threshold)
    return 1 if remaining else 0


def _coerce_paths(values: Sequence[str] | None) -> List[Path]:
    if not values:
        return []
    return [Path(value).resolve() for value in values]


def _merge_tools(primary: Sequence, secondary: Sequence) -> List:
    index = {tool.name: tool for tool in primary}
    for tool in secondary:
        existing = index.get(tool.name)
        if existing:
            existing.merge(tool)
        else:
            index[tool.name] = tool
    return sorted(index.values(), key=lambda item: item.name)


if __name__ == "__main__":
    raise SystemExit(main())
