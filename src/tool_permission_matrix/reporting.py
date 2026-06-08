from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path
from typing import Iterable

from tool_permission_matrix.models import Report


def render_report(report: Report, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    if output_format == "csv":
        return render_csv(report)
    if output_format == "sarif":
        return render_sarif(report)
    if output_format == "markdown":
        return render_markdown(report)
    raise ValueError(f"Unsupported format: {output_format}")


def write_output(text: str, output_path: Path | None) -> None:
    if output_path is None:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")


def render_markdown(report: Report) -> str:
    lines = [
        "# Tool Permission Matrix",
        "",
        "## Summary",
        "",
        f"- Tools: {report.summary['tool_count']}",
        f"- Effective findings: {report.summary['effective_finding_count']}",
        f"- Warnings: {report.summary['warning_count']}",
        f"- Errors: {report.summary['error_count']}",
        f"- Exempted: {report.summary['exempted_count']}",
        "",
        "## Tools",
        "",
        "| Tool | Source | Capabilities | Read paths | Write paths |",
        "| --- | --- | --- | --- | --- |",
    ]
    for tool in report.tools:
        lines.append(
            "| {name} | {source} | {caps} | {reads} | {writes} |".format(
                name=tool.name,
                source=tool.source,
                caps=", ".join(sorted(tool.capabilities)) or "-",
                reads=", ".join(tool.read_paths) or "-",
                writes=", ".join(tool.write_paths) or "-",
            )
        )

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Severity | Rule | Tool | Details | Exempted |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for finding in report.findings:
        detail = finding.command or finding.path or finding.description
        lines.append(
            "| {severity} | {rule} | {tool} | {detail} | {exempted} |".format(
                severity=finding.severity,
                rule=finding.rule_id,
                tool=finding.tool or "-",
                detail=str(detail).replace("|", "\\|"),
                exempted="yes" if finding.exempted else "no",
            )
        )

    lines.extend(
        [
            "",
            "## Overlap Matrix",
            "",
            "| Tool A | Tool B | Shared capabilities | Read overlap | Write overlap |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for overlap in report.overlaps:
        lines.append(
            f"| {overlap.tool_a} | {overlap.tool_b} | {', '.join(overlap.shared_capabilities)} | "
            f"{'yes' if overlap.read_scope_overlap else 'no'} | {'yes' if overlap.write_scope_overlap else 'no'} |"
        )
    if not report.overlaps:
        lines.append("| - | - | - | - | - |")

    lines.extend(["", "## Recommendations", ""])
    for item in report.recommendations:
        prefix = f"[{item.priority}]"
        if item.tool:
            lines.append(f"- {prefix} {item.title}: {item.details} (tool: {item.tool})")
        else:
            lines.append(f"- {prefix} {item.title}: {item.details}")
    return "\n".join(lines) + "\n"


def render_csv(report: Report) -> str:
    buffer = StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["section", "name", "value", "severity", "tool", "details", "exempted"],
    )
    writer.writeheader()
    for key, value in report.summary.items():
        writer.writerow(
            {
                "section": "summary",
                "name": key,
                "value": json.dumps(value, ensure_ascii=False) if isinstance(value, dict) else value,
                "severity": "",
                "tool": "",
                "details": "",
                "exempted": "",
            }
        )
    for tool in report.tools:
        writer.writerow(
            {
                "section": "tool",
                "name": tool.name,
                "value": ",".join(sorted(tool.capabilities)),
                "severity": "",
                "tool": tool.name,
                "details": f"reads={';'.join(tool.read_paths)} writes={';'.join(tool.write_paths)}",
                "exempted": "",
            }
        )
    for finding in report.findings:
        writer.writerow(
            {
                "section": "finding",
                "name": finding.rule_id,
                "value": finding.title,
                "severity": finding.severity,
                "tool": finding.tool or "",
                "details": finding.command or finding.path or finding.description,
                "exempted": "yes" if finding.exempted else "no",
            }
        )
    for overlap in report.overlaps:
        writer.writerow(
            {
                "section": "overlap",
                "name": f"{overlap.tool_a}->{overlap.tool_b}",
                "value": ",".join(overlap.shared_capabilities),
                "severity": "",
                "tool": "",
                "details": f"read_overlap={overlap.read_scope_overlap};write_overlap={overlap.write_scope_overlap}",
                "exempted": "",
            }
        )
    for item in report.recommendations:
        writer.writerow(
            {
                "section": "recommendation",
                "name": item.title,
                "value": item.priority,
                "severity": "",
                "tool": item.tool or "",
                "details": item.details,
                "exempted": "",
            }
        )
    return buffer.getvalue()


def render_sarif(report: Report) -> str:
    rules = {}
    for finding in report.findings:
        if finding.exempted:
            continue
        if finding.rule_id in rules:
            continue
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": _sarif_help_text(finding)},
            "properties": {
                "problem.severity": _sarif_problem_severity(finding.severity),
                "security-severity": _security_severity(finding.severity),
                "tags": ["ai-agent-permissions", finding.severity],
            },
        }

    results = []
    for finding in report.findings:
        if finding.exempted:
            continue
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": _sarif_message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _sarif_location(report, finding)},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "tool": finding.tool,
                    "capability": finding.capability,
                    "command": finding.command,
                    "path": finding.path,
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tool-permission-matrix",
                        "informationUri": "https://github.com/yanqr213/tool-permission-matrix",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
                "properties": {
                    "summary": report.summary,
                    "sources": list(report.sources),
                    "exempted_findings": report.summary.get("exempted_count", 0),
                },
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _sarif_message(finding) -> str:
    detail = finding.command or finding.path or finding.capability or finding.description
    if finding.tool:
        return f"{finding.title} in tool '{finding.tool}': {detail}. {finding.description}"
    return f"{finding.title}: {detail}. {finding.description}"


def _sarif_help_text(finding) -> str:
    parts = [finding.description]
    if finding.command:
        parts.append(f"Command: {finding.command}")
    if finding.path:
        parts.append(f"Path: {finding.path}")
    if finding.capability:
        parts.append(f"Capability: {finding.capability}")
    return "\n".join(parts)


def _sarif_location(report: Report, finding) -> str:
    if finding.path and _looks_like_relative_file(finding.path):
        return _normalize_uri(finding.path)
    if report.sources:
        return _normalize_uri(str(report.sources[0]))
    return "tool-permission-matrix-report"


def _looks_like_relative_file(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return not (
        normalized.startswith("/")
        or ":" in normalized
        or any(token in normalized for token in ("*", "?", "[", "]"))
        or normalized in {".", "..", "~"}
    )


def _normalize_uri(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            path = str(candidate.resolve().relative_to(Path.cwd().resolve()))
        except ValueError:
            path = candidate.name or "tool-permission-matrix-report"
    return path.replace("\\", "/").lstrip("./")


def _sarif_level(severity: str) -> str:
    if severity == "error":
        return "error"
    if severity == "warning":
        return "warning"
    return "note"


def _sarif_problem_severity(severity: str) -> str:
    if severity == "error":
        return "error"
    if severity == "warning":
        return "warning"
    return "note"


def _security_severity(severity: str) -> str:
    return {"error": "8.0", "warning": "5.0", "info": "2.0"}.get(severity, "0.0")
