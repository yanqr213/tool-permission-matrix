from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set


CAPABILITY_ORDER = [
    "network",
    "browse",
    "file_read",
    "file_write",
    "process_execute",
]


@dataclass
class ToolRecord:
    name: str
    source: str
    capabilities: Set[str] = field(default_factory=set)
    commands: List[str] = field(default_factory=list)
    read_paths: List[str] = field(default_factory=list)
    write_paths: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def merge(self, other: "ToolRecord") -> None:
        self.capabilities.update(other.capabilities)
        self.commands.extend(item for item in other.commands if item not in self.commands)
        self.read_paths.extend(item for item in other.read_paths if item not in self.read_paths)
        self.write_paths.extend(item for item in other.write_paths if item not in self.write_paths)
        self.urls.extend(item for item in other.urls if item not in self.urls)
        self.metadata.update(other.metadata)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "capabilities": sorted(self.capabilities),
            "commands": list(self.commands),
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
            "urls": list(self.urls),
            "metadata": dict(self.metadata),
        }


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    tool: Optional[str] = None
    command: Optional[str] = None
    path: Optional[str] = None
    capability: Optional[str] = None
    exempted: bool = False
    exemption_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "tool": self.tool,
            "command": self.command,
            "path": self.path,
            "capability": self.capability,
            "exempted": self.exempted,
            "exemption_reason": self.exemption_reason,
        }


@dataclass
class Recommendation:
    priority: str
    title: str
    details: str
    tool: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "priority": self.priority,
            "title": self.title,
            "details": self.details,
            "tool": self.tool,
        }


@dataclass
class RemediationItem:
    priority: str
    status: str
    action: str
    title: str
    details: str
    target: str
    id: str = ""
    tool: Optional[str] = None
    finding_rule_id: Optional[str] = None
    severity: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    suggested_change: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "priority": self.priority,
            "status": self.status,
            "action": self.action,
            "title": self.title,
            "details": self.details,
            "target": self.target,
            "tool": self.tool,
            "finding_rule_id": self.finding_rule_id,
            "severity": self.severity,
            "evidence": dict(self.evidence),
            "suggested_change": dict(self.suggested_change),
        }


@dataclass
class OverlapEntry:
    tool_a: str
    tool_b: str
    shared_capabilities: List[str]
    read_scope_overlap: bool
    write_scope_overlap: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_a": self.tool_a,
            "tool_b": self.tool_b,
            "shared_capabilities": list(self.shared_capabilities),
            "read_scope_overlap": self.read_scope_overlap,
            "write_scope_overlap": self.write_scope_overlap,
        }


@dataclass
class Policy:
    path_rules: Dict[str, List[str]] = field(
        default_factory=lambda: {"read_allow": [], "write_allow": [], "deny": []}
    )
    network: Dict[str, Any] = field(default_factory=lambda: {"allow": False, "hosts": []})
    shell: Dict[str, List[str]] = field(
        default_factory=lambda: {"allow_patterns": [], "deny_patterns": []}
    )
    exemptions: List[Dict[str, Any]] = field(default_factory=list)
    check_threshold: str = "error"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "path_rules": dict(self.path_rules),
            "network": dict(self.network),
            "shell": dict(self.shell),
            "exemptions": list(self.exemptions),
            "check_threshold": self.check_threshold,
        }


@dataclass
class Report:
    summary: Dict[str, Any]
    tools: Sequence[ToolRecord]
    findings: Sequence[Finding]
    overlaps: Sequence[OverlapEntry]
    recommendations: Sequence[Recommendation]
    policy: Optional[Policy] = None
    sources: Sequence[str] = field(default_factory=list)
    remediation_plan: Sequence[RemediationItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "tools": [tool.to_dict() for tool in self.tools],
            "findings": [finding.to_dict() for finding in self.findings],
            "overlaps": [entry.to_dict() for entry in self.overlaps],
            "recommendations": [item.to_dict() for item in self.recommendations],
            "remediation_plan": [item.to_dict() for item in self.remediation_plan],
            "policy": self.policy.to_dict() if self.policy else None,
            "sources": list(self.sources),
        }
