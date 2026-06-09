import json
import tempfile
import unittest
from pathlib import Path

from tool_permission_matrix.models import Finding, OverlapEntry, Recommendation, RemediationItem, Report, ToolRecord
from tool_permission_matrix.reporting import render_report, write_output


class ReportingTests(unittest.TestCase):
    def build_report(self):
        return Report(
            summary={
                "tool_count": 1,
                "effective_finding_count": 1,
                "warning_count": 1,
                "error_count": 0,
                "exempted_count": 0,
                "capabilities": {"file_read": 1},
            },
            tools=[ToolRecord(name="reader", source="x", capabilities={"file_read"}, read_paths=["src/app.py"])],
            findings=[Finding("broad_read_scope", "warning", "Broad read scope", "x", tool="reader", path="/tmp/file")],
            overlaps=[OverlapEntry("reader", "shell", ["file_read"], False, False)],
            recommendations=[Recommendation("medium", "Create a shell allowlist", "x", tool="shell")],
            remediation_plan=[
                RemediationItem(
                    id="rem-001",
                    priority="medium",
                    status="todo",
                    action="review_shell_allowlist",
                    title="Review shell command allowlist",
                    details="x",
                    target="shell.allow_patterns",
                    tool="shell",
                    finding_rule_id="command_outside_allowlist",
                    severity="warning",
                    suggested_change={"operation": "review_append", "value": "git status"},
                )
            ],
            sources=["sample.json"],
        )

    def test_render_markdown(self):
        text = render_report(self.build_report(), "markdown")
        self.assertIn("# Tool Permission Matrix", text)
        self.assertIn("## Findings", text)

    def test_render_json(self):
        text = render_report(self.build_report(), "json")
        payload = json.loads(text)
        self.assertEqual(payload["summary"]["tool_count"], 1)
        self.assertEqual(payload["remediation_plan"][0]["id"], "rem-001")

    def test_render_csv(self):
        text = render_report(self.build_report(), "csv")
        self.assertIn("section,name,value", text)
        self.assertIn("recommendation", text)
        self.assertIn("remediation", text)

    def test_render_sarif(self):
        text = render_report(self.build_report(), "sarif")
        payload = json.loads(text)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "tool-permission-matrix")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "broad_read_scope")
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "warning")

    def test_render_sarif_uses_relative_source_uri(self):
        report = self.build_report()
        report.sources = [str(Path.cwd() / "examples" / "sample-log.jsonl")]
        payload = json.loads(render_report(report, "sarif"))

        location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(location, "examples/sample-log.jsonl")

    def test_render_sarif_omits_exempted_findings(self):
        report = self.build_report()
        report.findings[0].exempted = True
        text = render_report(report, "sarif")
        payload = json.loads(text)

        self.assertEqual(payload["runs"][0]["results"], [])
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["rules"], [])

    def test_render_remediation_markdown(self):
        text = render_report(self.build_report(), "remediation-markdown")

        self.assertIn("# Tool Permission Remediation Plan", text)
        self.assertIn("review_shell_allowlist", text)
        self.assertIn("shell.allow_patterns", text)
        self.assertIn("rem-001", text)

    def test_render_remediation_json(self):
        payload = json.loads(render_report(self.build_report(), "remediation-json"))

        self.assertEqual(payload["summary"]["effective_finding_count"], 1)
        self.assertEqual(payload["summary"]["remediation_count"], 1)
        self.assertEqual(payload["remediation_plan"][0]["priority"], "medium")
        self.assertEqual(payload["remediation_plan"][0]["tool"], "shell")

    def test_render_remediation_markdown_empty_plan(self):
        report = Report(
            summary={
                "tool_count": 0,
                "effective_finding_count": 0,
                "warning_count": 0,
                "error_count": 0,
                "exempted_count": 0,
                "capabilities": {},
            },
            tools=[],
            findings=[],
            overlaps=[],
            recommendations=[],
            remediation_plan=[],
        )

        text = render_report(report, "remediation-markdown")

        self.assertIn("No remediation needed", text)

    def test_write_output_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "nested", "report.md")
            write_output("hello", path)
            self.assertEqual(path.read_text(encoding="utf-8"), "hello")
