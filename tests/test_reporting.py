import json
import tempfile
import unittest
from pathlib import Path

from tool_permission_matrix.models import Finding, OverlapEntry, Recommendation, Report, ToolRecord
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

    def test_render_csv(self):
        text = render_report(self.build_report(), "csv")
        self.assertIn("section,name,value", text)
        self.assertIn("recommendation", text)

    def test_write_output_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "nested", "report.md")
            write_output("hello", path)
            self.assertEqual(path.read_text(encoding="utf-8"), "hello")
