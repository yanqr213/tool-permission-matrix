import json
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from tool_permission_matrix.cli import main


class CliTests(unittest.TestCase):
    def test_init_policy_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "policy.json")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["init-policy", "--output", str(path)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(path.exists())

    def test_init_policy_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "policy.json")
            path.write_text("{}", encoding="utf-8")
            stderr = StringIO()
            with patch("sys.stderr", stderr):
                exit_code = main(["init-policy", "--output", str(path)])
            self.assertEqual(exit_code, 1)

    def test_explain_command_outputs_json(self):
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            exit_code = main(["explain", "--command-text", "rm -rf build"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["rule_id"], "recursive_delete")

    def test_from_log_outputs_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp, "agent.jsonl")
            log_path.write_text(json.dumps({"tool": "shell", "command": "git status"}) + "\n", encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["from-log", str(log_path), "--format", "markdown"])
            self.assertEqual(exit_code, 0)
            self.assertIn("# Tool Permission Matrix", stdout.getvalue())

    def test_from_log_writes_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_path = root / "agent.jsonl"
            output = root / "reports" / "permissions.sarif"
            log_path.write_text(json.dumps({"tool": "shell", "command": "rm -rf build"}) + "\n", encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["from-log", str(log_path), "--format", "sarif", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "recursive_delete")

    def test_from_log_outputs_remediation_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp, "agent.jsonl")
            log_path.write_text(json.dumps({"tool": "shell", "command": "rm -rf build"}) + "\n", encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["from-log", str(log_path), "--format", "remediation-markdown"])

        self.assertEqual(exit_code, 0)
        text = stdout.getvalue()
        self.assertIn("# Tool Permission Remediation Plan", text)
        self.assertIn("block_shell_pattern", text)
        self.assertIn("shell.deny_patterns", text)

    def test_from_log_writes_remediation_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_path = root / "agent.jsonl"
            output = root / "reports" / "remediation.json"
            log_path.write_text(json.dumps({"tool": "shell", "command": "rm -rf build"}) + "\n", encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["from-log", str(log_path), "--format", "remediation-json", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            self.assertIn(str(output.resolve()), stdout.getvalue())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["remediation_count"], 2)
            self.assertEqual(payload["remediation_plan"][0]["priority"], "high")
            self.assertEqual(payload["remediation_plan"][0]["finding_rule_id"], "recursive_delete")

    def test_from_log_check_returns_failure_on_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp, "agent.jsonl")
            log_path.write_text(json.dumps({"tool": "shell", "command": "rm -rf build"}) + "\n", encoding="utf-8")
            exit_code = main(["from-log", str(log_path), "--format", "json", "--check", "error"])
        self.assertEqual(exit_code, 1)

    def test_from_log_check_failure_still_writes_remediation_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_path = root / "agent.jsonl"
            output = root / "reports" / "report.json"
            log_path.write_text(json.dumps({"tool": "shell", "command": "rm -rf build"}) + "\n", encoding="utf-8")
            exit_code = main(["from-log", str(log_path), "--format", "json", "--output", str(output), "--check", "error"])

            self.assertEqual(exit_code, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(payload["remediation_plan"]), 1)

    def test_check_command_passes_clean_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp, "report.json")
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["check", "--report", str(report_path), "--threshold", "warning"])
            self.assertEqual(exit_code, 0)
            self.assertIn('"status": "pass"', stdout.getvalue())

    def test_check_command_fails_on_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp, "report.json")
            report_path.write_text(json.dumps({"findings": [{"severity": "warning", "exempted": False}]}), encoding="utf-8")
            exit_code = main(["check", "--report", str(report_path), "--threshold", "warning"])
        self.assertEqual(exit_code, 1)

    def test_scan_uses_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            Path(root, "tools.json").write_text(
                json.dumps({"tools": [{"name": "browser", "network": True, "browse": True}]}),
                encoding="utf-8",
            )
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["scan", str(root), "--repo-root", str(root), "--format", "json"])
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["summary"]["tool_count"], 1)

    def test_explain_report_includes_tool_remediation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_path = root / "agent.jsonl"
            report_path = root / "report.json"
            log_path.write_text(json.dumps({"tool": "shell", "command": "rm -rf build"}) + "\n", encoding="utf-8")
            main(["from-log", str(log_path), "--format", "json", "--output", str(report_path)])

            stdout = StringIO()
            with patch("sys.stdout", stdout):
                exit_code = main(["explain", "--report", str(report_path), "--tool", "shell"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertGreaterEqual(len(payload["remediation_plan"]), 1)
            self.assertEqual(payload["remediation_plan"][0]["tool"], "shell")

    def test_cli_module_entrypoint(self):
        completed = subprocess.run(
            [sys.executable, "-m", "tool_permission_matrix.cli", "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("tool-permission-matrix 0.3.0", completed.stdout)
