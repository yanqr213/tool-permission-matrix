import unittest
from datetime import date
from pathlib import Path

from tool_permission_matrix.models import Finding, Policy
from tool_permission_matrix.policy import apply_exemptions, filter_effective_findings, path_matches_any, severity_at_least


class PolicyTests(unittest.TestCase):
    def test_severity_at_least(self):
        self.assertTrue(severity_at_least("error", "warning"))
        self.assertFalse(severity_at_least("warning", "error"))

    def test_apply_exemptions_marks_finding(self):
        finding = Finding("recursive_delete", "error", "Recursive delete", "x", tool="shell", command="rm -rf build")
        policy = Policy(exemptions=[{"rule_id": "recursive_delete", "tool": "shell", "reason": "sandbox"}])
        result = apply_exemptions([finding], policy, today=date(2026, 6, 8))
        self.assertTrue(result[0].exempted)

    def test_expired_exemption_does_not_apply(self):
        finding = Finding("recursive_delete", "error", "Recursive delete", "x", tool="shell", command="rm -rf build")
        policy = Policy(exemptions=[{"rule_id": "recursive_delete", "expires_on": "2026-01-01"}])
        result = apply_exemptions([finding], policy, today=date(2026, 6, 8))
        self.assertFalse(result[0].exempted)

    def test_filter_effective_findings_ignores_exempted(self):
        findings = [
            Finding("a", "warning", "A", "x", exempted=True),
            Finding("b", "error", "B", "x"),
        ]
        result = filter_effective_findings(findings, "warning")
        self.assertEqual([item.rule_id for item in result], ["b"])

    def test_path_matches_any_absolute_and_relative(self):
        repo_root = Path("/repo")
        self.assertTrue(path_matches_any("/repo/src/app.py", ["src/**"], repo_root))
        self.assertFalse(path_matches_any("/repo/docs/app.py", ["src/**"], repo_root))
