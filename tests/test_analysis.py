import unittest
from pathlib import Path

from tool_permission_matrix.analysis import (
    analyze_commands,
    build_overlap_matrix,
    build_recommendations,
    build_report,
    classify_path_scope,
    merge_shell_config,
)
from tool_permission_matrix.models import Finding, Policy, ToolRecord


class AnalysisTests(unittest.TestCase):
    def test_classify_path_scope_repo_scoped(self):
        scope = classify_path_scope("src/app.py", Path("/repo"))
        self.assertEqual(scope, "repo_scoped")

    def test_classify_path_scope_outside_repo(self):
        scope = classify_path_scope("/tmp/app.py", Path("/repo"))
        self.assertEqual(scope, "outside_repo")

    def test_classify_path_scope_workspace_wide_glob(self):
        scope = classify_path_scope("**/*.py", Path("/repo"))
        self.assertEqual(scope, "workspace_wide")

    def test_analyze_commands_detects_deny_rule(self):
        tool = ToolRecord(name="shell", source="log", capabilities={"process_execute"}, commands=["rm -rf build"])
        findings = analyze_commands(tool, {"allow_patterns": [], "deny_patterns": ["rm -rf *"]})
        rule_ids = {item.rule_id for item in findings}
        self.assertIn("recursive_delete", rule_ids)
        self.assertIn("command_matches_deny_rule", rule_ids)

    def test_build_overlap_matrix_finds_shared_capabilities(self):
        left = ToolRecord(name="a", source="x", capabilities={"file_read", "file_write"}, write_paths=["src/app.py"])
        right = ToolRecord(name="b", source="x", capabilities={"file_write"}, write_paths=["src/app.py"])
        overlaps = build_overlap_matrix([left, right])
        self.assertEqual(len(overlaps), 1)
        self.assertTrue(overlaps[0].write_scope_overlap)

    def test_build_report_counts_findings(self):
        tools = [
            ToolRecord(name="browser", source="x", capabilities={"browse", "network"}),
            ToolRecord(name="writer", source="x", capabilities={"file_write"}, write_paths=["/tmp/out.txt"]),
        ]
        report = build_report(tools, Path("/repo"), Policy(), {"allow_patterns": [], "deny_patterns": []})
        self.assertGreaterEqual(report.summary["effective_finding_count"], 2)

    def test_build_recommendations_returns_overlap_hint(self):
        tools = [
            ToolRecord(name="writer-a", source="x", capabilities={"file_write"}),
            ToolRecord(name="writer-b", source="x", capabilities={"file_write"}),
        ]
        findings = [Finding("broad_write_scope", "error", "x", "x")]
        recommendations = build_recommendations(tools, findings, Policy(), {"allow_patterns": [], "deny_patterns": []})
        titles = [item.title for item in recommendations]
        self.assertIn("Reduce overlapping writer tools", titles)

    def test_merge_shell_config_uses_policy_and_external_rules(self):
        merged = merge_shell_config(
            {"allow_patterns": ["git status*"], "deny_patterns": ["rm -rf *"]},
            {"allow_patterns": ["python -m unittest*"], "deny_patterns": ["git reset --hard*"]},
        )
        self.assertEqual(merged["allow_patterns"], ["git status*", "python -m unittest*"])
        self.assertEqual(merged["deny_patterns"], ["rm -rf *", "git reset --hard*"])
