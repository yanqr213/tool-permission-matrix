import json
import tempfile
import unittest
from pathlib import Path

from tool_permission_matrix.parser import (
    discover_inputs,
    normalize_log_event,
    normalize_tool_entry,
    parse_log_records,
    parse_plain_log_line,
    parse_policy,
    parse_shell_config,
    parse_tool_inventory,
)


class ParserTests(unittest.TestCase):
    def test_normalize_tool_entry_infers_permissions(self):
        record = normalize_tool_entry(
            {
                "name": "shell",
                "commands": ["git status"],
                "permissions": {"process_execute": True},
            },
            source="manifest.json",
        )
        self.assertIn("process_execute", record.capabilities)
        self.assertIn("file_read", record.capabilities)

    def test_plain_log_line_parser(self):
        parsed = parse_plain_log_line("tool=shell command=git status")
        self.assertEqual(parsed["tool"], "shell")
        self.assertEqual(parsed["command"], "git status")

    def test_normalize_log_event_extracts_url(self):
        record = normalize_log_event({"tool": "browser.open", "url": "https://docs.python.org"}, "x.jsonl")
        self.assertIn("browse", record.capabilities)
        self.assertIn("network", record.capabilities)

    def test_parse_policy_defaults_when_path_missing(self):
        policy = parse_policy(None)
        self.assertFalse(policy.network["allow"])
        self.assertEqual(policy.check_threshold, "error")

    def test_parse_shell_config_merges_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "shell-a.json")
            second = Path(tmp, "shell-b.json")
            first.write_text(json.dumps({"allow_patterns": ["git status*"]}), encoding="utf-8")
            second.write_text(json.dumps({"deny_patterns": ["rm -rf *"]}), encoding="utf-8")
            merged = parse_shell_config([first, second])
        self.assertEqual(merged["allow_patterns"], ["git status*"])
        self.assertEqual(merged["deny_patterns"], ["rm -rf *"])

    def test_parse_tool_inventory_reads_list_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "tools.json")
            path.write_text(json.dumps([{"name": "browser", "browse": True, "network": True}]), encoding="utf-8")
            records = parse_tool_inventory([path])
        self.assertEqual(records[0].name, "browser")
        self.assertIn("browse", records[0].capabilities)

    def test_parse_log_records_merges_same_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "agent.jsonl")
            path.write_text(
                "\n".join(
                    [
                        json.dumps({"tool": "shell", "command": "git status"}),
                        json.dumps({"tool": "shell", "command": "git commit -m update"}),
                    ]
                ),
                encoding="utf-8",
            )
            records = parse_log_records([path])
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0].commands), 2)

    def test_discover_inputs_by_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            Path(root, "tools.json").write_text("{}", encoding="utf-8")
            Path(root, "agent.jsonl").write_text("", encoding="utf-8")
            Path(root, "team-policy.json").write_text("{}", encoding="utf-8")
            Path(root, "shell-rules.json").write_text("{}", encoding="utf-8")
            found = discover_inputs(root)
        self.assertEqual(len(found["tools"]), 1)
        self.assertEqual(len(found["logs"]), 1)
        self.assertEqual(len(found["policies"]), 1)
        self.assertEqual(len(found["shell_configs"]), 1)
