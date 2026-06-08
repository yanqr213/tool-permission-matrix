# Changelog

## 0.2.0 - 2026-06-08

- Added SARIF 2.1.0 report output for GitHub Code Scanning and security platform ingestion.
- Added CLI support for `--format sarif`.
- SARIF output omits policy-exempted findings so approved exceptions do not become code scanning alerts.
- Added SARIF renderer and CLI tests.
- Expanded Chinese and English README docs with Code Scanning examples.

## 0.1.0 - 2026-06-08

- First public release of `tool-permission-matrix`.
- Added offline CLI subcommands: `scan`, `from-log`, `init-policy`, `explain`, and `check`.
- Added parsers for tool manifests, JSONL logs, plain-text log lines, and shell allow/deny policy files.
- Added command risk rules, path scope auditing, overlap matrix generation, least-privilege recommendations, and policy exemptions.
- Added Markdown, JSON, and CSV report generation.
- Added examples, CI workflow, contributor guide, and test coverage across parser, analysis, reports, policy, and CLI flows.
