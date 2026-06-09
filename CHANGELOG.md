# Changelog

## 0.3.0 - 2026-06-09

- Added a stable remediation plan model for converting effective findings into actionable least-privilege tasks.
- Added `remediation-json` and `remediation-markdown` report formats.
- Added `remediation_plan` to the normal JSON report for CI artifacts and follow-up agent runs.
- Extended Markdown and CSV reports with remediation queue rows.
- Updated `explain --report --tool` to include tool-specific remediation items.
- Added CI smoke coverage and tests for remediation rendering, CLI output, check-failure artifacts, and exemption behavior.
- Expanded Chinese and English README docs with remediation workflow examples.

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
