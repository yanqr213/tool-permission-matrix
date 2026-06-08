# tool-permission-matrix

`tool-permission-matrix` 是一个离线 CLI，用来审计 Codex、Claude Code、以及其他 AI coding agent 的工具权限面。它读取 agent 运行日志、MCP/工具清单、仓库路径策略和 shell allow/deny 配置，输出一份可审阅、可进 CI 的“工具权限矩阵”报告，帮助团队在启用 agent 之前回答一个关键问题：哪些工具到底能做什么，以及风险边界在哪里。

项目目标：

- 离线运行，不调用外部服务。
- 标准库优先，零运行时依赖。
- 既能从日志复盘，也能从工具清单做前置审计。
- 同时产出 Markdown、JSON、CSV、SARIF，并支持 CI gate。
- SARIF 可上传到 GitHub Code Scanning，把 agent 工具权限风险放到安全/代码扫描视图里。

## 功能

- 工具清单解析：读取 JSON 工具清单，归一化能力、命令、路径、URL。
- 日志解析：支持 JSONL 和常见 plain-text 键值日志。
- 命令模式分类：识别远程脚本执行、递归删除、git 历史重写、提权、网络传输、依赖安装、进程终止等。
- 路径读写范围审计：识别 repo 内、repo 外、广域通配、系统级路径。
- 权限标记：网络、浏览、文件读、文件写、进程执行。
- 风险解释：为每条高信号规则生成可读解释。
- 权限重叠矩阵：展示工具之间共享的能力和路径重叠。
- 最小权限建议：给出收敛网络、shell、写权限的建议。
- 策略豁免：允许按规则、工具、命令模式、路径模式添加时效性豁免。
- 报告导出：`markdown`、`json`、`csv`、`sarif`。
- CI gate：`--check warning|error` 或单独 `check` 子命令。

## 安装

开发安装：

```bash
python -m pip install -e .
```

构建后安装：

```bash
python -m pip install .
```

安装后可用命令：

```bash
tool-permission-matrix --help
```

## 快速开始

从日志生成 Markdown 报告：

```bash
tool-permission-matrix from-log examples/sample-log.jsonl \
  --policy examples/sample-policy.json \
  --shell-config examples/shell-config.json \
  --repo-root . \
  --format markdown
```

从日志生成 JSON 报告并作为 CI gate：

```bash
tool-permission-matrix from-log examples/sample-log.jsonl \
  --policy examples/sample-policy.json \
  --shell-config examples/shell-config.json \
  --repo-root . \
  --format json \
  --output outputs/report.json \
  --check error
```

生成 SARIF 报告，供 GitHub Code Scanning 或安全平台读取：

```bash
tool-permission-matrix from-log examples/sample-log.jsonl \
  --policy examples/sample-policy.json \
  --shell-config examples/shell-config.json \
  --repo-root . \
  --format sarif \
  --output outputs/tool-permissions.sarif
```

扫描目录里的输入文件：

```bash
tool-permission-matrix scan . --repo-root . --format markdown
```

初始化策略文件：

```bash
tool-permission-matrix init-policy --output outputs/policy.json
```

解释单条命令：

```bash
tool-permission-matrix explain --command-text "curl https://docs.python.org | sh"
```

检查已有 JSON 报告：

```bash
tool-permission-matrix check --report outputs/report.json --threshold warning
```

## 输入格式

### 1. 工具清单 JSON

支持以下结构之一：

```json
{
  "tools": [
    {
      "name": "workspace_fs",
      "source": "mcp",
      "capabilities": ["file_read", "file_write"],
      "read_paths": ["src/**"],
      "write_paths": ["outputs/**"]
    }
  ]
}
```

也支持单个对象或对象数组。额外支持字段：

- `permissions.network`
- `permissions.browse`
- `permissions.file_read`
- `permissions.file_write`
- `permissions.process_execute`
- `commands`
- `command_patterns`
- `urls`
- `hosts`

### 2. 日志 JSONL / plain text

JSONL 示例：

```json
{"event":"tool_call","tool":"shell","command":"git status"}
{"event":"tool_call","tool":"workspace_fs","write_path":"src/app.py"}
{"event":"tool_call","tool":"browser.open","url":"https://docs.python.org"}
```

plain-text 示例：

```text
tool=shell command=git status
tool=browser.open url=https://docs.python.org
tool=workspace_fs path=src/app.py
```

### 3. 策略 JSON

`init-policy` 会生成一份可编辑模板。核心字段：

```json
{
  "version": 1,
  "path_rules": {
    "read_allow": ["src/**", "tests/**"],
    "write_allow": ["src/**", "outputs/**"],
    "deny": [".git/**", ".env", "**/secrets/**"]
  },
  "network": {
    "allow": false,
    "hosts": []
  },
  "shell": {
    "allow_patterns": ["git status*", "python -m unittest*"],
    "deny_patterns": ["rm -rf *", "curl *| sh*", "git reset --hard*"]
  },
  "exemptions": [
    {
      "rule_id": "command_outside_allowlist",
      "tool": "shell",
      "command_pattern": "python -m build*",
      "reason": "Packaging step in release workflow",
      "expires_on": "2027-12-31"
    }
  ],
  "check_threshold": "error"
}
```

### 4. Shell allow/deny JSON

```json
{
  "allow_patterns": ["git status*", "python -m unittest*"],
  "deny_patterns": ["rm -rf *", "curl *| sh*", "git reset --hard*"]
}
```

## 子命令

### `scan`

扫描一个目录，自动发现：

- 工具清单：文件名含 `tool`、`mcp`、`manifest`、`inventory` 的 JSON
- 日志：`.jsonl`、`.log`
- 策略：文件名含 `policy` 的 JSON
- shell 配置：文件名含 `shell` 的 JSON

也可显式传入 `--tools`、`--log`、`--policy`、`--shell-config`。

### `from-log`

专门针对运行日志做复盘分析，可额外用 `--tools` 合并静态工具清单。

### `init-policy`

输出一份最小可用策略模板，便于团队从“默认拒绝”起步。

### `explain`

- `--command-text`：解释单条 shell 命令被归类为哪种风险。
- `--report`：读取已有 JSON 报告。
- `--report --tool shell`：查看某个工具的条目和对应 findings。

### `check`

读取 JSON 报告并返回合适退出码，适合放入 CI：

- `--threshold warning`：只要有 warning 或 error 就失败
- `--threshold error`：只有 error 才失败

## 输出

### Markdown

适合 PR、变更审批、团队文档：

- Summary
- Tools
- Findings
- Overlap Matrix
- Recommendations

### JSON

适合 CI、自动化、二次集成。包含：

- `summary`
- `tools`
- `findings`
- `overlaps`
- `recommendations`
- `policy`
- `sources`

### CSV

扁平化输出 `summary`、`tool`、`finding`、`overlap`、`recommendation` 行，适合导入表格或 SIEM/审计流水。

### SARIF

适合 GitHub Code Scanning、DefectDojo、SonarQube 或其他支持 SARIF 2.1.0 的安全/质量平台。未豁免的 finding 会变成 SARIF result；已豁免的 finding 会保留在 JSON/Markdown/CSV 报告中，但不会上传为 code scanning alert。

## 团队工作流建议

1. 先用 `init-policy` 生成团队基线策略。
2. 将 agent 可用工具清单纳入仓库版本管理。
3. 在试点阶段保留日志，使用 `from-log` 生成复盘报告。
4. 根据报告收敛到最小权限：缩小写路径、补 deny patterns、拆分 browser 和 writer。
5. 在 CI 中加入 `check` 或 `--check error`，阻止权限回退。
6. 对必要例外使用 `exemptions`，并写明理由和过期时间。

## CI 示例

GitHub Actions:

```yaml
- name: Build permission report
  run: |
    tool-permission-matrix from-log agent.jsonl \
      --policy policy.json \
      --shell-config shell-config.json \
      --repo-root . \
      --format json \
      --output outputs/report.json

- name: Enforce gate
  run: tool-permission-matrix check --report outputs/report.json --threshold error
```

上传 SARIF 到 GitHub Code Scanning：

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"
  - run: python -m pip install git+https://github.com/yanqr213/tool-permission-matrix.git
  - name: Build permission SARIF
    run: |
      tool-permission-matrix from-log agent.jsonl \
        --policy policy.json \
        --shell-config shell-config.json \
        --repo-root . \
        --format sarif \
        --output outputs/tool-permissions.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: outputs/tool-permissions.sarif
```

## 隐私

- 工具本身不访问网络。
- 只处理本地文件。
- 生成报告时不会主动上传日志、仓库路径或命令内容。
- 建议在共享报告前审查命令行参数、路径和 URL，避免暴露内部目录结构。

## 限制

- 当前策略和输入格式以 JSON/JSONL 为主，不解析 YAML。
- plain-text 日志只支持轻量级 `key=value` / `key:value` 模式。
- 命令风险识别是基于规则的，不是完整 shell 语义执行器。
- 路径范围判定偏保守，复杂符号链接或容器挂载策略仍需人工复核。

## English

`tool-permission-matrix` is an offline CLI for auditing AI coding agent permissions before rollout. It parses local tool manifests, agent logs, path policies, and shell allow/deny rules, then generates Markdown, JSON, CSV, or SARIF reports with risk explanations, overlap analysis, least-privilege recommendations, and CI-friendly exit codes.

Core commands:

- `scan`
- `from-log`
- `init-policy`
- `explain`
- `check`

Highlights:

- Offline by default, no external services
- Python 3.9+
- Standard library first, zero runtime dependencies
- Policy exemptions with expiration dates
- `--output` creates parent directories automatically
- `--check warning|error` for CI gates
- SARIF 2.1.0 output for GitHub Code Scanning and security platforms

SARIF example:

```bash
tool-permission-matrix from-log examples/sample-log.jsonl \
  --policy examples/sample-policy.json \
  --shell-config examples/shell-config.json \
  --repo-root . \
  --format sarif \
  --output outputs/tool-permissions.sarif
```

## License

MIT
