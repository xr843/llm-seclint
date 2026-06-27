# llm-seclint

[![CI](https://github.com/xr843/llm-seclint/actions/workflows/ci.yml/badge.svg)](https://github.com/xr843/llm-seclint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Status: pre-release (v0.1.0, alpha).** Not yet published to PyPI — install from source (see [Quick Start](#quick-start)). The API and rule IDs may change before v1.0.

**Find LLM security vulnerabilities before they ship.**

llm-seclint is a static analysis tool that scans Python source code for security issues specific to LLM-powered applications. Think [Bandit](https://github.com/PyCQA/bandit), but for the AI era.

## The Problem

LLM-powered applications introduce a new class of vulnerabilities that traditional security tools miss:

- **Prompt injection** through unsanitized user input
- **Arbitrary code execution** when LLM output flows into `eval()`, `subprocess`, or SQL queries
- **API key leakage** through hardcoded credentials
- **Path traversal** when LLM output controls file access
- **Template injection** when dynamic content reaches template engines unsandboxed
- **XML external entities** when parsing untrusted XML without protection
- **Supply chain attacks** through unpinned LLM dependency versions

Existing tools like [garak](https://github.com/leondz/garak), [LLM Guard](https://github.com/protectai/llm-guard), and [Guardrails](https://github.com/guardrails-ai/guardrails) operate at **runtime** -- they test deployed models or filter live traffic. None of them analyze your **source code** before you ship.

**llm-seclint** fills this gap. It scans your Python source using AST analysis to find LLM-specific security issues at development time, just like Bandit does for general Python security.

## Quick Start

Install from source (a PyPI package is planned but not yet published):

```bash
pip install git+https://github.com/xr843/llm-seclint.git
```

Scan your project:

```bash
llm-seclint scan .
```

That's it. You'll see output like:

```text
src/app.py
  !! L12 [LS001] Hardcoded API key assigned to 'OPENAI_API_KEY'
  !  L41 [LS006] Dynamic input passed to eval()
  !! L55 [LS004] Dynamic output passed to subprocess.run() with shell=True

Found 3 issue(s): 2 critical, 1 high
Scanned in 0.03s
```

By default only **stable** (low false-positive) rules run. Add `--experimental`
to also enable the heuristic rules (LS002, LS003) — see [Rule stability](#rule-stability).

## How It Works

```text
Source Code → AST Parsing → 9 Security Rules → Findings Report
                              ├─ LS001: Hardcoded API Keys
                              ├─ LS002: Prompt Injection
                              ├─ LS003: SQL Injection via LLM
                              ├─ LS004: Shell Injection via LLM
                              ├─ LS005: Path Traversal via LLM
                              ├─ LS006: Insecure Deserialization
                              ├─ LS007: Template Injection (SSTI)
                              ├─ LS008: XXE XML Parsing
                              └─ LS010: Unpinned LLM Dependencies
```

llm-seclint parses your Python files into Abstract Syntax Trees and applies targeted security rules that understand LLM-specific data flows. No model access required, no runtime overhead -- just fast, deterministic analysis.

### Confirmed dataflow (taint analysis)

Beyond matching dangerous sinks, llm-seclint runs a lightweight **intra-procedural
taint engine** that tracks values returned by an LLM API call (`openai`/`litellm`/
Anthropic completions) as they flow through assignments, attribute/subscript
chains, and string building within a function. When such a value reaches a sink,
the finding is annotated **`confirmed LLM→sink dataflow`** and carries a
structured `taint_source` field — so you can tell a real LLM-output-to-`eval()`
flow from a merely-dynamic argument:

```python
resp = openai.chat.completions.create(model="gpt-4", messages=msgs)
code = resp.choices[0].message.content
eval(code)   # LS006 — confirmed LLM→sink dataflow
```

Today this confirmation drives **LS006** (`eval`/`exec`/`pickle`); it never
suppresses or downgrades an existing finding (a merely-dynamic argument is still
reported). Extending it to LS003/LS004 and to user-input sources — letting the
experimental rules graduate to stable — is on the [roadmap](#roadmap). Scope is
deliberately bounded: single-function, single-pass (no cross-function or
control-flow-graph precision yet).

## Where These Rules Come From

Every rule maps to a real insecure pattern I found while **manually auditing**
popular open-source LLM projects. Those audits are what motivated building
llm-seclint — to catch the same classes of issue automatically, before they
ship. Fixes were proposed upstream; several were declined in favor of the
maintainers' own approaches, but the underlying patterns are exactly what the
rules now detect.

| Project | Pattern found | Rule | Upstream PR |
|---------|---------------|------|-------------|
| [Dify](https://github.com/langgenius/dify) (100k★) | Unsafe `pickle.loads()` on database data | LS006 | found in audit |
| [Dify](https://github.com/langgenius/dify) (100k★) | `render_template_string()` SSTI in UNSAFE mode | LS007 | found in audit |
| [Dify](https://github.com/langgenius/dify) (100k★) | SQL f-string interpolation in VDB drivers | LS003 | found in audit |
| [LiteLLM](https://github.com/BerriAI/litellm) (20k★) | `exec()` in custom code guardrails | LS006 | [#24455](https://github.com/BerriAI/litellm/pull/24455) (closed) |
| [LiteLLM](https://github.com/BerriAI/litellm) (20k★) | Jinja2 SSTI in prompt managers | LS007 | [#24458](https://github.com/BerriAI/litellm/pull/24458) (closed) |
| [vllm](https://github.com/vllm-project/vllm) (45k★) | `eval()` on LLM output in example code | LS006 | [#37939](https://github.com/vllm-project/vllm/pull/37939) (closed) |
| [crewAI](https://github.com/crewAIInc/crewAI) (30k★) | XXE in XML parsing (use `defusedxml`) | LS008 | [#5005](https://github.com/crewAIInc/crewAI/pull/5005) (closed) |

## What It Detects

| Rule | Name | Severity | Stability | Description |
|------|------|----------|-----------|-------------|
| LS001 | `hardcoded-api-key` | CRITICAL | stable | Hardcoded API keys for LLM providers (OpenAI, Anthropic, xAI, etc.) |
| LS002 | `prompt-concat-injection` | HIGH | experimental | User input concatenated into LLM prompts via f-strings, `+`, or `.format()` |
| LS003 | `llm-to-sql-injection` | CRITICAL | experimental | LLM output interpolated into SQL queries |
| LS004 | `llm-to-shell-injection` | CRITICAL | stable | LLM output passed to `subprocess` / `os.system` |
| LS005 | `llm-to-path-traversal` | HIGH | stable | LLM output used as file paths |
| LS006 | `insecure-deserialization` | HIGH | stable | `eval` / `exec` / `pickle` / unsafe YAML on dynamic input |
| LS007 | `server-side-template-injection` | CRITICAL | stable | Dynamic content passed to template engine without sandboxing |
| LS008 | `xxe-xml-parsing` | HIGH | stable | XML parsing without protection against external entity attacks |
| LS010 | `unpinned-llm-dependency` | HIGH | stable | LLM dependency uses unpinned version constraint (e.g. `>=` without `<`), vulnerable to supply chain attacks |

### Rule stability

Rules are graded by how reliably they distinguish a real issue from noise:

- **stable** — sink-driven or pattern-unique (a hardcoded provider key, `eval()`
  on dynamic input, XXE-prone parsing). Low false-positive. **On by default.**
- **experimental** — relies on naming/keyword heuristics to *guess* whether data
  is LLM- or user-derived (LS002 keys off words like "you are"; LS003 flags any
  dynamic SQL f-string regardless of source, and overlaps Bandit's B608). Higher
  false-positive, so **off unless you pass `--experimental`**.

This keeps the default scan high-signal. Run `llm-seclint rules` to see each
rule's stability. A precise data-flow (taint) engine that would let LS002/LS003
graduate to stable is tracked on the [roadmap](#roadmap).

### Examples

#### LS001: Hardcoded API Key

```python
# Bad - detected by llm-seclint
openai.api_key = "sk-proj-abc123..."
client = Anthropic(api_key="sk-ant-api03-...")

# Good
openai.api_key = os.environ["OPENAI_API_KEY"]
client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
```

#### LS002: Prompt Injection

```python
# Bad - user input directly in prompt
prompt = f"You are a bot. User says: {user_input}"

# Good - separate message roles
messages = [
    {"role": "system", "content": "You are a bot."},
    {"role": "user", "content": user_input},
]
```

#### LS003: SQL Injection via LLM Output

```python
# Bad - LLM output in SQL
cursor.execute(f"SELECT * FROM users WHERE name = '{llm_response}'")

# Good - parameterized query
cursor.execute("SELECT * FROM users WHERE name = ?", (llm_response,))
```

#### LS004: Shell Injection via LLM Output

```python
# Bad - LLM output to shell
subprocess.run(llm_output, shell=True)

# Good - validate against allowlist
if command in ALLOWED_COMMANDS:
    subprocess.run([command], check=False)
```

#### LS005: Path Traversal via LLM Output

```python
# Bad - LLM output as file path
with open(llm_response) as f: ...

# Good - validate against base directory
path = (ALLOWED_BASE / filename).resolve()
assert str(path).startswith(str(ALLOWED_BASE))
```

#### LS006: Insecure Deserialization

```python
# Bad - eval on LLM response
data = eval(llm_response)

# Good - use safe parsing
data = json.loads(llm_response)
```

#### LS007: Server-Side Template Injection

```python
# Bad - user input in template string
render_template_string(f"<h1>Hello {user_input}</h1>")

# Good - pass variables through context
render_template_string("<h1>Hello {{ name }}</h1>", name=user_input)
```

#### LS008: XXE XML Parsing

```python
# Bad - parsing untrusted XML without protection
tree = etree.parse(user_uploaded_file)

# Good - use defusedxml
from defusedxml.lxml import parse
tree = parse(user_uploaded_file)
```

#### LS010: Unpinned LLM Dependency

```text
# Bad - open-ended constraint allows malicious future releases (requirements.txt)
litellm>=1.64.0
dspy>=2.0
openai>=1.0

# Good - pinned to exact version
litellm==1.82.2

# Good - upper bound prevents auto-upgrade to compromised versions
litellm>=1.64.0,<1.83
```

This rule was motivated by the [litellm supply chain attack](https://blog.pypi.org/posts/2025-01-14-litellm-typosquat/) where `dspy` used `litellm>=1.64.0` and a compromised release was automatically pulled in. It scans `requirements.txt`, `pyproject.toml`, and `setup.cfg` for LLM packages with open-ended `>=` constraints.

## Framework Support

llm-seclint understands patterns from popular LLM frameworks:

- **LangChain** -- `PromptTemplate`, `ChatPromptTemplate.from_messages()`, `HumanMessagePromptTemplate`
- **LiteLLM** -- `litellm.completion()`, `litellm.acompletion()`
- **OpenAI SDK** -- `openai.ChatCompletion.create()`, `client.chat.completions.create()`
- **Anthropic SDK** -- `anthropic.Anthropic().messages.create()`
- **Flask/Jinja2** -- `render_template_string()`, `jinja2.Template()`

## OWASP LLM Top 10 Mapping

| OWASP LLM Top 10 | llm-seclint Rules |
|---|---|
| LLM01: Prompt Injection | LS002 |
| LLM02: Insecure Output Handling | LS003, LS004, LS005, LS006, LS007 |
| LLM06: Sensitive Information Disclosure | LS001 |
| A05:2021: Security Misconfiguration | LS008 (CWE-611) |

## Comparison

| Feature | llm-seclint | garak | LLM Guard | Guardrails |
|---------|:-----------:|:-----:|:---------:|:----------:|
| Analysis type | Static (AST) | Dynamic (probing) | Runtime (filter) | Runtime (guard) |
| Requires running model | No | Yes | Yes | Yes |
| CI/CD integration | Native | Manual | Manual | Manual |
| SARIF output | Yes | No | No | No |
| `# nosec` inline suppression | Yes | N/A | N/A | N/A |
| Pre-commit hook | Yes | No | No | No |
| Finds hardcoded keys | Yes | No | No | No |
| Finds prompt injection patterns | Yes | Tests for | Filters | Filters |
| Finds output handling flaws | Yes | No | No | No |
| Language | Python | Python | Python | Python |

## CLI Usage

```bash
# Scan current directory
llm-seclint scan .

# Scan specific files
llm-seclint scan src/ --include "*.py"

# JSON output
llm-seclint scan . --format json -o results.json

# SARIF output (for GitHub Code Scanning)
llm-seclint scan . --format sarif -o results.sarif

# Ignore specific rules
llm-seclint scan . --ignore LS001,LS002

# Set minimum severity
llm-seclint scan . --min-severity HIGH

# List all rules
llm-seclint rules

# Show version
llm-seclint --version
```

## Profiles

llm-seclint ships with two scan profiles:

- `--profile app` (default) — Full scan for LLM-powered applications
- `--profile engine` — Tuned for LLM inference engines (vllm, TGI, etc.).
  Disables LS002 (prompt injection) since processing prompts is the engine's job.

### Experimental rules

By default only [stable](#rule-stability) rules run. Add `--experimental` to also
enable the heuristic rules (LS002, LS003), or set `include_experimental: true` in
your config file:

```bash
llm-seclint scan . --experimental
```

### Inline Suppression

Suppress specific findings with `# nosec` comments:

```python
api_key = "sk-test-key-for-ci"  # nosec LS001
```

## GitHub Code Scanning Integration

llm-seclint supports [SARIF](https://sarifweb.azurewebsites.net/) output for direct integration with GitHub Code Scanning. Add this to your GitHub Actions workflow:

```yaml
- name: Run llm-seclint
  run: llm-seclint scan . --format sarif -o results.sarif

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Pre-commit Hook

Add llm-seclint to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/xr843/llm-seclint
    rev: v0.1.0
    hooks:
      - id: llm-seclint
```

## Configuration

Create a `.llm-seclint.yml` in your project root:

```yaml
# Patterns for files to include
include_patterns:
  - "*.py"

# Patterns for files to exclude
exclude_patterns:
  - "test_*.py"
  - "*_test.py"

# Rules to ignore
ignore_rules:
  - LS005

# Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW, INFO)
min_severity: MEDIUM

# Also run experimental (heuristic, higher false-positive) rules
include_experimental: false
```

## Installation for Development

```bash
git clone https://github.com/xr843/llm-seclint.git
cd llm-seclint
pip install -e ".[dev]"
pytest
```

## Contributing

Contributions are welcome! Here's how to add a new rule:

1. Create a new file in `src/llm_seclint/rules/python/`
2. Subclass `Rule` and implement the `check()` method
3. Register the rule in `src/llm_seclint/rules/registry.py`
4. Add tests in `tests/rules/`
5. Update this README

Please open an issue first to discuss significant changes.

## Roadmap

- **v0.2**: Intra-procedural taint tracking (real LLM/user → sink data-flow) so
  the [experimental](#rule-stability) rules (LS002/LS003) can graduate to stable
  with far fewer false positives
- **v0.3**: JavaScript/TypeScript analyzer (LangChain.js, Vercel AI SDK)
- **v0.4**: Framework-specific rules (LangChain, LlamaIndex, Semantic Kernel)
- **v0.5**: Auto-fix suggestions with `--fix` flag
- **v1.0**: Stable API, VS Code extension

## License

MIT
