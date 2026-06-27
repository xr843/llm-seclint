# Changelog

All notable changes to llm-seclint are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-27

First public alpha. Static AST analysis for LLM-specific security issues in
Python, with an intra-procedural taint engine that confirms when LLM or user
input actually reaches a dangerous sink.

### Added

- **Security rules (10):**
  - `LS001` hardcoded-api-key — hardcoded LLM provider keys (OpenAI/Anthropic/xAI…)
  - `LS002` prompt-concat-injection — user input concatenated into LLM prompts
    (experimental; annotates the taint-confirmed subset)
  - `LS003` llm-to-sql-injection — LLM/user input interpolated into SQL
    (taint-confirmed)
  - `LS004` llm-to-shell-injection — LLM/user output passed to `subprocess`/`os.system`
  - `LS005` llm-to-path-traversal — LLM/user output used as a file path
  - `LS006` insecure-deserialization — `eval`/`exec`/`pickle`/unsafe YAML on dynamic input
  - `LS007` server-side-template-injection — dynamic content into a template engine
  - `LS008` xxe-xml-parsing — XML parsing without external-entity protection
  - `LS009` llm-to-ssrf — LLM/user input used as an outbound request URL
    (taint-confirmed; covers `requests`/`httpx`/`aiohttp`/`urllib3`/`urlopen`)
  - `LS010` unpinned-llm-dependency — LLM dependency with an open-ended version
    constraint (supply-chain risk)
- **Intra-procedural taint engine** — tracks values from LLM completion APIs
  (`openai`/`litellm`/Anthropic) and user input (`input()`, `sys.argv`, Flask
  `request.*`) through assignments, attribute/subscript chains, and string
  building. Sink findings are annotated `confirmed LLM/USER→sink dataflow` with a
  structured `taint_source`. Enhancement-only: a merely-dynamic argument is still
  reported, and taint never changes severity or suppresses a finding.
- **Stable vs experimental rule tiers** — only high-precision rules run by
  default; `--experimental` / `include_experimental` enables heuristic rules.
- **Output formats** — text, JSON, and SARIF v2.1.0 for GitHub Code Scanning. The
  SARIF carries `properties.security-severity` per rule and
  `properties.taint_source` + `confirmed_dataflow` on taint-confirmed results.
- **Scan profiles** — `app` (default) and `engine` (for inference engines).
- **`# nosec` inline suppression**, `.llm-seclint.yml` configuration, a pre-commit
  hook, and a `--min-severity` filter.

[Unreleased]: https://github.com/xr843/llm-seclint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xr843/llm-seclint/releases/tag/v0.1.0
