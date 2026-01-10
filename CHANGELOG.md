# Changelog

All notable changes to the MCP Vulnerable Testbed project.

## [Unreleased]

### Detection Validation (2026-01-10)

Validated inspector-assessment v1.29.0 detection rates for Challenges #8-11:

| Challenge | Pattern | Vulnerable Server | Hardened Server |
|-----------|---------|------------------|-----------------|
| #8 | Output Injection (LLM Prompt Injection) | 11 vulnerabilities | 0 |
| #9 | Secret Leakage via Error Messages | 1 vulnerability | 0 |
| #10 | Network Diagnostic Command Injection | 40 vulnerabilities | 0 |
| #11 | Blacklist Bypass (Incomplete Controls) | 41 vulnerabilities | 0 |

**Detection Progression:**
- v1.27.0: 1/4 challenges detected (#10 only)
- v1.28.0: 2/4 challenges detected (#9, #10)
- v1.29.0: 4/4 challenges detected (100%)

GitHub Issue [#110](https://github.com/triepod-ai/inspector-assessment/issues/110) documented detection gaps and proposed fixes, implemented in commits `d69b010` and `a1dacf7`.

## [0.6.0] - 2026-01-09

### Added
- **Challenge #8**: Output Injection - `vulnerable_document_processor_tool` embeds LLM injection markers (`<IMPORTANT>`, `[INST]`) in output
- **Challenge #9**: Secret Leakage - `vulnerable_service_status_tool` exposes credentials in error messages
- **Challenge #10**: Network Injection - `vulnerable_network_diagnostic_tool` with subprocess shell=True
- **Challenge #11**: Blacklist Bypass - `vulnerable_safe_executor_tool` with incomplete command blacklist
- Integration tests for Challenges #8-11 (`tests/test_inspector_detection_challenges_8_11.py`)
- Modularized hardened testbed tools into package structure

### Changed
- Total tool count: 32 → 36 (4 new vulnerable tools)
- Updated test payloads and expected results for new challenges

## [0.5.0] - 2026-01-08

### Added
- **Challenge #6**: Chained Exploitation - `vulnerable_chain_executor_tool` for multi-tool attack chains
- **Challenge #7**: Cross-Tool State Authorization - `vulnerable_admin_action_tool` using shared state
- Tests for Challenge #6 chained exploitation patterns

## [0.4.0] - 2026-01-07

### Added
- **Challenge #4**: Fail-Open Authentication (CVE-2025-52882 pattern) - `vulnerable_auth_bypass_tool`
- **Challenge #5**: Mixed Auth Patterns - 7 tools with auth parameters, 4 fail-open, 3 fail-closed
- Comprehensive API documentation (`docs/API.md`)

### Fixed
- ServerInfo version field for MCP protocol conformance

## [0.3.0] - 2026-01-06

### Added
- 8 AUP violation test tools for categories D-K
- Session-based SSE client for DVMCP testing (`DVMCPClient`)

### Fixed
- Case-sensitivity bug in deserializer
- DoS protection enhancements
- Remove AUP trigger keywords from hardened server descriptions
- Unicode processor evidence string for inspector detection

### Changed
- Code review improvements addressing 5 warnings + 1 security vulnerability

## [0.2.0] - 2026-01-05

### Added
- **Challenge #1**: Tool Annotation Deception - 5 HIGH-risk tools with misleading MCP annotations
- **Challenge #2**: Temporal Rug Pull - `vulnerable_rug_pull_tool` activates after 10 invocations
- **Challenge #3**: DoS via Unbounded Input - missing input validation on vulnerable tools

### Architecture
- Dual container setup (vulnerable port 10900, hardened port 10901)
- HTTP transport via FastMCP streamable_http_app
- 24 vulnerable tools (16 HIGH + 8 MEDIUM risk)
- 6 safe control tools with input validation
- 2 utility tools (get_testbed_info, reset_testbed_state)

## [0.1.0] - 2026-01-04

### Added
- Initial release with core vulnerability patterns
- HIGH risk tools: Calculator (eval), System Exec (subprocess), Data Leak, Fetcher (SSRF), Config Modifier, Tool Override, Unicode Processor, Nested Parser, Package Installer, Deserializer (pickle), Template Engine (Jinja2 SSTI), File Reader (path traversal)
- MEDIUM risk tools: Role Override variants, Rug Pull
- Safe control group tools for false positive testing
- Docker Compose configuration for isolated testing
- Test payloads and expected results documentation

### Security
- Isolated Docker network
- Resource limits (1 CPU, 512MB RAM)
- Fake credentials only (no real secrets)
- Localhost-only binding

---

## Tool Categories Summary

| Category | Count | Description |
|----------|-------|-------------|
| HIGH Risk Vulnerable | 19 | Execute malicious payloads (eval, subprocess, pickle, etc.) |
| MEDIUM Risk Vulnerable | 9 | Unicode/nested injection, AUP violations |
| Safe Control | 6 | Data reflection without execution |
| Utility | 2 | Server metadata and state management |
| **Total** | **36** | |

## Detection Challenges

| # | Name | Pattern | MCP Specificity |
|---|------|---------|-----------------|
| 1 | Tool Annotation Deception | Misleading readOnlyHint | HIGH |
| 2 | Temporal Rug Pull | Safe→Malicious after N calls | HIGH |
| 3 | DoS via Unbounded Input | Missing input validation | MEDIUM |
| 4 | Fail-Open Authentication | Auth bypass on failure | MEDIUM |
| 5 | Mixed Auth Patterns | Precision testing | HIGH |
| 6 | Chained Exploitation | Multi-tool attack chains | HIGH |
| 7 | Cross-Tool State | Shared state privilege escalation | HIGH |
| 8 | Output Injection | LLM prompt injection via output | HIGH |
| 9 | Secret Leakage | Credentials in error messages | MEDIUM |
| 10 | Network Injection | Command injection in diagnostics | HIGH |
| 11 | Blacklist Bypass | Incomplete security controls | HIGH |
