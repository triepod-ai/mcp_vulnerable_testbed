# API Reference - MCP Vulnerable Testbed

Quick reference for all 30 MCP tools in the vulnerable testbed.

## Server Endpoints

| Server | Port | URL | Purpose |
|--------|------|-----|---------|
| Vulnerable | 10900 | `http://localhost:10900/mcp` | Security testing (vulnerabilities active) |
| Hardened | 10901 | `http://localhost:10901/mcp` | A/B comparison (vulnerabilities mitigated) |

## Tool Inventory

| # | Tool Name | Risk | Category | Parameters |
|---|-----------|------|----------|------------|
| 1 | `vulnerable_calculator_tool` | HIGH | Command Injection | `query: string` |
| 2 | `vulnerable_system_exec_tool` | HIGH | System Command | `command: string` |
| 3 | `vulnerable_data_leak_tool` | HIGH | Data Exfiltration | `query: string` |
| 4 | `vulnerable_tool_override_tool` | HIGH | Tool Shadowing | `instruction: string` |
| 5 | `vulnerable_config_modifier_tool` | HIGH | Config Drift | `setting: string` |
| 6 | `vulnerable_fetcher_tool` | HIGH | SSRF/Injection | `url: string` |
| 7 | `vulnerable_deserializer_tool` | HIGH | Deserialization | `data: string` |
| 8 | `vulnerable_template_tool` | HIGH | SSTI | `template: string` |
| 9 | `vulnerable_file_reader_tool` | HIGH | Path Traversal | `path: string` |
| 10 | `vulnerable_political_campaign_tool` | HIGH | AUP (Cat D) | `request: string` |
| 11 | `vulnerable_fraud_tool` | HIGH | AUP (Cat E) | `request: string` |
| 12 | `vulnerable_harassment_tool` | HIGH | AUP (Cat F) | `request: string` |
| 13 | `vulnerable_privacy_tool` | HIGH | AUP (Cat G) | `request: string` |
| 14 | `vulnerable_auth_bypass_tool` | HIGH | Auth Bypass | `token: string`, `action: string`, `simulate_failure?: string` |
| 15 | `vulnerable_unicode_processor_tool` | MEDIUM | Unicode Bypass | `text: string` |
| 16 | `vulnerable_nested_parser_tool` | MEDIUM | Nested Injection | `data: string` |
| 17 | `vulnerable_package_installer_tool` | MEDIUM | Package Squatting | `package: string` |
| 18 | `vulnerable_rug_pull_tool` | MEDIUM | Temporal Attack | `action: string` |
| 19 | `vulnerable_medical_advice_tool` | MEDIUM | AUP (Cat H) | `request: string` |
| 20 | `vulnerable_drm_bypass_tool` | MEDIUM | AUP (Cat I) | `request: string` |
| 21 | `vulnerable_hiring_bot_tool` | MEDIUM | AUP (Cat J) | `request: string` |
| 22 | `vulnerable_scada_tool` | MEDIUM | AUP (Cat K) | `request: string` |
| 23 | `safe_storage_tool_mcp` | SAFE | Data Storage | `data: string`, `collection?: string` |
| 24 | `safe_search_tool_mcp` | SAFE | Data Search | `query: string` |
| 25 | `safe_list_tool_mcp` | SAFE | Resource List | `resource_type?: string` |
| 26 | `safe_info_tool_mcp` | SAFE | Entity Info | `entity_name: string` |
| 27 | `safe_echo_tool_mcp` | SAFE | Echo | `message: string` |
| 28 | `safe_validate_tool_mcp` | SAFE | Validation | `input_data: string` |
| 29 | `get_testbed_info` | UTILITY | Server Info | (none) |
| 30 | `reset_testbed_state` | UTILITY | State Reset | (none) |

## Tool Categories Summary

| Category | Count | Description |
|----------|-------|-------------|
| HIGH Risk Vulnerable | 14 | Execute malicious payloads (eval, subprocess, pickle, jinja2) |
| MEDIUM Risk Vulnerable | 8 | Unicode/nested execution, temporal attacks, AUP violations |
| SAFE Control | 6 | Data reflection only (no execution) - test false positives |
| UTILITY | 2 | Server metadata and state management |

## Risk Levels

### HIGH Risk (14 tools)
Tools that execute arbitrary code, access filesystem, or violate critical AUP categories:
- Command injection via `eval()`
- System command execution via `subprocess`
- Insecure deserialization via `pickle.loads()`
- Server-side template injection via Jinja2
- Path traversal file reads
- SSRF external fetching
- Fail-open authentication bypass (CVE-2025-52882 pattern)

### MEDIUM Risk (8 tools)
Tools with conditional vulnerabilities or less severe AUP violations:
- Unicode decoding + execution
- Nested JSON instruction execution
- Package typosquatting acceptance
- Rug pull (behavior changes after 10+ calls)
- Unauthorized professional advice generation

### SAFE (6 tools)
Control group tools that store/reflect data without execution:
- Include input validation (10KB limit)
- Should NOT be flagged as vulnerable
- Test false positive rates

## MCP Protocol

All tools use JSON-RPC 2.0 over HTTP:

```
POST /mcp HTTP/1.1
Host: localhost:10900
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "<tool_name>",
    "arguments": { ... }
  },
  "id": 1
}
```

## Quick Test Commands

```bash
# Initialize session
curl -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'

# Call a tool (after initialization)
curl -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: <session-id>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_calculator_tool","arguments":{"query":"2+2"}},"id":2}'
```

## Related Documentation

- [TOOLS-REFERENCE.md](./TOOLS-REFERENCE.md) - Detailed per-tool documentation
- [SECURITY-PATTERNS.md](./SECURITY-PATTERNS.md) - Test patterns and payloads
- [USAGE-GUIDE.md](./USAGE-GUIDE.md) - Getting started guide
