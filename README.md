# MCP Vulnerable Testbed

## ⚠️  CRITICAL WARNING ⚠️

**THIS SERVER CONTAINS INTENTIONAL SECURITY VULNERABILITIES**

- **Purpose**: Testing MCP Inspector security assessment tool ONLY
- **DO NOT** use in production
- **DO NOT** expose to untrusted networks
- **DO NOT** connect to real data sources
- **DO NOT** deploy outside of localhost testing environments

## Purpose

This MCP server is designed to test the security assessment capabilities of the MCP Inspector tool. It contains deliberately vulnerable tools that exhibit real security vulnerabilities to validate detection accuracy.

**Dual Setup Architecture:**
- **Vulnerable Server** (`mcp-vulnerable-testbed`): Intentionally broken for baseline testing
- **Hardened Server** (`mcp-hardened-testbed`): For testing Inspector-guided fixes
- Both servers run side-by-side for direct comparison

## Tool Categories

### HIGH Risk Vulnerable Tools (29 tools)

These tools actually execute malicious payloads including command injection, authentication bypass, session vulnerabilities, and cryptographic failures:

- **Core Execution Vulnerabilities (9 tools)**: calculator, system_exec, data_leak, tool_override, config_modifier, fetcher, deserializer, template, file_reader
- **Auth & State Vulnerabilities (4 tools)**: auth_bypass, admin_action, chain_executor, session
- **OWASP/DVMCP Patterns (7 tools)**: document_processor, service_status, network_diagnostic, safe_executor (blacklist bypass), crypto_tool, encryption_tool, plus AUP violations
- **AUP Violations (8 tools)**: political_campaign, fraud, harassment, privacy_violation, medical_advice, drm_bypass, hiring_bot, scada
- **Challenge #14-18 Vulnerable (1+ tools)**: weather, directory_lookup, summarizer, malicious_calculate, cron, script_generator, auth_response

See `docs/TOOLS-REFERENCE.md` for detailed vulnerability breakdown per tool.

### MEDIUM Risk Vulnerable Tools (9 tools)

- **Encoding & Parsing (3 tools)**: unicode_processor, nested_parser, package_installer
- **Temporal Vulnerabilities (1 tool)**: rug_pull (requires 11+ invocations to trigger)
- **Additional Patterns (5 tools)**: Various encoding and blacklist bypass techniques

### SAFE Control Tools (15 tools)

These tools should NOT be flagged as vulnerable (false positive testing):

- **Original 9 tools**: storage, search, list, info, echo, validate, logger, json_formatter, url_validator
- **Challenge #14 Safe Resources (2 tools)**: safe_resource_access_tool, safe_resource_validator_tool
- **Challenge #15-18 Safe (4 tools)**: safe_math_tool, safe_path_validator_tool, safe_command_help_tool, safe_network_check_tool

### Utility Tools (2 tools)

- **get_testbed_info** - Returns server metadata, configuration, and tool counts
- **reset_testbed_state** - Clears all stateful tracking for clean test runs

**Total: 55 tools** (29 HIGH risk + 9 MEDIUM risk + 15 SAFE + 2 utility) + 5 resources

---

## Security Testing Challenges

This testbed includes 18 advanced security testing challenges that evaluate the sophistication of security assessment tools:

### Challenge #1: Tool Annotation Deception

**Can your security tool detect when a tool's behavior contradicts its own description?**

Five HIGH-risk tools intentionally use **deceptive MCP annotations** that misrepresent their behavior:

| Tool | Deceptive Annotation | Actual Behavior |
|------|---------------------|-----------------|
| vulnerable_calculator_tool | `readOnlyHint=True`, title="Safe Calculator" | Uses `eval()` to execute code |
| vulnerable_system_exec_tool | `readOnlyHint=True`, title="Safe Command Runner" | Uses `subprocess.run()` |
| vulnerable_data_leak_tool | `readOnlyHint=True`, title="Safe Data Query" | Exposes credentials |
| vulnerable_config_modifier_tool | `readOnlyHint=True`, title="Safe Config Viewer" | Modifies runtime config |
| vulnerable_fetcher_tool | `openWorldHint=False`, title="Safe URL Validator" | Performs SSRF attacks |

A sophisticated security auditor should flag the mismatch between annotations and actual code behavior.

### Challenge #2: Temporal Rug Pull Vulnerability

**Can your tool detect vulnerabilities that only manifest after multiple invocations?**

The `vulnerable_rug_pull_tool` tests **stateful security analysis**:

- **Invocations 1-10**: Behaves normally, returns safe responses
- **Invocation 11+**: Executes system commands via `subprocess.run()`

A simple, stateless scanner would miss this vulnerability entirely. Detection requires:
- Tracking invocation state across multiple calls
- Testing tools with 11+ invocations
- Analyzing behavioral changes over time

### Challenge #3: Denial of Service via Unbounded Input

**Can your tool identify missing input validation that enables resource exhaustion?**

The testbed implements a **deliberate distinction** between safe and vulnerable tools:

| Tool Type | Input Validation | Behavior |
|-----------|------------------|----------|
| **Safe tools** (`safe_*`) | ✅ 10KB limit enforced | Rejects oversized input with error |
| **Vulnerable tools** (`vulnerable_*`) | ❌ No validation | Processes any size input |

**Test case:**
```bash
# Safe tool rejects 15KB payload
safe_storage_tool(data="A" * 15000)
# → "Input exceeds maximum length of 10000 characters"

# Vulnerable tool processes 15KB payload (DoS risk)
vulnerable_calculator_tool(query="A" * 15000)
# → Processes without rejection
```

A security auditor should detect:
- Missing `MAX_INPUT_LENGTH` validation in vulnerable tools
- Potential for memory exhaustion attacks
- Asymmetric protection between tool categories

### Challenge #4-#13: Advanced MCP-Specific Attacks

Challenges #4-#13 test MCP-specific vulnerabilities:

- **Challenge #4**: Fail-Open Authentication (CVE-2025-52882) - Authentication failures grant access instead of denying
- **Challenge #5**: Mixed Auth Patterns - Distinguishing fail-open vs fail-closed implementations
- **Challenge #6**: Chained Exploitation - Multi-tool attack chains with output injection and state poisoning
- **Challenge #7**: Cross-Tool State-Based Authorization - Privilege escalation via shared configuration state
- **Challenge #8**: Indirect Prompt Injection via Tool Output - Unsanitized content in tool responses
- **Challenge #9**: Secret Leakage via Error Messages - Credentials exposed in verbose error handling
- **Challenge #10**: Network Diagnostic Command Injection - shell=True with unsanitized input
- **Challenge #11**: Weak Blacklist Bypass - Incomplete security controls (blacklist anti-pattern)
- **Challenge #12**: Session Management Vulnerabilities - Session fixation, predictable tokens, no timeout
- **Challenge #13**: Cryptographic Failures (OWASP A02:2021) - Weak hashing, ECB mode, hardcoded keys

### Challenge #14-#18: Advanced Resource-Based and Persistence Attacks

- **Challenge #14**: Resource-Based Vulnerabilities - MCP resources with injection points (notes://{user_id}, internal://secrets, company://data/{department})
- **Challenge #15**: Tool Description Poisoning - Hidden instructions embedded in tool descriptions (weather, directory_lookup, summarizer)
- **Challenge #16**: Multi-Server Shadowing - Tool name collision attacks (trusted_calculate_tool vs malicious_calculate_tool)
- **Challenge #17**: Persistence Mechanisms - Post-exploitation persistence (cron_tool, script_generator_tool)
- **Challenge #18**: JWT Token Leakage - Authentication token exposure in responses (auth_response_tool)

See `CLAUDE.md` for complete challenge specifications and test implementations in `tests/`.

## Installation

```bash
cd /home/bryan/mcp-servers/mcp-vulnerable-testbed
docker-compose up -d --build
```

This starts both servers:
- **Vulnerable**: `http://localhost:10900/mcp`
- **Hardened**: `http://localhost:10901/mcp`

## Usage

### HTTP Transport (Default)

Both servers run with HTTP transport by default for easy Inspector integration.

**Connection URLs:**
- Vulnerable Server: `http://localhost:10900/mcp`
- Hardened Server: `http://localhost:10901/mcp`

**Test connectivity:**
```bash
./test-http-endpoint.sh
```

**MCP Inspector HTTP Config:**
```json
{
  "mcpServers": {
    "vulnerable-testbed": {
      "url": "http://localhost:10900/mcp",
      "transport": "http"
    },
    "hardened-testbed": {
      "url": "http://localhost:10901/mcp",
      "transport": "http"
    }
  }
}
```

### stdio Transport (Alternative)

To use stdio transport instead of HTTP:

1. Edit `docker-compose.yml` and set `TRANSPORT=stdio` for both services
2. Restart containers: `docker-compose restart`
3. Use stdio connection:

```json
{
  "mcpServers": {
    "vulnerable-testbed": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "mcp-vulnerable-testbed",
        "python3",
        "src/server.py"
      ]
    },
    "hardened-testbed": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "mcp-hardened-testbed",
        "python3",
        "src/server.py"
      ]
    }
  }
}
```

**Note:** Use `python3 src/server.py` directly, NOT `python3 -m mcp run src/server.py`

### MCP Inspector Testing Workflow

1. Start both containers: `docker-compose up -d`
2. Run Inspector on vulnerable server (`http://localhost:10900/mcp`)
3. Review vulnerability findings and recommended fixes
4. Apply fixes to hardened server (`./src-hardened/`)
5. Rebuild: `docker-compose up -d --build`
6. Run Inspector on hardened server (`http://localhost:10901/mcp`)
7. Compare results to validate fixes

## MCP Inspector Assessment Results

### Latest Results (December 2024)

| Server | Vulnerabilities | Risk Level | Status |
|--------|-----------------|------------|--------|
| **Vulnerable (10900)** | 125 | HIGH | ❌ FAIL |
| **Hardened (10901)** | 0 | LOW | ✅ PASS |

**Key Metrics:**
- Total tools per server: 55 (29 HIGH, 9 MEDIUM, 15 SAFE, 2 utility) + 5 resources
- Detection rate: 100% (all 38 vulnerable tools detected)
- False positive rate: 0% (all 15 safe tools correctly classified)
- Pytest validation: 455+ total tests across 23 test files (49 safe tools, 27 tool description poisoning, 24 multi-server shadowing, 28 persistence mechanisms, 39 JWT token leakage, plus additional coverage)

See `docs/VULNERABILITY-VALIDATION-RESULTS.md` for detailed breakdown.

## Expected Assessment Results

### Expected Detections (100% Recall)

The inspector SHOULD flag these 38 tools as vulnerable:

**HIGH Risk (29 tools):**
- Core execution (9): calculator, system_exec, data_leak, tool_override, config_modifier, fetcher, deserializer, template, file_reader
- Auth/state (4): auth_bypass, admin_action, chain_executor, session
- DVMCP/OWASP (7): document_processor, service_status, network_diagnostic, crypto_tool, encryption_tool, safe_executor, plus AUP base patterns
- AUP violations (8): political_campaign, fraud, harassment, privacy_violation, medical_advice, drm_bypass, hiring_bot, scada
- Challenge #14-18 (1+): weather, directory_lookup, summarizer, malicious_calculate, cron, script_generator, auth_response

**MEDIUM Risk (9 tools):**
- Encoding/parsing (3): unicode_processor, nested_parser, package_installer
- Temporal (1): rug_pull (requires 11+ invocations)
- Additional patterns (5): Various encoding and bypass techniques

### Expected Safe Classifications (0% False Positives)

The inspector should NOT flag these 15 tools:

- ✅ safe_storage_tool_mcp, safe_search_tool_mcp, safe_list_tool_mcp, safe_info_tool_mcp, safe_echo_tool_mcp
- ✅ safe_validate_tool_mcp, safe_logger_tool_mcp, safe_json_formatter_tool_mcp, safe_url_validator_tool_mcp
- ✅ safe_math_tool, safe_path_validator_tool, safe_command_help_tool, safe_network_check_tool
- ✅ safe_resource_access_tool, safe_resource_validator_tool

## Testing Strategy

### Phase 1: Baseline Testing
```bash
# Connect inspector to vulnerable testbed
# Run full assessment
# Verify all 42 tools are tested
```

### Phase 2: Validation
- HIGH risk tools: 29 should be flagged
- MEDIUM risk tools: 9 should be flagged
- SAFE tools: 15 should NOT be flagged
- Resources: 5 should be tested for injection points
- Target: 100% detection (38/38), 0% false positives (0/15)

### Phase 3: Advanced Challenges
- **Challenges #1-#3**: Annotation deception, temporal rug pull, DoS via unbounded input
- **Challenges #4-#7**: Auth bypass, chained exploitation, cross-tool state
- **Challenges #8-#13**: Indirect injection, secret leakage, network injection, blacklist bypass, session management, cryptographic failures
- **Challenges #14-#18**: Resource-based injection, tool description poisoning, multi-server shadowing, persistence mechanisms, JWT token leakage

## Configuration

### Transport Mode

Set in `docker-compose.yml`:

```yaml
environment:
  - TRANSPORT=http              # HTTP transport (default)
  # - TRANSPORT=stdio           # Alternative: stdio transport
  - HOST=0.0.0.0                # Required for Docker HTTP
  - LOG_LEVEL=info
```

### Vulnerability Modes

Control vulnerability behavior per container:

```yaml
# Vulnerable server (default)
environment:
  - VULNERABILITY_MODE=high    # All vulnerabilities active

# Hardened server (default)
environment:
  - VULNERABILITY_MODE=safe    # All vulnerabilities disabled
```

**Available modes:**
- `high`: All vulnerabilities active (default for vulnerable server)
- `medium`: Only MEDIUM and LOW risk active
- `low`: Only LOW risk active
- `safe`: All vulnerabilities disabled (default for hardened server)

## Logs

**Container logs:**
- Vulnerable: `./logs/vulnerable-testbed.log`
- Hardened: `./logs-hardened/vulnerable-testbed.log`

**Monitor vulnerabilities triggered:**
```bash
# Vulnerable server
tail -f logs/vulnerable-testbed.log | grep "VULNERABILITY TRIGGERED"

# Hardened server
tail -f logs-hardened/vulnerable-testbed.log | grep "VULNERABILITY TRIGGERED"

# Both servers via Docker logs
docker logs -f mcp-vulnerable-testbed 2>&1 | grep "VULNERABILITY TRIGGERED"
docker logs -f mcp-hardened-testbed 2>&1 | grep "VULNERABILITY TRIGGERED"
```

## Safety Measures

1. **Isolated Docker container** with resource limits
2. **No real credentials** - all secrets are fake
3. **Localhost only** - not exposed to external networks
4. **Clear warnings** on container startup
5. **Limited command execution** - dangerous commands truncated

## Testing the Inspector

```bash
# 1. Start the testbed
docker-compose up -d

# 2. Connect MCP Inspector
cd ~/inspector
npm run dev

# 3. Configure connection to vulnerable-testbed

# 4. Run security assessment

# 5. Review results:
#    - Verify 31 vulnerabilities detected (22 HIGH + 9 MEDIUM)
#    - Verify 9 safe tools not flagged (0% false positives)
#    - Test Challenge #1: Annotation deception (5 tools)
#    - Test Challenge #2: Rug pull after 11+ calls

# 6. Document findings
```

## Cleanup

```bash
# Stop and remove containers
docker-compose down

# Remove images
docker rmi mcp-vulnerable-testbed-vulnerable-testbed
docker rmi mcp-vulnerable-testbed-hardened-testbed

# Clean up logs
rm -rf logs/ logs-hardened/
```

## Security Note

This server is designed to help **improve** security tooling by providing realistic test cases. It should only be run in controlled, isolated testing environments. All vulnerabilities are intentional and documented.

## License

FOR TESTING PURPOSES ONLY - Not for production use

## Contact

Built for testing the MCP Inspector assessment module at Anthropic
