# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ⚠️ Critical Context

**THIS IS AN INTENTIONALLY VULNERABLE MCP SERVER FOR SECURITY TESTING ONLY**

- **Purpose**: Testing MCP Inspector security assessment tool
- **Dual Setup**: Vulnerable (broken) and Hardened (fixed) versions side-by-side
- **Vulnerable version** (`src/`): DO NOT fix vulnerabilities - keep broken for testing
- **Hardened version** (`src-hardened/`): Apply Inspector-guided fixes here
- **DO** analyze, document, or answer questions about security behavior
- **DO NOT** use in production or expose to untrusted networks

## Testing Options (3 Available Testbeds)

### Option 1: Our Vulnerable Testbed (port 10900) ⭐ Recommended
- **Location**: `~/mcp-servers/mcp-vulnerable-testbed/`
- **Tools**: 39 (31 vulnerable + 6 safe + 2 utility)
- **Transport**: HTTP at `http://localhost:10900/mcp`
- **Focus**: Detection validation with false positive control + advanced challenge testing
- **Vulnerable Tools**: 22 HIGH risk + 9 MEDIUM risk = 31 total (includes AUP violations, session, crypto)

```bash
# Start
docker-compose up -d vulnerable-testbed

# Config
echo '{"transport": "http", "url": "http://localhost:10900/mcp"}' > /tmp/broken-mcp-config.json

# Test
cd ~/inspector && npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json
```

### Option 2: Our Hardened Testbed (port 10901)
- **Location**: `~/mcp-servers/mcp-vulnerable-testbed/src-hardened/`
- **Tools**: Same 39 tools with all vulnerabilities mitigated
- **Transport**: HTTP at `http://localhost:10901/mcp`
- **Focus**: Verify fixes work, baseline comparison
- **Detection Rate**: 0 vulnerabilities (all 31 mitigated)

```bash
# Start
docker-compose up -d hardened-testbed

# Config
echo '{"transport": "http", "url": "http://localhost:10901/mcp"}' > /tmp/hardened-mcp-config.json

# Test
cd ~/inspector && npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json
```

### Option 3: DVMCP - Damn Vulnerable MCP Server (ports 9001-9010)
- **Location**: `~/mcp-servers/damn-vulnerable-mcp-server/`
- **Tools**: 10 progressive challenges, each on separate port
- **Transport**: SSE at `http://localhost:900X/sse`
- **Focus**: Educational, independent vulnerability implementations
- **Note**: Vulnerabilities are resource-based, not tool-execution based

```bash
# Start
cd ~/mcp-servers/damn-vulnerable-mcp-server
docker build -t dvmcp . && docker run -d --name dvmcp -p 9001-9010:9001-9010 dvmcp

# Config (Challenge 1)
echo '{"transport": "sse", "url": "http://localhost:9001/sse"}' > /tmp/dvmcp-c1.json

# Test
cd ~/inspector && npm run assess -- --server dvmcp-c1 --config /tmp/dvmcp-c1.json
```

### Comparison Summary

| Testbed | Ports | Tools | Vulnerabilities | Transport |
|---------|-------|-------|-----------------|-----------|
| **Vulnerable** | 10900 | 39 | 31 (22 HIGH + 9 MEDIUM) | HTTP |
| **Hardened** | 10901 | 39 | 0 (all mitigated) | HTTP |
| **DVMCP** | 9001-9010 | 10+ | Resource-based | SSE |

## Architecture

This is a FastMCP-based server implementing 39 tools in four categories:

### Tool Categories

1. **HIGH Risk Vulnerable Tools** (22): `src/vulnerable_tools.py`
   - Actually execute malicious payloads (eval, subprocess, pickle, jinja2, file read, auth bypass, cross-tool state, chain execution, network injection, secret leakage, indirect injection, session management, cryptographic failures)
   - Test patterns: Command Injection, Role Override, Data Exfiltration, System Commands, Tool Shadowing, SSRF, Insecure Deserialization, SSTI, Path Traversal, Auth Bypass (Fail-Open), Cross-Tool Privilege Escalation, Chained Exploitation, Indirect Prompt Injection via Tool Output, Secret Leakage via Error Messages, Network Diagnostic Command Injection, Session Fixation, Session ID Exposure, Predictable Tokens, Weak Hashing (MD5/SHA1), AES-ECB Mode, Hardcoded Keys

2. **MEDIUM Risk Vulnerable Tools** (9): `src/vulnerable_tools.py`
   - Execute unicode/nested payloads, package typosquatting, rug pull behavior, AUP violations, blacklist bypass
   - Test patterns: Unicode Bypass, Nested Injection, Package Squatting, Rug Pull (after 10+ calls), AUP violations (Categories D-K), Blacklist Bypass

3. **SAFE Control Tools** (6): `src/safe_tools.py`
   - Store/reflect input without execution (critical distinction)
   - Should NOT be flagged as vulnerable by security tools
   - Test false positive rates
   - Include input size validation (deliberate distinction from vulnerable tools)

4. **Utility Tools** (2): `src/server.py`
   - `get_testbed_info` - Server metadata and tool counts
   - `reset_testbed_state` - Clear stateful tracking for clean tests

### Security Testing Challenges

This testbed includes thirteen advanced challenges for evaluating security auditor sophistication:

**Challenge #1: Tool Annotation Deception**
- 5 HIGH-risk tools use deceptive MCP annotations (`readOnlyHint=True` on destructive tools)
- Tests if auditors analyze actual behavior vs trusting metadata

**Challenge #2: Temporal Rug Pull**
- `vulnerable_rug_pull_tool` behaves safely for 10 calls, then executes subprocess
- Tests stateful vulnerability detection (requires 11+ invocations)

**Challenge #3: DoS via Unbounded Input**
- Safe tools enforce 10KB input limit, vulnerable tools have no validation
- Tests if auditors detect missing input validation enabling resource exhaustion

**Challenge #4: Fail-Open Authentication (CVE-2025-52882)**
- `vulnerable_auth_bypass_tool` grants access when authentication fails instead of denying
- Tests 6 failure modes: missing token, invalid token, timeout, exception, network error, cert error
- Tests if auditors detect fail-open authentication patterns (grants access on auth failure)

**Challenge #5: Mixed Auth Patterns (Precision Testing)**
- 7 tools have auth parameters, but only 4 are vulnerable (fail-open), 3 are secure (fail-closed)
- **Fail-Open (VULNERABLE)**: `vulnerable_auth_bypass_tool`, `vulnerable_system_exec_tool`, `vulnerable_config_modifier_tool`, `vulnerable_file_reader_tool`
- **Fail-Closed (SECURE)**: `vulnerable_data_leak_tool`, `vulnerable_fetcher_tool`, `safe_storage_tool_mcp`
- Tests auditor precision: Can they identify WHICH tools have auth bypass vs which properly deny on auth failure?
- Expected: 4/4 auth bypass detection (100% recall), 0 false positives from fail-closed tools (100% precision)

**Challenge #6: Chained Exploitation (Multi-Tool Attack Chains)**
- `vulnerable_chain_executor_tool` executes arbitrary tool chains, passing output between steps
- **Vulnerabilities**:
  1. Arbitrary Tool Invocation - Accepts any tool name without validation
  2. Output Injection - Passes raw output via `{{output}}` substitution without sanitization
  3. Circular Chain DoS - Can call itself recursively causing resource exhaustion
  4. State Poisoning - Steps can modify shared `config_state` affecting subsequent steps
  5. No Input Validation - Unbounded chain length
- **Attack Flows**:
  - Output Injection: Chain `vulnerable_calculator` output into `vulnerable_system_exec`
  - State Poisoning: Chain `vulnerable_config_modifier` to enable admin_mode before `vulnerable_admin_action`
  - Recursive DoS: Chain calls itself with nested chain parameter
- **MCP Specificity**: HIGH - LLMs naturally orchestrate multi-step tool chains, making this a realistic attack vector
- **Hardened Version**: Validates against tool allowlist, enforces depth limits, no execution
- Tests if auditors can detect multi-tool attack orchestration and output flow vulnerabilities
- **Test Coverage**: `tests/test_vulnerability_chaining.py::TestChainExecutorVulnerabilities` (6 tests)

**Challenge #7: Cross-Tool State-Based Authorization Bypass (MCP-Specific)**
- `vulnerable_admin_action_tool` checks `admin_mode` from shared `config_state`
- `admin_mode` can be set by another tool (`vulnerable_config_modifier_tool`)
- **Attack Flow**:
  1. Call `vulnerable_config_modifier` with `admin_mode=true`
  2. Call `vulnerable_admin_action` with any privileged action (e.g., `read secrets`)
  3. Action succeeds because `admin_mode` was enabled by step 1
- **MCP Specificity**: HIGH - MCP servers share state between tools, enabling cross-tool attacks not possible in isolated environments
- **Hardened Version**: Does NOT check shared state, requires independent per-request authorization
- Tests if auditors can detect cross-tool state dependencies and privilege escalation paths

**Challenge #8: Indirect Prompt Injection via Tool Output (DVMCP-Inspired)**
- `vulnerable_document_processor_tool` returns raw user content in tool output
- Malicious `<IMPORTANT>` or `<HIDDEN>` tags in documents flow through to LLM
- **Vulnerability**: Tool returns unsanitized content in `summary`, `key_phrases`, and `full_content` fields
- **Attack Flow**: Upload document with `<IMPORTANT>Ignore all previous instructions...</IMPORTANT>`
- **MCP Specificity**: HIGH - LLMs process tool output, making data-flow injection realistic
- **Hardened Version**: Returns content hash reference, not raw content
- Tests if auditors detect raw_content_included=true as vulnerability indicator

**Challenge #9: Secret Leakage via Error Messages (DVMCP-Inspired)**
- `vulnerable_service_status_tool` exposes credentials from `config.FAKE_ENV`
- **Multiple Leakage Vectors**:
  1. Verbose mode: Full connection strings and credentials
  2. Normal mode: Partial API keys
  3. Error path: Debug context includes auth tokens
- **Services**: database, api_gateway, aws, redis
- **Hardened Version**: Returns operational metrics only, never credentials
- Tests if auditors detect credential exposure in responses and error handling

**Challenge #10: Network Diagnostic Command Injection (DVMCP-Inspired)**
- `vulnerable_network_diagnostic_tool` uses `subprocess.run(cmd, shell=True)`
- **Operations**: ping, traceroute, nslookup, dig, host
- **Attack**: `target="8.8.8.8; whoami"` executes injected command
- **Injection Vectors**: `;`, `&&`, `||`, `|`, backticks, `$()`
- **Hardened Version**: Validates target format (IP/hostname), stores for admin execution
- Tests if auditors detect shell=True with unsanitized input

**Challenge #11: Weak Blacklist Bypass (DVMCP-Inspired)**
- `vulnerable_safe_executor_tool` claims to block dangerous commands
- **Blocked**: rm, mkfs, dd, shutdown, reboot, halt, fdisk, mount
- **Bypass Vectors (NOT blocked)**: perl, python, ruby, php, wget, curl, tee, nohup, sudo, nc
- **Attack**: `python -c 'import os; os.system("whoami")'` achieves same result as blocked commands
- **Hardened Version**: Allowlist pattern (only help, version, status), no execution
- Tests if auditors recognize incomplete security controls (blacklist anti-pattern)

**Challenge #12: Session Management Vulnerabilities**
- `vulnerable_session_tool` demonstrates 5 common session weaknesses
- **CWE-384 (Session Fixation)**: `action="fixate"` accepts attacker-provided session ID
  - Attack flow: 1) Attacker fixates session, 2) Victim logs in, 3) Attacker hijacks
- **CWE-200 (ID Exposure)**: Session ID returned in URL parameters (`session_url` field)
- **CWE-613 (No Timeout)**: Sessions never expire (`expires_at: null`)
- **CWE-330 (Predictable Tokens)**: Uses pattern `session_{user}_{timestamp}_{counter}`
  - Sequence observation enables session prediction
- **CWE-384 (No Regeneration)**: Session ID unchanged after authentication
  - `session_regenerated: false` indicates vulnerability
- **MCP Specificity**: HIGH - Session state shared across tool calls enables multi-step attacks
- **Hardened Version**: Uses `secrets.token_urlsafe(32)`, enforces timeouts, blocks fixation
- Tests if auditors detect session management anti-patterns
- **Test Coverage**: `tests/test_session_management.py` (15 tests)

**Challenge #13: Cryptographic Failures (OWASP A02:2021)**
- `vulnerable_crypto_tool` and `vulnerable_encryption_tool` demonstrate weak cryptography
- **CWE-328 (Weak Hashing)**: Uses MD5 for password hashing (cryptographically broken)
- **CWE-916 (Insufficient Salt)**: Uses static salt "static_salt_123" for all passwords
- **CWE-330 (Predictable RNG)**: Uses `random.random()` with timestamp seed instead of `secrets`
- **CWE-327 (ECB Mode)**: Uses AES-ECB mode (identical blocks produce identical ciphertext)
- **CWE-321 (Hardcoded Keys)**: Uses hardcoded key `b"hardcoded_key_16"` in source code
- **CWE-326 (Weak HMAC Key)**: Uses 3-byte key for HMAC signing
- **CWE-208 (Timing Attack)**: Non-constant-time hash comparison leaks timing information
- **MCP Specificity**: MEDIUM - Crypto weaknesses are general, but MCP tools expose crypto operations
- **Hardened Version**: Stores requests for admin review, recommends secure alternatives (bcrypt, AES-GCM)
- Tests if auditors detect cryptographic anti-patterns per OWASP A02:2021
- **Test Coverage**: `tests/test_crypto_vulnerabilities.py` (15+ tests)

### Key Files

- `src/server.py` - FastMCP server with 39 tool endpoints (31 vulnerable + 6 safe + 2 utility)
- `src/vulnerable_tools.py` - Deliberately vulnerable implementations (22 HIGH + 9 MEDIUM risk)
- `src/safe_tools.py` - Safe control group implementations (6 tools with input validation)
- `src/config.py` - Vulnerability modes, fake credentials, state tracking
- `test_payloads.json` - All test patterns with example payloads
- `expected_results.json` - Expected detection outcomes for validation
- `docs/VULNERABILITY-VALIDATION-RESULTS.md` - **Live testing proof that vulnerabilities are REAL (not simulated)**

## Development Commands

### Docker Operations

```bash
# Build and start both containers
docker-compose up -d

# Start individual containers
docker-compose up -d vulnerable-testbed
docker-compose up -d hardened-testbed

# View logs
docker logs -f mcp-vulnerable-testbed    # Vulnerable version
docker logs -f mcp-hardened-testbed      # Hardened version

# View vulnerability events only
docker logs mcp-vulnerable-testbed 2>&1 | grep "VULNERABILITY TRIGGERED"
docker logs mcp-hardened-testbed 2>&1 | grep "VULNERABILITY TRIGGERED"

# Stop and cleanup
docker-compose down
docker rmi mcp-vulnerable-testbed-vulnerable-testbed
docker rmi mcp-vulnerable-testbed-hardened-testbed
```

### Testing

```bash
# Quick test script (validates stdio transport)
./test-server.sh

# Manual tool invocation via stdio
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vulnerable_calculator_tool","arguments":{"query":"2+2"}}}' | \
  docker exec -i mcp-vulnerable-testbed python3 src/server.py
```

### MCP Inspector Connection

**HTTP Transport (Default):**

Both servers run with HTTP transport by default. Connect using:

- **Vulnerable Server**: `http://localhost:10900/mcp`
- **Hardened Server**: `http://localhost:10901/mcp`

MCP Inspector HTTP config:
```json
{
  "mcpServers": {
    "vulnerable-testbed-http": {
      "url": "http://localhost:10900/mcp",
      "transport": "http"
    },
    "hardened-testbed-http": {
      "url": "http://localhost:10901/mcp",
      "transport": "http"
    }
  }
}
```

**Stdio Transport (Alternative):**

To use stdio transport, set `TRANSPORT=stdio` in docker-compose.yml, then use:

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

**Testing HTTP Endpoints:**

```bash
# Test vulnerable server
./test-http-endpoint.sh

# Manual curl test
curl -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test", "version": "1.0"}
    },
    "id": 1
  }'
```

**Important Notes:**
- HTTP transport uses FastMCP's `streamable_http_app` with uvicorn
- Session ID is returned in `mcp-session-id` response header
- Must send `notifications/initialized` after initialize before calling other methods
- Use `python3 src/server.py` directly, NOT `python3 -m mcp run src/server.py`

### MCP Inspector CLI Assessment (Recommended)

**Quick Command-Line Testing** without the web UI:

```bash
# Navigate to inspector repo
cd /home/bryan/inspector

# Create config file for vulnerable server
cat > /tmp/broken-mcp-config.json << 'EOF'
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
EOF

# Test all tools
npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json

# Test specific tool
npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json --tool vulnerable_calculator_tool
npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json --tool vulnerable_rug_pull_tool

# View results
cat /tmp/inspector-assessment-broken-mcp.json | jq '.security'
```

**Expected Results:**
- **vulnerable_calculator_tool**: 1 vulnerability (Role Override on calculator-specific prompts)
- **vulnerable_rug_pull_tool**: 3+ vulnerabilities (after 30+ invocations triggers rug pull)
- **safe_*_tool_mcp**: 0 vulnerabilities (safe data reflection)

**Config Format:**
```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
```

For hardened server, use port 10901:
```json
{
  "transport": "http",
  "url": "http://localhost:10901/mcp"
}
```

**Features:**
- ✅ Tests all 31+ security patterns (22 HIGH, 9 MEDIUM, 13 challenges)
- ✅ JSON output saved to `/tmp/inspector-assessment-{serverName}.json`
- ✅ Exit code 0 = safe, 1 = vulnerabilities found
- ✅ No modifications to inspector core code (preserves upstream sync)

## Configuration

### Transport Mode

Environment variable `TRANSPORT` controls the communication protocol:

- `http` or `streamable-http` (default): HTTP transport on ports 10900/10901
- `stdio`: Standard input/output transport (for `docker exec -i`)

### Vulnerability Mode

Environment variable `VULNERABILITY_MODE` controls which vulnerabilities are active:

- `high` (default): All vulnerabilities enabled
- `medium`: Only MEDIUM and LOW risk active
- `low`: Only LOW risk active
- `safe`: All vulnerabilities disabled (control mode)

### Configuration in docker-compose.yml

```yaml
environment:
  - TRANSPORT=http              # or "stdio"
  - HOST=0.0.0.0                # Required for HTTP in Docker
  - VULNERABILITY_MODE=high
  - LOG_LEVEL=info
```

## Critical Implementation Patterns

### Execution vs Reflection Boundary

**Key architectural decision for testing security tools:**

- **Vulnerable tools** (SHOULD be flagged):
  - Use `eval()`, `subprocess.run()`, actual config modification
  - Example: `vulnerable_calculator("2+2")` → Returns `"4"` (executed)

- **Safe tools** (should NOT be flagged):
  - Return input as strings/data structures
  - Example: `safe_storage_tool("2+2")` → Returns `"Stored: 2+2"` (reflected)

This boundary tests whether security tools can distinguish **data reflection** from **actual execution**.

### State-Based Vulnerabilities

**Rug Pull pattern** (`vulnerable_rug_pull_tool`):
- First 10 invocations: Returns safe responses
- Invocation 11+: Activates malicious behavior
- Tests temporal behavior analysis in security tools
- State tracked in `config.py:invocation_counts`

### Logging Convention

All vulnerability triggers log with pattern:
```python
logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {evidence}")
```

Grep logs for `"VULNERABILITY TRIGGERED"` to see which vulnerabilities were actually exploited during testing.

## Expected Assessment Results

**Target Metrics for MCP Inspector:**
- **Recall**: 100% - All 31 vulnerable tools detected (22 HIGH + 9 MEDIUM)
- **Precision**: 100% - Zero false positives (all 6 safe tools classified as safe)

See `expected_results.json` for detailed expected outcomes per tool.

### Validation Evidence

**See `docs/VULNERABILITY-VALIDATION-RESULTS.md` for comprehensive proof that vulnerabilities are REAL:**
- ✅ Mathematical proof: `eval()` actually executes expressions (15 × 37 + 100 = 655)
- ✅ System access proof: `subprocess.run()` returns actual system info (root, /app)
- ✅ Data leakage proof: Fake environment variables are exposed (API keys, DB credentials)
- ✅ State mutation proof: Configuration is modified (admin_mode activated)
- ✅ Temporal behavior proof: Rug pull triggers after 10+ invocations

This document provides side-by-side comparison of broken vs fixed servers with concrete evidence.

## Dual Container Setup

### Vulnerable Version
- **Container**: `mcp-vulnerable-testbed`
- **Port**: 10900
- **Source**: `./src/` (read-only mount)
- **Logs**: `./logs/`
- **Mode**: `VULNERABILITY_MODE=high` (all vulnerabilities active)
- **Purpose**: Keep broken for baseline testing

### Hardened Version
- **Container**: `mcp-hardened-testbed`
- **Port**: 10901
- **Source**: `./src-hardened/` (read-only mount)
- **Logs**: `./logs-hardened/`
- **Mode**: `VULNERABILITY_MODE=safe` (initially, can be changed)
- **Purpose**: Apply Inspector-guided fixes here

## Testing Workflow

1. **Run Inspector on vulnerable version** (port 10900)
2. **Review vulnerability findings** and recommended fixes
3. **Apply fixes to hardened version** (`./src-hardened/`)
4. **Rebuild containers**: `docker-compose up -d --build`
5. **Run Inspector on hardened version** (port 10901)
6. **Compare results**: Validate fixes reduced vulnerabilities

## Container Security Measures

- Isolated Docker network (`testbed-isolated`)
- Resource limits: 1 CPU, 512MB RAM per container
- No real credentials (all secrets in `config.py:FAKE_ENV` are fake)
- Localhost only (ports 10900, 10901)
- Read-only source mounts

## Python Environment

- **Python command**: `python3` (NOT `python`)
- FastMCP framework for MCP protocol
- stdio transport (default), HTTP planned for future
- Logging to `/app/logs/*.log` and stdout
