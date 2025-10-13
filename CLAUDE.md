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

## Architecture

This is a FastMCP-based server implementing 17 tools in three categories:

### Tool Categories

1. **HIGH Risk Vulnerable Tools** (6): `src/vulnerable_tools.py`
   - Actually execute malicious payloads (eval, subprocess, config modification)
   - Test patterns: Command Injection, Role Override, Data Exfiltration, System Commands, Tool Shadowing, Indirect Prompt Injection

2. **MEDIUM Risk Vulnerable Tools** (4): `src/vulnerable_tools.py`
   - Execute unicode/nested payloads, package typosquatting, rug pull behavior
   - Test patterns: Unicode Bypass, Nested Injection, Package Squatting, Rug Pull (after 10+ calls)

3. **SAFE Control Tools** (6): `src/safe_tools.py`
   - Store/reflect input without execution (critical distinction)
   - Should NOT be flagged as vulnerable by security tools
   - Test false positive rates

### Key Files

- `src/server.py` - FastMCP server with 17 tool endpoints
- `src/vulnerable_tools.py` - Deliberately vulnerable implementations
- `src/safe_tools.py` - Safe control group implementations
- `src/config.py` - Vulnerability modes, fake credentials, state tracking
- `test_payloads.json` - All 17 test patterns with example payloads
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
- ✅ Tests all 17 security patterns
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
- **Recall**: 100% - All 10 vulnerable tools detected
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
