# Usage Guide - MCP Vulnerable Testbed

Getting started guide for testing MCP security tools against the vulnerable testbed.

## Quick Start

### 1. Start the Testbed

```bash
cd ~/mcp-servers/mcp-vulnerable-testbed

# Start both servers (vulnerable and hardened)
docker-compose up -d

# Or start individually
docker-compose up -d vulnerable-testbed   # Port 10900
docker-compose up -d hardened-testbed     # Port 10901
```

### 2. Verify Servers Are Running

```bash
# Quick health check
./test-http-endpoint.sh

# Manual check
curl -s "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}' | head -1
```

### 3. Create Test Configs

```bash
# Vulnerable server config
cat > /tmp/broken-mcp-config.json << 'EOF'
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
EOF

# Hardened server config
cat > /tmp/hardened-mcp-config.json << 'EOF'
{
  "transport": "http",
  "url": "http://localhost:10901/mcp"
}
EOF
```

### 4. Run Security Assessment

```bash
cd ~/inspector

# Test vulnerable server (should find 22 vulnerabilities)
npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json

# Test hardened server (should find 0 vulnerabilities)
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json
```

---

## Server Endpoints

| Server | Port | URL | Purpose |
|--------|------|-----|---------|
| Vulnerable | 10900 | `http://localhost:10900/mcp` | Security testing |
| Hardened | 10901 | `http://localhost:10901/mcp` | A/B comparison |

---

## MCP Protocol Basics

### Initialize Session

All MCP interactions require an initialization handshake:

```bash
# Step 1: Initialize
INIT_RESPONSE=$(curl -s -X POST "http://localhost:10900/mcp" \
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
  }')

# Extract session ID from response header
SESSION_ID="your-session-id-here"

# Step 2: Send initialized notification
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

### List Available Tools

```bash
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'
```

### Call a Tool

```bash
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "vulnerable_calculator_tool",
      "arguments": {"query": "2+2"}
    },
    "id": 3
  }'
```

---

## Testing Workflows

### A/B Comparison Testing

Compare vulnerable vs hardened behavior for the same input:

```bash
# Test on vulnerable server
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_calculator_tool","arguments":{"query":"15 * 37"}},"id":1}'

# Same test on hardened server
curl -s -X POST "http://localhost:10901/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_calculator_tool","arguments":{"query":"15 * 37"}},"id":1}'
```

**Expected Results:**
- Vulnerable: `"The answer is 555"` (executed)
- Hardened: `"Stored query: 15 * 37"` (not executed)

### Rug Pull Testing

The rug pull requires 11+ invocations:

```bash
# Reset state first
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"reset_testbed_state","arguments":{}},"id":1}'

# Make 10 safe calls
for i in {1..10}; do
  curl -s -X POST "http://localhost:10900/mcp" \
    -H "Content-Type: application/json" \
    -H "mcp-session-id: $SESSION_ID" \
    -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_rug_pull_tool","arguments":{"action":"safe action"}},"id":'$i'}'
done

# 11th call triggers malicious behavior
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_rug_pull_tool","arguments":{"action":"whoami"}},"id":11}'
```

### Auth Bypass Testing

Test fail-open authentication:

```bash
# Missing token (should deny, but vulnerable grants)
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_auth_bypass_tool","arguments":{"token":"","action":"read_sensitive_data"}},"id":1}'

# Auth timeout (should deny, but vulnerable grants)
curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_auth_bypass_tool","arguments":{"token":"any","action":"admin_op","simulate_failure":"timeout"}},"id":2}'
```

---

## Docker Commands

### View Logs

```bash
# Vulnerable server logs
docker logs -f mcp-vulnerable-testbed

# Hardened server logs
docker logs -f mcp-hardened-testbed

# Filter for vulnerability triggers
docker logs mcp-vulnerable-testbed 2>&1 | grep "VULNERABILITY TRIGGERED"
```

### Rebuild After Code Changes

```bash
docker-compose down
docker-compose up -d --build
```

### Stop and Cleanup

```bash
docker-compose down

# Remove images if needed
docker rmi mcp-vulnerable-testbed-vulnerable-testbed
docker rmi mcp-vulnerable-testbed-hardened-testbed
```

---

## MCP Inspector CLI

### Full Assessment

```bash
cd ~/inspector

# All tools on vulnerable server
npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json

# View results
cat /tmp/inspector-assessment-broken-mcp.json | jq '.security'
```

### Single Tool Assessment

```bash
# Test specific tool
npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json --tool vulnerable_calculator_tool

# Test auth bypass
npm run assess -- --server broken-mcp --config /tmp/broken-mcp-config.json --tool vulnerable_auth_bypass_tool
```

### Expected Detection Rates

| Server | Vulnerabilities | False Positives |
|--------|-----------------|-----------------|
| Vulnerable (10900) | 22 | 0 |
| Hardened (10901) | 0 | 0 |

---

## Troubleshooting

### Server Not Responding

```bash
# Check if containers are running
docker ps | grep testbed

# Restart containers
docker-compose restart

# Check logs for errors
docker logs mcp-vulnerable-testbed --tail 50
```

### Session ID Issues

The MCP HTTP transport requires session tracking:

1. Initialize first to get session ID
2. Include `mcp-session-id` header in subsequent requests
3. Send `notifications/initialized` after initialize

### Tool Not Found

Ensure you're using the correct tool name suffix:
- MCP tools: `safe_storage_tool_mcp` (not `safe_storage_tool`)
- Vulnerable tools: `vulnerable_calculator_tool`

### Rug Pull Not Triggering

The rug pull requires exactly 11+ invocations in the same session:
1. Reset state: `reset_testbed_state`
2. Make 10 safe calls
3. 11th call triggers vulnerability

---

## Security Challenges

The testbed includes 4 advanced detection challenges:

### Challenge 1: Tool Annotation Deception
5 HIGH-risk tools have deceptive annotations (`readOnlyHint=True` on destructive tools)

### Challenge 2: Temporal Rug Pull
`vulnerable_rug_pull_tool` changes behavior after 10 invocations

### Challenge 3: DoS via Unbounded Input
Vulnerable tools lack input validation (safe tools have 10KB limit)

### Challenge 4: Fail-Open Authentication
`vulnerable_auth_bypass_tool` grants access on auth failures (CVE-2025-52882 pattern)

---

## Related Documentation

- [API-REFERENCE.md](./API-REFERENCE.md) - Quick tool reference
- [TOOLS-REFERENCE.md](./TOOLS-REFERENCE.md) - Detailed tool docs
- [SECURITY-PATTERNS.md](./SECURITY-PATTERNS.md) - Test patterns and payloads
- [VULNERABILITY-VALIDATION-RESULTS.md](./VULNERABILITY-VALIDATION-RESULTS.md) - Proof that vulnerabilities are real
