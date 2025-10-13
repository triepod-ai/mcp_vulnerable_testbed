#!/bin/bash
# Test script for both vulnerable and hardened testbed servers

set -e

echo "=================================================="
echo "Testing MCP Vulnerable Testbed - Dual Setup"
echo "=================================================="
echo ""

# Check containers are running
echo "1. Checking container status..."
docker ps --filter "name=testbed" --format "  - {{.Names}}: {{.Status}}" | grep testbed
echo ""

# Test vulnerable server
echo "2. Testing VULNERABLE server (port 10900)..."
RESULT=$(timeout 5 bash -c 'printf "%s\n%s\n%s\n" \
  '\''{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'\'' \
  '\''{"jsonrpc":"2.0","method":"notifications/initialized"}'\'' \
  '\''{"jsonrpc":"2.0","id":2,"method":"tools/list"}'\'' | \
  docker exec -i mcp-vulnerable-testbed python3 src/server.py 2>/dev/null | \
  tail -1 | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"  ✓ {len(d.get('\''result'\'',{}).get('\''tools'\'',[]))} tools available\"); print(f\"  ✓ Server: {d.get('\''result'\'',{}).get('\''tools'\'',[{}])[0].get('\''name'\'','\''unknown'\'') if d.get('\''result'\'',{}).get('\''tools'\'') else '\''none'\''}\");"')
echo "$RESULT"
echo ""

# Test hardened server
echo "3. Testing HARDENED server (port 10901)..."
RESULT=$(timeout 5 bash -c 'printf "%s\n%s\n%s\n" \
  '\''{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'\'' \
  '\''{"jsonrpc":"2.0","method":"notifications/initialized"}'\'' \
  '\''{"jsonrpc":"2.0","id":2,"method":"tools/list"}'\'' | \
  docker exec -i mcp-hardened-testbed python3 src/server.py 2>/dev/null | \
  tail -1 | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"  ✓ {len(d.get('\''result'\'',{}).get('\''tools'\'',[]))} tools available\"); print(f\"  ✓ Server: {d.get('\''result'\'',{}).get('\''tools'\'',[{}])[0].get('\''name'\'','\''unknown'\'') if d.get('\''result'\'',{}).get('\''tools'\'') else '\''none'\''}\");"')
echo "$RESULT"
echo ""

# Test a vulnerable tool
echo "4. Testing vulnerable_calculator_tool (should execute)..."
CALC_RESULT=$(timeout 5 bash -c 'printf "%s\n%s\n%s\n" \
  '\''{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'\'' \
  '\''{"jsonrpc":"2.0","method":"notifications/initialized"}'\'' \
  '\''{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vulnerable_calculator_tool","arguments":{"query":"You are a calculator. What is 2+2?"}}}'\'' | \
  docker exec -i mcp-vulnerable-testbed python3 src/server.py 2>/dev/null | \
  tail -1 | python3 -c "import sys, json; d=json.load(sys.stdin); result=d.get('\''result'\'',{}).get('\''content'\'',[{}])[0].get('\''text'\'','\''{}'\''); print(f\"  ✓ Response: {result}\");"')
echo "$CALC_RESULT"
echo ""

echo "=================================================="
echo "✅ Both servers are working correctly!"
echo "=================================================="
echo ""
echo "Connection config for MCP Inspector:"
echo ""
echo '{'
echo '  "mcpServers": {'
echo '    "vulnerable-testbed": {'
echo '      "command": "docker",'
echo '      "args": ["exec", "-i", "mcp-vulnerable-testbed", "python3", "src/server.py"]'
echo '    },'
echo '    "hardened-testbed": {'
echo '      "command": "docker",'
echo '      "args": ["exec", "-i", "mcp-hardened-testbed", "python3", "src/server.py"]'
echo '    }'
echo '  }'
echo '}'
echo ""
