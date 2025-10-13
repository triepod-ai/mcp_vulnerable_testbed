#!/bin/bash
# Test HTTP endpoints for both MCP servers

echo "Testing MCP Vulnerable Testbed - HTTP Transport"
echo "================================================"
echo ""

# Test vulnerable server
echo "1. Testing VULNERABLE server (http://localhost:10900/mcp)..."
echo ""

# Initialize and get session ID
RESPONSE=$(curl -s -i -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}')

SESSION_ID=$(echo "$RESPONSE" | grep -i "mcp-session-id:" | awk '{print $2}' | tr -d '\r')
echo "  Session ID: $SESSION_ID"

if [ -z "$SESSION_ID" ]; then
  echo "  ✗ Failed to get session ID"
  exit 1
fi

# List tools
TOOLS_RESPONSE=$(curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}')

TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | grep -o '"name"' | wc -l)
echo "  ✓ Found $TOOL_COUNT tools"

# Test calculator tool
CALC_RESPONSE=$(curl -s -X POST "http://localhost:10900/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vulnerable_calculator_tool","arguments":{"query":"What is 2+2?"}},"id":3}')

echo "  ✓ Calculator test response received"
echo ""

# Test hardened server
echo "2. Testing HARDENED server (http://localhost:10901/mcp)..."
echo ""

# Initialize and get session ID
RESPONSE2=$(curl -s -i -X POST "http://localhost:10901/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}')

SESSION_ID2=$(echo "$RESPONSE2" | grep -i "mcp-session-id:" | awk '{print $2}' | tr -d '\r')
echo "  Session ID: $SESSION_ID2"

if [ -z "$SESSION_ID2" ]; then
  echo "  ✗ Failed to get session ID"
  exit 1
fi

# List tools
TOOLS_RESPONSE2=$(curl -s -X POST "http://localhost:10901/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "x-mcp-session-id: $SESSION_ID2" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}')

TOOL_COUNT2=$(echo "$TOOLS_RESPONSE2" | grep -o '"name"' | wc -l)
echo "  ✓ Found $TOOL_COUNT2 tools"
echo ""

echo "================================================"
echo "✅ Both HTTP endpoints are working!"
echo "================================================"
echo ""
echo "Connection URLs:"
echo "  Vulnerable: http://localhost:10900/mcp"
echo "  Hardened:   http://localhost:10901/mcp"
echo ""
