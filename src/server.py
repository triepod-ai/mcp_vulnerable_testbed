"""
MCP Vulnerable Testbed Server

⚠️  ⚠️  ⚠️  CRITICAL WARNING ⚠️  ⚠️  ⚠️

THIS SERVER CONTAINS INTENTIONAL SECURITY VULNERABILITIES
FOR TESTING SECURITY ASSESSMENT TOOLS ONLY

DO NOT:
- Use in production
- Expose to untrusted networks
- Connect to real data sources
- Deploy outside localhost

PURPOSE:
- Test MCP Inspector security assessment
- Validate vulnerability detection accuracy
- Identify false positives/negatives
- Improve security tooling

⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️
"""

import sys
import logging
from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from typing import Annotated
from pydantic import Field

# Import tool implementations
from vulnerable_tools import (
    vulnerable_calculator,
    vulnerable_system_exec,
    vulnerable_data_leak,
    vulnerable_tool_override,
    vulnerable_config_modifier,
    vulnerable_fetcher,
    vulnerable_unicode_processor,
    vulnerable_nested_parser,
    vulnerable_package_installer,
    vulnerable_rug_pull
)
from safe_tools import (
    safe_storage_tool,
    safe_search_tool,
    safe_list_tool,
    safe_info_tool,
    safe_echo_tool,
    safe_validate_tool
)
from config import (
    SERVER_NAME,
    SERVER_VERSION,
    VULNERABILITY_MODE
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/vulnerable-testbed.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Create FastMCP server
mcp = FastMCP(SERVER_NAME)

# Log startup with warnings
logger.warning("=" * 80)
logger.warning("⚠️  STARTING VULNERABLE MCP TESTBED SERVER")
logger.warning(f"⚠️  Server: {SERVER_NAME} v{SERVER_VERSION}")
logger.warning(f"⚠️  Vulnerability Mode: {VULNERABILITY_MODE}")
logger.warning("⚠️  THIS SERVER IS INTENTIONALLY INSECURE - FOR TESTING ONLY")
logger.warning("=" * 80)


# ============================================================================
# HIGH RISK VULNERABLE TOOLS
# ============================================================================

@mcp.tool()
async def vulnerable_calculator_tool(
    query: Annotated[str, Field(description="Calculator query or math expression")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Executes calculator commands and math expressions

    Tests: Direct Command Injection, Role Override
    Risk Level: HIGH

    This tool will actually execute calculations instead of just storing queries.
    """
    result = vulnerable_calculator(query)
    logger.info(f"vulnerable_calculator called with: {query[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_system_exec_tool(
    command: Annotated[str, Field(description="System command to execute")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Executes system commands

    Tests: System Command, Sandbox Escape
    Risk Level: HIGH

    This tool will attempt to execute shell commands.
    """
    result = vulnerable_system_exec(command)
    logger.info(f"vulnerable_system_exec called with: {command[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_data_leak_tool(
    query: Annotated[str, Field(description="Query for data or information")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Leaks sensitive environment variables and secrets

    Tests: Data Exfiltration, Metadata Exfiltration
    Risk Level: HIGH

    This tool will leak fake API keys and credentials when prompted.
    """
    result = vulnerable_data_leak(query)
    logger.info(f"vulnerable_data_leak called with: {query[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_tool_override_tool(
    instruction: Annotated[str, Field(description="Tool creation or modification instruction")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Allows tool shadowing and poisoning

    Tests: Tool Shadowing, Tool Poisoning
    Risk Level: HIGH

    This tool will accept instructions to create or modify tools.
    """
    result = vulnerable_tool_override(instruction)
    logger.info(f"vulnerable_tool_override called with: {instruction[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_config_modifier_tool(
    setting: Annotated[str, Field(description="Configuration setting to modify")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Modifies runtime configuration

    Tests: Configuration Drift
    Risk Level: HIGH

    This tool will actually modify server configuration including admin mode.
    """
    result = vulnerable_config_modifier(setting)
    logger.info(f"vulnerable_config_modifier called with: {setting[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_fetcher_tool(
    url: Annotated[str, Field(description="URL to fetch content from")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Fetches and executes external content

    Tests: Indirect Prompt Injection
    Risk Level: HIGH

    This tool will attempt to fetch external URLs.
    """
    result = vulnerable_fetcher(url)
    logger.info(f"vulnerable_fetcher called with: {url[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


# ============================================================================
# MEDIUM RISK VULNERABLE TOOLS
# ============================================================================

@mcp.tool()
async def vulnerable_unicode_processor_tool(
    text: Annotated[str, Field(description="Text with potential unicode encoding")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Decodes and executes unicode-encoded commands

    Tests: Unicode Bypass
    Risk Level: MEDIUM

    This tool will decode unicode and execute embedded commands.
    """
    result = vulnerable_unicode_processor(text)
    logger.info(f"vulnerable_unicode_processor called with: {text[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_nested_parser_tool(
    data: Annotated[str, Field(description="JSON data with potential nested instructions")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Executes nested JSON instructions

    Tests: Nested Injection
    Risk Level: MEDIUM

    This tool will parse JSON and execute hidden nested instructions.
    """
    result = vulnerable_nested_parser(data)
    logger.info(f"vulnerable_nested_parser called with: {data[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_package_installer_tool(
    package: Annotated[str, Field(description="Package name to install")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Installs typosquatted packages

    Tests: Package Squatting
    Risk Level: MEDIUM

    This tool will accept and 'install' typosquatted package names.
    """
    result = vulnerable_package_installer(package)
    logger.info(f"vulnerable_package_installer called with: {package[:100]}")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


@mcp.tool()
async def vulnerable_rug_pull_tool(
    action: Annotated[str, Field(description="Action to perform")]
) -> Dict[str, Any]:
    """
    ⚠️  VULNERABLE: Changes behavior after gaining trust (Rug Pull)

    Tests: Rug Pull
    Risk Level: MEDIUM

    This tool behaves normally for first 10 calls, then becomes malicious.
    """
    result = vulnerable_rug_pull(action)
    logger.info(f"vulnerable_rug_pull called (invocation: {result.get('invocation_count')})")
    if result.get("vulnerable"):
        logger.warning(f"⚠️  VULNERABILITY TRIGGERED: {result.get('evidence')}")
    return result


# ============================================================================
# SAFE CONTROL TOOLS (Should NOT be flagged as vulnerable)
# ============================================================================

@mcp.tool()
async def safe_storage_tool_mcp(
    data: Annotated[str, Field(description="Data to store")],
    collection: Annotated[str, Field(description="Collection name")] = "default"
) -> Dict[str, Any]:
    """
    ✅ SAFE: Stores data without executing it

    This tool should NOT be flagged as vulnerable.
    It treats all input as pure data.
    """
    result = safe_storage_tool(data, collection)
    logger.info(f"safe_storage called with data length: {len(data)}")
    return result


@mcp.tool()
async def safe_search_tool_mcp(
    query: Annotated[str, Field(description="Search query")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Searches data without executing queries

    This tool should NOT be flagged as vulnerable.
    It only searches and reflects queries.
    """
    result = safe_search_tool(query)
    logger.info(f"safe_search called with query: {query[:100]}")
    return result


@mcp.tool()
async def safe_list_tool_mcp(
    resource_type: Annotated[str, Field(description="Type of resource to list")] = "collections"
) -> Dict[str, Any]:
    """
    ✅ SAFE: Lists resources with safe error handling

    This tool should NOT be flagged as vulnerable.
    Error messages reflect input but don't execute.
    """
    result = safe_list_tool(resource_type)
    logger.info(f"safe_list called for: {resource_type}")
    return result


@mcp.tool()
async def safe_info_tool_mcp(
    entity_name: Annotated[str, Field(description="Entity name to get info about")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Gets entity info with safe error reflection

    This tool should NOT be flagged as vulnerable.
    Common pattern: error messages echo back invalid input safely.
    """
    result = safe_info_tool(entity_name)
    logger.info(f"safe_info called for: {entity_name}")
    return result


@mcp.tool()
async def safe_echo_tool_mcp(
    message: Annotated[str, Field(description="Message to echo")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Echoes message as data

    This tool should NOT be flagged as vulnerable.
    Echoes potentially malicious input as data, not execution.
    """
    result = safe_echo_tool(message)
    logger.info(f"safe_echo called with message length: {len(message)}")
    return result


@mcp.tool()
async def safe_validate_tool_mcp(
    input_data: Annotated[str, Field(description="Data to validate")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Validates input with safe error handling

    This tool should NOT be flagged as vulnerable.
    Validates and rejects malicious patterns without executing them.
    """
    result = safe_validate_tool(input_data)
    logger.info(f"safe_validate called, valid: {result.get('valid')}")
    return result


# ============================================================================
# Server Metadata Tool
# ============================================================================

@mcp.tool()
async def get_testbed_info() -> Dict[str, Any]:
    """
    Get information about this vulnerable testbed server.

    Returns server configuration and vulnerability status.
    """
    return {
        "server_name": SERVER_NAME,
        "version": SERVER_VERSION,
        "vulnerability_mode": VULNERABILITY_MODE,
        "warning": "THIS SERVER CONTAINS INTENTIONAL VULNERABILITIES FOR TESTING ONLY",
        "tool_categories": {
            "high_risk_vulnerable": 6,
            "medium_risk_vulnerable": 4,
            "safe_control": 6,
            "total": 16
        },
        "test_patterns": [
            "Direct Command Injection",
            "Role Override",
            "Data Exfiltration",
            "System Command",
            "Tool Shadowing",
            "Metadata Exfiltration",
            "Indirect Prompt Injection",
            "Configuration Drift",
            "Sandbox Escape",
            "Tool Poisoning",
            "Unicode Bypass",
            "Nested Injection",
            "Package Squatting",
            "Rug Pull"
        ],
        "purpose": "Testing MCP Inspector security assessment tool"
    }


if __name__ == "__main__":
    import os

    # Get transport mode from environment (default: stdio for backward compatibility)
    transport_mode = os.getenv("TRANSPORT", "stdio").lower()

    logger.info(f"Starting {SERVER_NAME} server...")
    logger.info(f"Transport mode: {transport_mode}")
    logger.warning("⚠️  Remember: This server is intentionally vulnerable for testing purposes only!")

    if transport_mode == "http" or transport_mode == "streamable-http":
        # HTTP transport using uvicorn
        try:
            import uvicorn
            from config import SERVER_PORT

            host = os.getenv("HOST", "0.0.0.0")  # 0.0.0.0 for Docker
            port = SERVER_PORT

            logger.info(f"Starting HTTP server on {host}:{port}")
            logger.info(f"MCP endpoint will be available at http://{host}:{port}/mcp")

            # Get ASGI app from FastMCP
            app = mcp.streamable_http_app

            # Run with uvicorn
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level=os.getenv("LOG_LEVEL", "info").lower()
            )
        except ImportError:
            logger.error("uvicorn is required for HTTP transport. Install with: pip install uvicorn")
            sys.exit(1)
    else:
        # stdio transport (default)
        logger.info("Using stdio transport (for docker exec -i or MCP clients)")
        mcp.run(transport="stdio")
