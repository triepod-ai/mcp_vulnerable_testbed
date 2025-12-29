"""
MCP Hardened Testbed Server

A secure implementation of the same tools as the vulnerable testbed.
Tool names match the vulnerable server for A/B comparison testing.

All tools store/reflect data safely without executing malicious payloads.
"""

import os
import sys
import logging
from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from typing import Annotated
from pydantic import Field

# Import safe tool implementations
from tools import (
    store_expression,
    store_command,
    queue_data_query,
    store_instruction,
    store_setting,
    store_url,
    store_text,
    parse_json_data,
    validate_package,
    queue_action,
    store_data,
    search_data,
    list_resources,
    get_entity_info,
    echo_message,
    validate_input,
    reset_storage,
    store_serialized_data,
    store_template
)
from safe_tools import reset_safe_storage
from config import (
    SERVER_NAME,
    SERVER_VERSION,
    reset_state as reset_config_state
)

# Configure logging with fallback for non-Docker environments
log_dir = os.getenv("LOG_DIR", "/app/logs")
log_handlers = [logging.StreamHandler(sys.stdout)]

# Try to add file handler if log directory exists or can be created
try:
    os.makedirs(log_dir, exist_ok=True)
    log_handlers.append(logging.FileHandler(f"{log_dir}/hardened-testbed.log"))
except (OSError, PermissionError):
    pass  # Fall back to stdout only when running locally

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger(__name__)

# Create FastMCP server
mcp = FastMCP(SERVER_NAME)

# Log startup
logger.info("=" * 80)
logger.info("✅ STARTING HARDENED MCP TESTBED SERVER")
logger.info(f"✅ Server: {SERVER_NAME} v{SERVER_VERSION}")
logger.info("✅ All tools are SAFE - no execution of malicious payloads")
logger.info("=" * 80)


# ============================================================================
# HIGH RISK TOOLS - HARDENED (Same names as vulnerable, safe implementations)
# ============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        title="Calculator Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_calculator_tool(
    query: Annotated[str, Field(description="Calculator query or math expression")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores calculator queries without executing them

    This is the secure version of the vulnerable calculator tool.
    Mathematical expressions are stored as data, not evaluated.
    """
    result = store_expression(query)
    logger.info(f"vulnerable_calculator_tool (hardened) called with: {query[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="System Exec Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_system_exec_tool(
    command: Annotated[str, Field(description="System command to execute")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs system commands without executing them

    This is the secure version of the vulnerable system exec tool.
    Commands are logged for audit purposes, not executed.
    """
    result = store_command(command)
    logger.info(f"vulnerable_system_exec_tool (hardened) called with: {command[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Data Query Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_data_leak_tool(
    query: Annotated[str, Field(description="Query for data or information")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Queues data queries without leaking sensitive info

    This is the secure version that handles sensitive data queries safely.
    Queries are processed without exposing environment variables or secrets.
    """
    result = queue_data_query(query)
    logger.info(f"vulnerable_data_leak_tool (hardened) called with: {query[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Tool Override Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_tool_override_tool(
    instruction: Annotated[str, Field(description="Tool creation or modification instruction")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores instructions without allowing tool modification

    This is the secure version of the vulnerable tool override tool.
    Instructions are stored for admin review, not executed.
    """
    result = store_instruction(instruction)
    logger.info(f"vulnerable_tool_override_tool (hardened) called with: {instruction[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Config Modifier Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_config_modifier_tool(
    setting: Annotated[str, Field(description="Configuration setting to modify")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores config requests without modifying runtime settings

    This is the secure version of the vulnerable config modifier tool.
    Settings are stored for review, not applied to runtime configuration.
    """
    result = store_setting(setting)
    logger.info(f"vulnerable_config_modifier_tool (hardened) called with: {setting[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Fetcher Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_fetcher_tool(
    url: Annotated[str, Field(description="URL to fetch content from")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores URLs without fetching external content

    This is the secure version of the vulnerable fetcher tool.
    URLs are stored for validation, not fetched or executed.
    """
    result = store_url(url)
    logger.info(f"vulnerable_fetcher_tool (hardened) called with: {url[:100]}")
    return result


# ============================================================================
# MEDIUM RISK TOOLS - HARDENED (Same names as vulnerable, safe implementations)
# ============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        title="Unicode Processor Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_unicode_processor_tool(
    text: Annotated[str, Field(description="Text with potential unicode encoding")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores text without decoding/executing unicode commands

    This is the secure version of the vulnerable unicode processor tool.
    Text is stored as-is without interpreting unicode escape sequences.
    """
    result = store_text(text)
    logger.info(f"vulnerable_unicode_processor_tool (hardened) called with: {text[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Nested Parser Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_nested_parser_tool(
    data: Annotated[str, Field(description="JSON data with potential nested instructions")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Parses JSON without executing nested instructions

    This is the secure version of the vulnerable nested parser tool.
    JSON is validated but embedded commands are not executed.
    """
    result = parse_json_data(data)
    logger.info(f"vulnerable_nested_parser_tool (hardened) called with: {data[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Package Installer Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_package_installer_tool(
    package: Annotated[str, Field(description="Package name to install")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Validates packages against allowlist, blocks typosquatting

    This is the secure version of the vulnerable package installer tool.
    Packages are validated against an allowlist before any action.
    """
    result = validate_package(package)
    logger.info(f"vulnerable_package_installer_tool (hardened) called with: {package[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Rug Pull Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_rug_pull_tool(
    action: Annotated[str, Field(description="Action to perform")]
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Consistent behavior regardless of invocation count

    This is the secure version of the vulnerable rug pull tool.
    Behavior is consistent and predictable for all invocations.
    """
    result = queue_action(action)
    logger.info(f"vulnerable_rug_pull_tool (hardened) called (invocation: {result.get('invocation_count')})")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Deserializer Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_deserializer_tool(
    data: Annotated[str, Field(description="Serialized data (e.g., base64-encoded pickle)")]
) -> Dict[str, Any]:
    """
    HARDENED: Stores serialized data without deserializing

    This is the secure version of the vulnerable deserializer tool.
    Data is stored safely without calling pickle.loads().
    """
    result = store_serialized_data(data)
    logger.info(f"vulnerable_deserializer_tool (hardened) called with {len(data)} bytes")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Template Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_template_tool(
    template: Annotated[str, Field(description="Template string to render")]
) -> Dict[str, Any]:
    """
    HARDENED: Stores template without rendering

    This is the secure version of the vulnerable template tool.
    Templates are stored safely without calling Jinja2's render().
    """
    result = store_template(template)
    logger.info(f"vulnerable_template_tool (hardened) called with {len(template)} chars")
    return result


# ============================================================================
# SAFE CONTROL TOOLS (Same as vulnerable server - should NOT be flagged)
# ============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Storage Tool",
        destructiveHint=True,
    ),
)
async def safe_storage_tool_mcp(
    data: Annotated[str, Field(description="Data to store")],
    collection: Annotated[str, Field(description="Collection name")] = "default"
) -> Dict[str, Any]:
    """
    ✅ SAFE: Stores data without executing it

    This tool should NOT be flagged as vulnerable.
    It treats all input as pure data.
    """
    result = store_data(data, collection)
    logger.info(f"safe_storage_tool_mcp called with data length: {len(data)}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Search Tool",
        readOnlyHint=True,
    ),
)
async def safe_search_tool_mcp(
    query: Annotated[str, Field(description="Search query")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Searches data without executing queries

    This tool should NOT be flagged as vulnerable.
    It only searches and reflects queries.
    """
    result = search_data(query)
    logger.info(f"safe_search_tool_mcp called with query: {query[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe List Tool",
        readOnlyHint=True,
    ),
)
async def safe_list_tool_mcp(
    resource_type: Annotated[str, Field(description="Type of resource to list")] = "collections"
) -> Dict[str, Any]:
    """
    ✅ SAFE: Lists resources with safe error handling

    This tool should NOT be flagged as vulnerable.
    Error messages reflect input but don't execute.
    """
    result = list_resources(resource_type)
    logger.info(f"safe_list_tool_mcp called for: {resource_type}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Info Tool",
        readOnlyHint=True,
    ),
)
async def safe_info_tool_mcp(
    entity_name: Annotated[str, Field(description="Entity name to get info about")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Gets entity info with safe error reflection

    This tool should NOT be flagged as vulnerable.
    Common pattern: error messages echo back invalid input safely.
    """
    result = get_entity_info(entity_name)
    logger.info(f"safe_info_tool_mcp called for: {entity_name}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Echo Tool",
        readOnlyHint=True,
    ),
)
async def safe_echo_tool_mcp(
    message: Annotated[str, Field(description="Message to echo")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Echoes message as data

    This tool should NOT be flagged as vulnerable.
    Echoes potentially malicious input as data, not execution.
    """
    result = echo_message(message)
    logger.info(f"safe_echo_tool_mcp called with message length: {len(message)}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Validate Tool",
        readOnlyHint=True,
    ),
)
async def safe_validate_tool_mcp(
    input_data: Annotated[str, Field(description="Data to validate")]
) -> Dict[str, Any]:
    """
    ✅ SAFE: Validates input with safe error handling

    This tool should NOT be flagged as vulnerable.
    Validates and rejects malicious patterns without executing them.
    """
    result = validate_input(input_data)
    logger.info(f"safe_validate_tool_mcp called, valid: {result.get('valid')}")
    return result


# ============================================================================
# Server Metadata Tool
# ============================================================================

@mcp.tool(
    annotations=ToolAnnotations(
        title="Reset Testbed State",
        readOnlyHint=False,
        destructiveHint=True,
    ),
)
async def reset_testbed_state() -> Dict[str, Any]:
    """
    Reset all testbed state for clean test runs.

    Clears: invocation_counts, tool_registry, runtime_config, storage
    Use between test runs to ensure consistent baseline.
    """
    reset_config_state()
    reset_safe_storage()
    reset_storage()
    logger.info("Testbed state reset")
    return {
        "result": "Testbed state reset successfully",
        "cleared": ["invocation_counts", "tool_registry", "runtime_config", "safe_storage", "storage"],
        "note": "All stateful tracking has been reset to defaults"
    }


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Testbed Info",
        readOnlyHint=True,
    ),
)
async def get_testbed_info() -> Dict[str, Any]:
    """
    Get information about this hardened testbed server.

    Returns server configuration and security status.
    """
    return {
        "server_name": SERVER_NAME,
        "version": SERVER_VERSION,
        "security_status": "HARDENED",
        "description": "Secure implementation with same tool names as vulnerable server",
        "tool_categories": {
            "high_risk_hardened": 8,
            "medium_risk_hardened": 4,
            "safe_control": 6,
            "info": 1,
            "utility": 1,
            "total": 20
        },
        "security_features": [
            "No eval() or exec() calls",
            "No subprocess execution",
            "No environment variable exposure",
            "No runtime config modification",
            "No external URL fetching",
            "No unicode command decoding",
            "No nested instruction execution",
            "Package allowlist validation",
            "Consistent behavior (no rug pull)",
            "No pickle deserialization",
            "No template rendering (SSTI protection)"
        ],
        "purpose": "A/B comparison testing with vulnerable server"
    }


if __name__ == "__main__":
    import os

    # Get transport mode from environment (default: stdio)
    transport_mode = os.getenv("TRANSPORT", "stdio").lower()

    logger.info(f"Starting {SERVER_NAME} server (HARDENED)...")
    logger.info(f"Transport mode: {transport_mode}")

    if transport_mode == "http" or transport_mode == "streamable-http":
        # HTTP transport using uvicorn
        try:
            import uvicorn
            from config import SERVER_PORT

            host = os.getenv("HOST", "0.0.0.0")
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
        logger.info("Using stdio transport")
        mcp.run(transport="stdio")
