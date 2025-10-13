"""
Business Automation MCP Server

A FastMCP-based server providing business automation tools for data processing,
validation, storage, and workflow management.
"""

import sys
import logging
from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from typing import Annotated
from pydantic import Field

# Import tool implementations
from tools import (
    calculate_expression,
    store_command,
    query_data,
    store_instruction,
    store_setting,
    store_url,
    process_text,
    parse_json_data,
    validate_package,
    execute_action,
    store_data,
    search_data,
    list_resources,
    get_entity_info,
    echo_message,
    validate_input
)
from config import (
    SERVER_NAME,
    SERVER_VERSION
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Create FastMCP server
mcp = FastMCP(SERVER_NAME)

logger.info(f"Initializing {SERVER_NAME} v{SERVER_VERSION}")


# ============================================================================
# Business Logic Tools
# ============================================================================

@mcp.tool()
async def calculate_expression_tool(
    query: Annotated[str, Field(description="Calculator query or math expression")]
) -> Dict[str, Any]:
    """
    Store mathematical expressions and queries for later processing.

    Use this tool to store calculation requests that will be processed
    by the backend computational engine.
    """
    result = calculate_expression(query)
    logger.info(f"calculate_expression called with query length: {len(query)}")
    return result


@mcp.tool()
async def store_command_tool(
    command: Annotated[str, Field(description="System command to store")]
) -> Dict[str, Any]:
    """
    Store system commands for audit logging and compliance tracking.

    Commands are stored for compliance review and audit trail purposes.
    """
    result = store_command(command)
    logger.info(f"store_command called with command length: {len(command)}")
    return result


@mcp.tool()
async def query_data_tool(
    query: Annotated[str, Field(description="Query for data or information")]
) -> Dict[str, Any]:
    """
    Store data queries for processing by backend systems.

    Submit queries that will be processed by the data processing engine.
    """
    result = query_data(query)
    logger.info(f"query_data called with query length: {len(query)}")
    return result


@mcp.tool()
async def store_instruction_tool(
    instruction: Annotated[str, Field(description="Configuration or setup instruction")]
) -> Dict[str, Any]:
    """
    Store configuration instructions for system administrators.

    Instructions are queued for admin review and implementation.
    """
    result = store_instruction(instruction)
    logger.info(f"store_instruction called with instruction length: {len(instruction)}")
    return result


@mcp.tool()
async def store_setting_tool(
    setting: Annotated[str, Field(description="Configuration setting to store")]
) -> Dict[str, Any]:
    """
    Store configuration settings for later application.

    Settings are stored and applied during the next configuration update cycle.
    """
    result = store_setting(setting)
    logger.info(f"store_setting called with setting length: {len(setting)}")
    return result


@mcp.tool()
async def store_url_tool(
    url: Annotated[str, Field(description="URL to store for processing")]
) -> Dict[str, Any]:
    """
    Store URLs for content processing and validation.

    URLs are queued for content fetching and validation workflows.
    """
    result = store_url(url)
    logger.info(f"store_url called with URL: {url[:50]}...")
    return result


@mcp.tool()
async def process_text_tool(
    text: Annotated[str, Field(description="Text with potential encoding")]
) -> Dict[str, Any]:
    """
    Process and store text content for analysis.

    Text is processed for language detection, sentiment analysis, and storage.
    """
    result = process_text(text)
    logger.info(f"process_text called with text length: {len(text)}")
    return result


@mcp.tool()
async def parse_json_data_tool(
    data: Annotated[str, Field(description="JSON data to parse")]
) -> Dict[str, Any]:
    """
    Parse and validate JSON data structures.

    Validates JSON format and extracts field information for processing.
    """
    result = parse_json_data(data)
    logger.info(f"parse_json_data called with data length: {len(data)}")
    return result


@mcp.tool()
async def validate_package_tool(
    package: Annotated[str, Field(description="Package name to validate")]
) -> Dict[str, Any]:
    """
    Validate package names against approved package repository.

    Checks package names against allowlist and blocklist before processing.
    """
    result = validate_package(package)
    logger.info(f"validate_package called for: {package}")
    return result


@mcp.tool()
async def execute_action_tool(
    action: Annotated[str, Field(description="Action to perform")]
) -> Dict[str, Any]:
    """
    Execute business automation action workflows.

    Triggers predefined automation workflows based on action identifier.
    """
    result = execute_action(action)
    logger.info(f"execute_action called with action: {action[:50]}...")
    return result


# ============================================================================
# Data Management Tools
# ============================================================================

@mcp.tool()
async def store_data_tool(
    data: Annotated[str, Field(description="Data to store")],
    collection: Annotated[str, Field(description="Collection name")] = "default"
) -> Dict[str, Any]:
    """
    Store data in specified collection for later retrieval.

    Data is stored in memory-based collections for fast access.
    """
    result = store_data(data, collection)
    logger.info(f"store_data called with data length: {len(data)}")
    return result


@mcp.tool()
async def search_data_tool(
    query: Annotated[str, Field(description="Search query")]
) -> Dict[str, Any]:
    """
    Search stored data across all collections.

    Performs full-text search across all stored data collections.
    """
    result = search_data(query)
    logger.info(f"search_data called with query: {query[:100]}")
    return result


@mcp.tool()
async def list_resources_tool(
    resource_type: Annotated[str, Field(description="Type of resource to list")] = "collections"
) -> Dict[str, Any]:
    """
    List available resources of specified type.

    Returns information about available collections, items, or users.
    """
    result = list_resources(resource_type)
    logger.info(f"list_resources called for: {resource_type}")
    return result


@mcp.tool()
async def get_entity_info_tool(
    entity_name: Annotated[str, Field(description="Entity name to get info about")]
) -> Dict[str, Any]:
    """
    Retrieve information about a specific entity.

    Returns metadata and statistics for the specified entity.
    """
    result = get_entity_info(entity_name)
    logger.info(f"get_entity_info called for: {entity_name}")
    return result


@mcp.tool()
async def echo_message_tool(
    message: Annotated[str, Field(description="Message to echo")]
) -> Dict[str, Any]:
    """
    Echo message back to caller with metadata.

    Simple echo utility for testing connectivity and message formatting.
    """
    result = echo_message(message)
    logger.info(f"echo_message called with message length: {len(message)}")
    return result


@mcp.tool()
async def validate_input_tool(
    input_data: Annotated[str, Field(description="Data to validate")]
) -> Dict[str, Any]:
    """
    Validate input data against security and format rules.

    Performs security checks and format validation on input data.
    """
    result = validate_input(input_data)
    logger.info(f"validate_input called, valid: {result.get('valid')}")
    return result


# ============================================================================
# Server Metadata
# ============================================================================

@mcp.tool()
async def get_server_info() -> Dict[str, Any]:
    """
    Get information about this MCP server.

    Returns server configuration, version, and available tool categories.
    """
    return {
        "server_name": SERVER_NAME,
        "version": SERVER_VERSION,
        "description": "Business automation MCP server with data processing and workflow tools",
        "tool_categories": {
            "business_logic": 10,
            "data_management": 6,
            "total": 16
        },
        "capabilities": [
            "Mathematical expression storage",
            "Command audit logging",
            "Data query processing",
            "Configuration management",
            "URL content processing",
            "Text analysis",
            "JSON parsing",
            "Package validation",
            "Workflow automation",
            "Data storage and retrieval",
            "Full-text search",
            "Resource management",
            "Input validation"
        ],
        "status": "operational"
    }


if __name__ == "__main__":
    import os

    # Get transport mode from environment (default: stdio)
    transport_mode = os.getenv("TRANSPORT", "stdio").lower()

    logger.info(f"Starting {SERVER_NAME} server...")
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
