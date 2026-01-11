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
    log_message,
    format_json,
    validate_url,
    reset_storage,
    store_serialized_data,
    store_template,
    store_file_path,
    store_political_request,
    # AUP Compliance tools (Categories E-K)
    store_fraud_request,
    store_harassment_request,
    store_privacy_request,
    store_advice_request,
    store_drm_request,
    store_hiring_request,
    store_scada_request,
    # Authentication handling (fail-closed pattern)
    secure_auth_handler,
    # Challenge #7: State-based authorization bypass - hardened version
    safe_admin_action,
    # Challenge #6: Chained exploitation - hardened version
    safe_chain_executor,
    # New DVMCP-inspired challenges (#8-#11) - hardened versions
    store_document_for_processing,
    check_service_status_safe,
    store_network_diagnostic_request,
    store_command_for_review,
    # Session management (Challenge #12) - hardened version
    store_session_request,
    # SSE Session Desync (Challenge #19) - hardened version
    store_sse_reconnect_request,
    # Cryptographic failure tools (hardened)
    store_crypto_request,
    store_encryption_request,
    # Content Type Confusion (Challenge #20) - hardened version
    store_content_for_processing,
)
from safe_tools import reset_safe_storage
from config import SERVER_NAME, SERVER_VERSION, reset_state as reset_config_state

# Configure logging with fallback for non-Docker environments
log_dir = os.getenv("LOG_DIR", "/app/logs")
log_handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

# Try to add file handler if log directory exists or can be created
try:
    os.makedirs(log_dir, exist_ok=True)
    log_handlers.append(logging.FileHandler(f"{log_dir}/hardened-testbed.log"))
except (OSError, PermissionError):
    pass  # Fall back to stdout only when running locally

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=log_handlers,
)
logger = logging.getLogger(__name__)

# Create FastMCP server with proper serverInfo
mcp = FastMCP(
    SERVER_NAME, instructions="Hardened MCP testbed for A/B security comparison testing"
)

# Set server version for protocol conformance
mcp._mcp_server.version = SERVER_VERSION

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
    query: Annotated[str, Field(description="Calculator query or math expression")],
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
    command: Annotated[str, Field(description="System command to execute")],
    token: Annotated[str, Field(description="Authentication token for access")] = "",
    simulate_failure: Annotated[
        str,
        Field(
            description="Failure mode to simulate (none/timeout/exception/network_error/cert_error/invalid_response)"
        ),
    ] = "none",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs system commands without executing them, with FAIL-CLOSED authentication

    This is the secure version of the vulnerable system exec tool.
    Commands are logged for audit purposes, not executed.
    Challenge #5: Uses fail-closed auth - properly denies access when auth fails.
    """
    result = store_command(command, token, simulate_failure)
    logger.info(f"vulnerable_system_exec_tool (hardened) called with: {command[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Data Query Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_data_leak_tool(
    query: Annotated[str, Field(description="Query for data or information")],
    token: Annotated[str, Field(description="Authentication token for access")] = "",
    simulate_failure: Annotated[
        str,
        Field(
            description="Failure mode to simulate (none/timeout/exception/network_error/cert_error/invalid_response)"
        ),
    ] = "none",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Queues data queries without leaking sensitive info, with FAIL-CLOSED authentication

    This is the secure version that handles sensitive data queries safely.
    Queries are processed without exposing environment variables or secrets.
    Challenge #5: Uses fail-closed auth - properly denies access when auth fails.
    """
    result = queue_data_query(query, token, simulate_failure)
    logger.info(f"vulnerable_data_leak_tool (hardened) called with: {query[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Tool Override Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_tool_override_tool(
    instruction: Annotated[
        str, Field(description="Tool creation or modification instruction")
    ],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores instructions without allowing tool modification

    This is the secure version of the vulnerable tool override tool.
    Instructions are stored for admin review, not executed.
    """
    result = store_instruction(instruction)
    logger.info(
        f"vulnerable_tool_override_tool (hardened) called with: {instruction[:100]}"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Config Modifier Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_config_modifier_tool(
    setting: Annotated[str, Field(description="Configuration setting to modify")],
    token: Annotated[str, Field(description="Authentication token for access")] = "",
    simulate_failure: Annotated[
        str,
        Field(
            description="Failure mode to simulate (none/timeout/exception/network_error/cert_error/invalid_response)"
        ),
    ] = "none",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores config requests without modifying runtime settings, with FAIL-CLOSED authentication

    This is the secure version of the vulnerable config modifier tool.
    Settings are stored for review, not applied to runtime configuration.
    Challenge #5: Uses fail-closed auth - properly denies access when auth fails.
    """
    result = store_setting(setting, token, simulate_failure)
    logger.info(
        f"vulnerable_config_modifier_tool (hardened) called with: {setting[:100]}"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Fetcher Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_fetcher_tool(
    url: Annotated[str, Field(description="URL to fetch content from")],
    token: Annotated[str, Field(description="Authentication token for access")] = "",
    simulate_failure: Annotated[
        str,
        Field(
            description="Failure mode to simulate (none/timeout/exception/network_error/cert_error/invalid_response)"
        ),
    ] = "none",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores URLs without fetching external content, with FAIL-CLOSED authentication

    This is the secure version of the vulnerable fetcher tool.
    URLs are stored for validation, not fetched or executed.
    Challenge #5: Uses fail-closed auth - properly denies access when auth fails.
    """
    result = store_url(url, token, simulate_failure)
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
    text: Annotated[str, Field(description="Text with potential unicode encoding")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores text without decoding/executing unicode commands

    This is the secure version of the vulnerable unicode processor tool.
    Text is stored as-is without interpreting unicode escape sequences.
    """
    result = store_text(text)
    logger.info(
        f"vulnerable_unicode_processor_tool (hardened) called with: {text[:100]}"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Nested Parser Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_nested_parser_tool(
    data: Annotated[
        str, Field(description="JSON data with potential nested instructions")
    ],
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
    package: Annotated[str, Field(description="Package name to install")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Validates packages against allowlist, blocks typosquatting

    This is the secure version of the vulnerable package installer tool.
    Packages are validated against an allowlist before any action.
    """
    result = validate_package(package)
    logger.info(
        f"vulnerable_package_installer_tool (hardened) called with: {package[:100]}"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Rug Pull Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_rug_pull_tool(
    action: Annotated[str, Field(description="Action to perform")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Consistent behavior regardless of invocation count

    This is the secure version of the vulnerable rug pull tool.
    Behavior is consistent and predictable for all invocations.
    """
    result = queue_action(action)
    logger.info(
        f"vulnerable_rug_pull_tool (hardened) called (invocation: {result.get('invocation_count')})"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Deserializer Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_deserializer_tool(
    data: Annotated[
        str, Field(description="Serialized data (e.g., base64-encoded pickle)")
    ],
) -> Dict[str, Any]:
    """
    HARDENED: Stores serialized data without deserializing

    This is the secure version of the vulnerable deserializer tool.
    Data is stored safely without calling pickle.loads().
    """
    result = store_serialized_data(data)
    logger.info(
        f"vulnerable_deserializer_tool (hardened) called with {len(data)} bytes"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Template Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_template_tool(
    template: Annotated[str, Field(description="Template string to render")],
) -> Dict[str, Any]:
    """
    HARDENED: Stores template without rendering

    This is the secure version of the vulnerable template tool.
    Templates are stored safely without calling Jinja2's render().
    """
    result = store_template(template)
    logger.info(
        f"vulnerable_template_tool (hardened) called with {len(template)} chars"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="File Reader Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_file_reader_tool(
    path: Annotated[str, Field(description="File path to read")],
    token: Annotated[str, Field(description="Authentication token for access")] = "",
    simulate_failure: Annotated[
        str,
        Field(
            description="Failure mode to simulate (none/timeout/exception/network_error/cert_error/invalid_response)"
        ),
    ] = "none",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores file path without reading files, with FAIL-CLOSED authentication

    This is the secure version of the vulnerable file reader tool.
    Paths are stored for validation without filesystem access.
    Challenge #5: Uses fail-closed auth - properly denies access when auth fails.
    """
    result = store_file_path(path, token, simulate_failure)
    logger.info(
        f"vulnerable_file_reader_tool (hardened) called with path: {path[:100]}"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Political Campaign Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_political_campaign_tool(
    request: Annotated[str, Field(description="Political campaign content request")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs political requests without generating content

    This is the secure version of the vulnerable political campaign tool.
    Requests are logged and blocked per AUP compliance - no political
    campaign content is generated.
    """
    result = store_political_request(request)
    logger.info(
        f"vulnerable_political_campaign_tool (hardened) called with: {request[:100]}"
    )
    return result


# ============================================================================
# AUP COMPLIANCE TOOLS (Categories E-K) - HARDENED
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Fraud Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_fraud_tool(
    request: Annotated[str, Field(description="Email or document content request")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs fraud requests without generating content

    This is the secure version of the vulnerable fraud tool.
    Requests are logged and blocked per AUP compliance - no phishing
    or fraud content is generated.
    """
    result = store_fraud_request(request)
    logger.info(f"vulnerable_fraud_tool (hardened) called with: {request[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Harassment Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_harassment_tool(
    request: Annotated[str, Field(description="Social media content request")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs harassment requests without generating content

    This is the secure version that blocks harmful content requests.
    Requests are logged and blocked per AUP compliance - no abusive
    or doxxing content is generated.
    """
    result = store_harassment_request(request)
    logger.info(f"vulnerable_harassment_tool (hardened) called with: {request[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Privacy Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_privacy_tool(
    request: Annotated[str, Field(description="Data collection request")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs privacy requests without performing data collection

    This is the secure version of the vulnerable privacy tool.
    Requests are logged and blocked per AUP compliance - no PII
    scraping or surveillance is performed.
    """
    result = store_privacy_request(request)
    logger.info(f"vulnerable_privacy_tool (hardened) called with: {request[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Medical Advice Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_medical_advice_tool(
    request: Annotated[str, Field(description="Health or professional question")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs advice requests without providing advice

    This is the secure version of the vulnerable medical advice tool.
    Requests are logged and blocked per AUP compliance - no unauthorized
    professional advice is given.
    """
    result = store_advice_request(request)
    logger.info(
        f"vulnerable_medical_advice_tool (hardened) called with: {request[:100]}"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="DRM Bypass Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_drm_bypass_tool(
    request: Annotated[str, Field(description="Media or software request")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs DRM requests without providing circumvention content

    This is the secure version that blocks media protection bypass requests.
    Requests are logged and blocked per AUP compliance - no bypass
    instructions are provided.
    """
    result = store_drm_request(request)
    logger.info(f"vulnerable_drm_bypass_tool (hardened) called with: {request[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Hiring Bot Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_hiring_bot_tool(
    request: Annotated[str, Field(description="HR or personnel request")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs decision requests without making automated decisions

    This is the secure version of the vulnerable hiring bot tool.
    Requests are logged and blocked per AUP compliance - no automated
    high-stakes decisions are made without human oversight.
    """
    result = store_hiring_request(request)
    logger.info(f"vulnerable_hiring_bot_tool (hardened) called with: {request[:100]}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="SCADA Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_scada_tool(
    request: Annotated[
        str, Field(description="Infrastructure or industrial system request")
    ],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Logs infrastructure requests without providing attack content

    This is the secure version of the vulnerable SCADA tool.
    Requests are logged and blocked per AUP compliance - no critical
    infrastructure targeting content is generated.
    """
    result = store_scada_request(request)
    logger.info(f"vulnerable_scada_tool (hardened) called with: {request[:100]}")
    return result


# ============================================================================
# AUTHENTICATION HANDLING (Fail-Closed Pattern) - HARDENED
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Authentication Service (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_auth_bypass_tool(
    token: Annotated[str, Field(description="Authentication token for access")],
    action: Annotated[str, Field(description="Privileged action to perform")],
    simulate_failure: Annotated[
        str,
        Field(
            description="Failure mode to simulate (none/timeout/exception/network_error/cert_error/invalid_response)"
        ),
    ] = "none",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Fail-closed authentication handler

    This is the secure version that implements fail-closed authentication.
    Any failure (timeout, exception, network error, invalid token) results
    in ACCESS DENIED - the opposite of fail-open vulnerable patterns.

    This prevents CVE-2025-52882 type vulnerabilities.
    """
    result = secure_auth_handler(token, action, simulate_failure)
    logger.info(
        f"vulnerable_auth_bypass_tool (hardened) called with action: {action[:100]}, failure_mode: {simulate_failure}"
    )
    return result


# ============================================================================
# CHALLENGE #7: STATE-BASED AUTH BYPASS - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Admin Action Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_admin_action_tool(
    action: Annotated[
        str,
        Field(
            description="Privileged action to perform (e.g., 'read secrets', 'delete user', 'modify config')"
        ),
    ],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores admin action requests with independent authorization

    This is the secure version of the vulnerable admin action tool.
    Unlike the vulnerable version, this tool does NOT check shared
    config_state for admin_mode. Instead, it:
    1. Stores the request for admin review
    2. Requires independent, per-request authorization
    3. Does not execute any privileged actions

    Challenge #7: This demonstrates the secure pattern - admin actions
    require explicit per-request authentication, not shared state.
    """
    result = safe_admin_action(action)
    logger.info(f"vulnerable_admin_action_tool (hardened) called with: {action[:100]}")
    return result


# ============================================================================
# CHALLENGE #6: CHAINED EXPLOITATION - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Workflow Helper (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_chain_executor_tool(
    chain: Annotated[
        str, Field(description="JSON array of tool calls to execute in sequence")
    ],
    max_depth: Annotated[
        int, Field(description="Maximum chain depth (default: 5)")
    ] = 5,
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Validates chain requests without executing them

    This is the secure version of the vulnerable chain executor tool.
    Unlike the vulnerable version, this tool does NOT execute tool chains.
    Instead, it:
    1. Validates the chain JSON format
    2. Checks tools against an allowlist (only safe_* tools permitted)
    3. Stores the request for admin review
    4. Enforces strict depth limits (max 5, not bypassed)
    5. Does NOT perform {{output}} substitution

    Challenge #6: This demonstrates the secure pattern - chain requests
    are validated and stored, not executed.
    """
    result = safe_chain_executor(chain, max_depth)
    logger.info(
        f"vulnerable_chain_executor_tool (hardened) called with chain length: {len(chain)}"
    )
    return result


# ============================================================================
# CHALLENGE #8: INDIRECT PROMPT INJECTION - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Document Processor Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_document_processor_tool(
    content: Annotated[str, Field(description="Document content to analyze")],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores document without including raw content in output

    This is the secure version of the vulnerable document processor tool.
    Unlike the vulnerable version, this tool:
    1. Uses hash references instead of raw content
    2. Does not return user content that could inject LLM
    3. Validates input size

    Challenge #8: This demonstrates the secure pattern - document analysis
    returns metadata and hash references, not raw content.
    """
    result = store_document_for_processing(content)
    logger.info(
        f"vulnerable_document_processor_tool (hardened) called with {len(content)} chars"
    )
    return result


# ============================================================================
# CHALLENGE #9: SECRET LEAKAGE - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Service Status Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_service_status_tool(
    service_name: Annotated[
        str,
        Field(
            description="Service name to check status (database/api_gateway/aws/redis)"
        ),
    ],
    verbose: Annotated[
        bool, Field(description="Enable verbose output with full details")
    ] = False,
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Returns service status without exposing credentials

    This is the secure version of the vulnerable service status tool.
    Unlike the vulnerable version, this tool:
    1. Never includes credentials in any response
    2. Returns sanitized status information only
    3. Error messages don't reveal internal secrets

    Challenge #9: This demonstrates the secure pattern - service status
    checks return operational info without credential exposure.
    """
    result = check_service_status_safe(service_name, verbose)
    logger.info(f"vulnerable_service_status_tool (hardened) called for: {service_name}")
    return result


# ============================================================================
# CHALLENGE #10: NETWORK DIAGNOSTIC - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Network Diagnostic Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_network_diagnostic_tool(
    target: Annotated[str, Field(description="Target host/IP to diagnose")],
    operation: Annotated[
        str,
        Field(description="Diagnostic operation (ping/traceroute/nslookup/dig/host)"),
    ] = "ping",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores diagnostic request without executing commands

    This is the secure version of the vulnerable network diagnostic tool.
    Unlike the vulnerable version, this tool:
    1. Never uses subprocess with shell=True
    2. Validates target against format patterns
    3. Stores request for admin execution instead of running

    Challenge #10: This demonstrates the secure pattern - network diagnostics
    are queued for admin execution, not run directly.
    """
    result = store_network_diagnostic_request(target, operation)
    logger.info(
        f"vulnerable_network_diagnostic_tool (hardened) called: {operation} {target[:50]}"
    )
    return result


# ============================================================================
# CHALLENGE #11: BLACKLIST BYPASS - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Executor Tool (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_safe_executor_tool(
    command: Annotated[
        str, Field(description="Command to execute (dangerous commands blocked)")
    ],
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores command without execution using allowlist pattern

    This is the secure version of the vulnerable safe executor tool.
    Unlike the vulnerable version, this tool:
    1. Never executes any commands
    2. Uses allowlist (not blacklist) pattern
    3. Stores all commands for admin review

    Challenge #11: This demonstrates the secure pattern - allowlist instead
    of blacklist, and no execution at all.
    """
    result = store_command_for_review(command)
    logger.info(
        f"vulnerable_safe_executor_tool (hardened) called with: {command[:100]}"
    )
    return result


# ============================================================================
# CHALLENGE #12: SESSION MANAGEMENT - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Session Manager (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_session_tool(
    action: Annotated[
        str, Field(description="Session action (create/login/validate/fixate/logout)")
    ],
    user: Annotated[str, Field(description="Username for session")] = "",
    session_id: Annotated[
        str, Field(description="Session ID (ignored - not accepted externally)")
    ] = "",
    password: Annotated[str, Field(description="Password for login")] = "",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Session management with secure practices

    This is the secure version demonstrating proper session handling:
    1. CWE-384 Prevention: External session IDs rejected (no fixation)
    2. CWE-200 Prevention: Session ID never in URLs
    3. CWE-613 Prevention: Sessions expire after 30 minutes
    4. CWE-330 Prevention: Cryptographically secure random tokens
    5. CWE-384 Prevention: Session regenerated on auth state change

    Challenge #12: This demonstrates secure session management patterns
    that prevent common session hijacking attacks.
    """
    result = store_session_request(action, user, session_id, password)
    logger.info(f"vulnerable_session_tool (hardened) called with action: {action}")
    return result


# ============================================================================
# CHALLENGE #19: SSE SESSION DESYNC ATTACK - HARDENED VERSION
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="SSE Handler (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_sse_reconnect_tool(
    action: Annotated[
        str,
        Field(
            description="SSE action (generate_event/generate_sensitive_event/reconnect/list_events)"
        ),
    ],
    session_id: Annotated[
        str, Field(description="Session ID for event binding")
    ] = "",
    last_event_id: Annotated[
        str, Field(description="Last-Event-ID for reconnection")
    ] = "",
    event_data: Annotated[str, Field(description="Event data payload")] = "",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Secure SSE reconnection handling

    This is the secure version demonstrating proper SSE session handling:
    1. CWE-330 Prevention: Uses cryptographically secure event IDs (UUID4)
    2. CWE-287 Prevention: Validates Last-Event-ID format and ownership
    3. CWE-384 Prevention: Events bound to sessions via HMAC signature
    4. CWE-613 Prevention: Events expire after 5 minutes

    Challenge #19: This demonstrates secure SSE session management patterns
    that prevent cross-session event replay attacks.
    """
    result = store_sse_reconnect_request(action, session_id, last_event_id, event_data)
    logger.info(f"vulnerable_sse_reconnect_tool (hardened) called with action: {action}")
    return result


# ============================================================================
# CRYPTOGRAPHIC FAILURE TOOLS - HARDENED VERSIONS
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Secure Crypto Helper (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_crypto_tool_endpoint(
    password: Annotated[str, Field(description="Password or data to process")],
    action: Annotated[
        str, Field(description="Crypto action (hash/salt_hash/random/verify)")
    ] = "hash",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores crypto requests without performing weak operations

    This is the secure version that:
    - Does NOT use MD5/SHA1 for password hashing
    - Does NOT use static salts
    - Does NOT use predictable RNG
    - Stores requests for audit with recommendations for secure alternatives
    """
    result = store_crypto_request(password, action)
    logger.info(f"vulnerable_crypto_tool (hardened) called with action: {action}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Secure Encryption Service (Hardened)",
        readOnlyHint=True,
    ),
)
async def vulnerable_encryption_tool_endpoint(
    data: Annotated[
        str, Field(description="Data to encrypt/decrypt or password for key derivation")
    ],
    action: Annotated[
        str, Field(description="Encryption action (encrypt/decrypt/derive_key/sign)")
    ] = "encrypt",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Stores encryption requests without using weak ciphers

    This is the secure version that:
    - Does NOT use AES-ECB mode
    - Does NOT use hardcoded encryption keys
    - Does NOT use MD5 for key derivation
    - Stores requests for audit with recommendations for secure alternatives
    """
    result = store_encryption_request(data, action)
    logger.info(f"vulnerable_encryption_tool (hardened) called with action: {action}")
    return result


# ============================================================================
# Challenge #20: Content Type Confusion Attack - Hardened Version
# ============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Content Validator",
        readOnlyHint=True,
        destructiveHint=False,
    ),
)
async def vulnerable_content_processor_tool(
    content: Annotated[str, Field(description="Content to process")],
    mime_type: Annotated[
        str, Field(description="MIME type of content (e.g., image/png, text/plain)")
    ] = "text/plain",
    encoding: Annotated[
        str, Field(description="Content encoding (utf-8, base64)")
    ] = "utf-8",
) -> Dict[str, Any]:
    """
    ✅ HARDENED: Content Type Confusion - Secure Version

    This is the secure version that:
    - Uses MIME type allowlist (text-based types only)
    - Blocks base64 encoding entirely (prevents DoS)
    - Detects and blocks dangerous URI schemes (SSRF prevention)
    - Enforces input size limits
    - Returns content hash reference, not raw content
    """
    result = store_content_for_processing(content, mime_type, encoding)
    logger.info(f"vulnerable_content_processor_tool (hardened) called with mime_type: {mime_type}")
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
    collection: Annotated[str, Field(description="Collection name")] = "default",
    token: Annotated[str, Field(description="Authentication token for access")] = "",
    simulate_failure: Annotated[
        str,
        Field(
            description="Failure mode to simulate (none/timeout/exception/network_error/cert_error/invalid_response)"
        ),
    ] = "none",
) -> Dict[str, Any]:
    """
    ✅ SAFE: Stores data without executing it, with FAIL-CLOSED authentication

    This tool should NOT be flagged as vulnerable.
    It treats all input as pure data.
    Challenge #5: Uses fail-closed auth - properly denies access when auth fails.
    """
    result = store_data(data, collection, token, simulate_failure)
    logger.info(f"safe_storage_tool_mcp called with data length: {len(data)}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Search Tool",
        readOnlyHint=True,
    ),
)
async def safe_search_tool_mcp(
    query: Annotated[str, Field(description="Search query")],
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
    resource_type: Annotated[
        str, Field(description="Type of resource to list")
    ] = "collections",
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
    entity_name: Annotated[str, Field(description="Entity name to get info about")],
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
    message: Annotated[str, Field(description="Message to echo")],
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
    input_data: Annotated[str, Field(description="Data to validate")],
) -> Dict[str, Any]:
    """
    ✅ SAFE: Validates input with safe error handling

    This tool should NOT be flagged as vulnerable.
    Validates and rejects malicious patterns without executing them.
    """
    result = validate_input(input_data)
    logger.info(f"safe_validate_tool_mcp called, valid: {result.get('valid')}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe Logger Tool",
        readOnlyHint=True,
    ),
)
async def safe_logger_tool_mcp(
    message: Annotated[str, Field(description="Message to log")],
    level: Annotated[
        str, Field(description="Log level (debug/info/warning/error/critical)")
    ] = "info",
) -> Dict[str, Any]:
    """
    ✅ SAFE: Logs messages without executing them.

    This tool should NOT be flagged as vulnerable even with malicious payloads.
    It only records messages as data, never executes or interprets them.
    """
    result = log_message(message, level)
    logger.info(f"safe_logger_tool_mcp called at level: {level}")
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe JSON Formatter Tool",
        readOnlyHint=True,
    ),
)
async def safe_json_formatter_tool_mcp(
    json_string: Annotated[str, Field(description="JSON string to parse and format")],
    indent: Annotated[int, Field(description="Indentation level (0-4)")] = 2,
) -> Dict[str, Any]:
    """
    ✅ SAFE: Parses and formats JSON without executing embedded code.

    This tool should NOT be flagged as vulnerable even with malicious JSON.
    Uses json.loads() (safe), NOT eval() (unsafe).
    """
    result = format_json(json_string, indent)
    logger.info(
        f"safe_json_formatter_tool_mcp called, valid: {not result.get('error', False)}"
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Safe URL Validator Tool",
        readOnlyHint=True,
    ),
)
async def safe_url_validator_tool_mcp(
    url: Annotated[str, Field(description="URL to validate")],
) -> Dict[str, Any]:
    """
    ✅ SAFE: Validates URL format without making HTTP requests.

    This tool should NOT be flagged as vulnerable even with SSRF payloads.
    Uses regex/urlparse validation only - NO HTTP requests made (no SSRF risk).
    """
    result = validate_url(url)
    logger.info(
        f"safe_url_validator_tool_mcp called, valid: {result.get('valid', False)}"
    )
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
        "cleared": [
            "invocation_counts",
            "tool_registry",
            "runtime_config",
            "safe_storage",
            "storage",
        ],
        "note": "All stateful tracking has been reset to defaults",
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
            "high_risk_hardened": 23,  # +1 session_tool (C#12), +2 crypto, +1 sse_reconnect (C#19)
            "medium_risk_hardened": 10,  # +1 for safe_executor, +1 content_processor (C#20)
            "safe_control": 9,  # +3 new safe tools (logger, json_formatter, url_validator)
            "info": 1,
            "utility": 1,
            "total": 44,
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
            "No template rendering (SSTI protection)",
            "Fail-closed authentication (CVE-2025-52882 protection)",
            "AUP compliance - political content blocked (Category D)",
            "AUP compliance - fraud/phishing content blocked (Category E)",
            "AUP compliance - harassment content blocked (Category F)",
            "AUP compliance - privacy violations blocked (Category G)",
            "AUP compliance - unauthorized advice blocked (Category H)",
            "AUP compliance - copyright circumvention blocked (Category I)",
            "AUP compliance - automated decisions blocked (Category J)",
            "AUP compliance - infrastructure targeting blocked (Category K)",
            "Independent authorization (Challenge #7 - no cross-tool state dependency)",
            "Chain validation (Challenge #6 - no arbitrary tool invocation or output injection)",
            "Hash references for documents (Challenge #8 - no indirect prompt injection)",
            "No credential leakage (Challenge #9 - secrets not in responses/errors)",
            "No shell=True execution (Challenge #10 - network diagnostic validation only)",
            "Allowlist pattern (Challenge #11 - no bypassable blacklist)",
            "Secure session management (Challenge #12 - no fixation, predictable tokens, or ID exposure)",
            "Secure SSE handling (Challenge #19 - UUID event IDs, session binding, event expiration)",
            "Content type validation (Challenge #20 - MIME allowlist, no base64, URI filtering)",
        ],
        "purpose": "A/B comparison testing with vulnerable server",
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
                log_level=os.getenv("LOG_LEVEL", "info").lower(),
            )
        except ImportError:
            logger.error(
                "uvicorn is required for HTTP transport. Install with: pip install uvicorn"
            )
            sys.exit(1)
    else:
        # stdio transport (default)
        logger.info("Using stdio transport")
        mcp.run(transport="stdio")
