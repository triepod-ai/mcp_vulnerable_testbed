"""
Response Factory for MCP Testbed

Provides standardized response structures for consistent tool outputs.
This enables reliable parsing by MCP Inspector and other assessment tools.
"""

from typing import Dict, Any, Optional


def create_response(
    result: str,
    *,
    vulnerable: bool = False,
    evidence: Optional[str] = None,
    safe: bool = False,
    note: Optional[str] = None,
    **extra_fields,
) -> Dict[str, Any]:
    """
    Create standardized tool response.

    Args:
        result: Primary result message
        vulnerable: True if vulnerability was triggered
        evidence: Evidence of vulnerability exploitation (required if vulnerable=True)
        safe: True if this is a safe tool response
        note: Additional context note
        **extra_fields: Any additional fields to include

    Returns:
        Standardized response dictionary

    Examples:
        # Vulnerable tool triggered
        create_response(
            "Executed: 2+2 = 4",
            vulnerable=True,
            evidence="eval() executed user input"
        )

        # Safe tool response
        create_response(
            "Stored data successfully",
            safe=True,
            note="Data stored without execution"
        )

        # With extra fields
        create_response(
            "Fetched URL",
            vulnerable=True,
            evidence="SSRF to internal network",
            status_code=200,
            content_length=1234
        )
    """
    response: Dict[str, Any] = {"result": result}

    if vulnerable:
        response["vulnerable"] = True
        if evidence:
            response["evidence"] = evidence
    elif safe:
        response["safe"] = True
        response["vulnerable"] = False
        if note:
            response["note"] = note
    else:
        response["vulnerable"] = False

    # Add any extra fields
    response.update(extra_fields)

    return response


def create_vulnerable_response(
    result: str, evidence: str, **extra_fields
) -> Dict[str, Any]:
    """
    Shorthand for creating a vulnerable tool response.

    Args:
        result: What the tool did
        evidence: Proof of vulnerability exploitation
        **extra_fields: Additional context

    Returns:
        Response with vulnerable=True
    """
    return create_response(result, vulnerable=True, evidence=evidence, **extra_fields)


def create_safe_response(
    result: str, note: Optional[str] = None, **extra_fields
) -> Dict[str, Any]:
    """
    Shorthand for creating a safe tool response.

    Args:
        result: What the tool did
        note: Safety note
        **extra_fields: Additional context

    Returns:
        Response with safe=True, vulnerable=False
    """
    return create_response(result, safe=True, note=note, **extra_fields)
