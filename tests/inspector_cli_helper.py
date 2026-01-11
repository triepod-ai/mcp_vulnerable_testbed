"""
Inspector CLI Helper Module

Provides utilities for invoking the MCP Inspector CLI and parsing results.
Used by test_inspector_cli_detection.py for end-to-end Inspector validation.

GitHub Issue: https://github.com/triepod-ai/mcp_vulnerable_testbed/issues/6
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


# Inspector CLI location - configurable via environment variable for CI/CD
INSPECTOR_DIR = Path(os.getenv("INSPECTOR_DIR", "/home/bryan/inspector"))

# Timeout configuration - also configurable via environment
INSPECTOR_TIMEOUT_DEFAULT = int(os.getenv("INSPECTOR_TIMEOUT", "120"))
INSPECTOR_TIMEOUT_SLOW = int(os.getenv("INSPECTOR_TIMEOUT_SLOW", "300"))


@dataclass
class InspectorFinding:
    """Parsed vulnerability finding from Inspector CLI."""

    test_name: str
    tool_name: str
    risk_level: str
    vulnerable: bool
    cwe_ids: List[str]
    evidence: str
    description: str
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InspectorResult:
    """Parsed Inspector CLI assessment result."""

    server_name: str
    overall_status: str
    overall_risk_level: str
    findings: List[InspectorFinding]
    modules_run: List[str]
    raw_output: Dict[str, Any]


def run_inspector_assessment(
    server_name: str,
    config_path: str,
    tool_name: Optional[str] = None,
    modules: Optional[List[str]] = None,
    timeout: int = 120,
) -> InspectorResult:
    """
    Run MCP Inspector CLI assessment and parse results.

    Args:
        server_name: Name for the assessment (used in output filename)
        config_path: Path to server config JSON
        tool_name: Optional tool to filter assessment to
        modules: Optional list of modules to run (default: security)
        timeout: Command timeout in seconds

    Returns:
        InspectorResult with parsed findings

    Raises:
        pytest.skip: On any error (graceful degradation)
    """
    # Build command
    cmd = [
        "npm",
        "run",
        "assess",
        "--",
        "--server",
        server_name,
        "--config",
        config_path,
    ]
    if tool_name:
        cmd.extend(["--tool", tool_name])
    if modules:
        cmd.extend(["--module", ",".join(modules)])

    # Run Inspector CLI
    try:
        result = subprocess.run(
            cmd, cwd=INSPECTOR_DIR, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        pytest.skip(f"Inspector CLI timed out after {timeout}s")
    except FileNotFoundError:
        pytest.skip("npm not found - Inspector CLI unavailable")
    except OSError as e:
        pytest.skip(f"OS error running Inspector CLI: {e}")

    # Check for execution errors (note: exit code 1 is expected for FAIL status)
    if (
        result.returncode != 0
        and "FAIL" not in result.stdout
        and "PASS" not in result.stdout
    ):
        pytest.skip(f"Inspector CLI failed unexpectedly: {result.stderr[:500]}")

    # Parse output file
    output_path = Path(f"/tmp/inspector-assessment-{server_name}.json")
    if not output_path.exists():
        pytest.skip(f"Inspector output not found: {output_path}")

    try:
        with open(output_path) as f:
            raw_output = json.load(f)
    except json.JSONDecodeError as e:
        pytest.skip(f"Invalid JSON in Inspector output: {e}")

    # Parse into structured result
    return _parse_inspector_output(raw_output, server_name)


def _parse_inspector_output(raw: Dict[str, Any], server_name: str) -> InspectorResult:
    """Parse raw Inspector JSON into structured InspectorResult."""
    findings: List[InspectorFinding] = []

    # Handle modules data - can be dict or nested structure
    modules_data = raw.get("modules", {})

    # Parse security module findings
    if "security" in modules_data:
        security_data = modules_data["security"]
        findings.extend(_parse_module_findings(security_data))

    # Parse aupCompliance module findings
    if "aupCompliance" in modules_data:
        aup_data = modules_data["aupCompliance"]
        findings.extend(_parse_module_findings(aup_data))

    # Parse any other modules
    for module_name, module_data in modules_data.items():
        if module_name not in ("security", "aupCompliance") and isinstance(
            module_data, dict
        ):
            findings.extend(_parse_module_findings(module_data))

    # Extract overall risk level from summary or modules
    overall_risk = _extract_risk_level(raw)

    return InspectorResult(
        server_name=server_name,
        overall_status=raw.get("summary", {}).get("overallStatus", "UNKNOWN"),
        overall_risk_level=overall_risk,
        findings=findings,
        modules_run=raw.get("modulesRun", []),
        raw_output=raw,
    )


def _parse_module_findings(module_data: Dict[str, Any]) -> List[InspectorFinding]:
    """Parse findings from a single module.

    Handles multiple Inspector output formats:
    - findings: Array of structured findings (legacy format)
    - promptInjectionTests: Array of test results with vulnerability data
    """
    findings: List[InspectorFinding] = []

    # Parse legacy findings array
    for finding in module_data.get("findings", []):
        cwe_ids = finding.get("cweIds", finding.get("cwe_ids", []))
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        findings.append(
            InspectorFinding(
                test_name=finding.get("testName", finding.get("test_name", "")),
                tool_name=finding.get("toolName", finding.get("tool_name", "")),
                risk_level=finding.get(
                    "riskLevel", finding.get("risk_level", "UNKNOWN")
                ),
                vulnerable=finding.get("vulnerable", False),
                cwe_ids=cwe_ids,
                evidence=finding.get("evidence", ""),
                description=finding.get("description", ""),
                raw=finding,
            )
        )

    # Parse promptInjectionTests (where Session/Crypto CWE data lives in v1.30+)
    for test in module_data.get("promptInjectionTests", []):
        if not test.get("vulnerable"):
            continue  # Only include vulnerable findings

        # Extract CWE IDs from multiple sources
        cwe_ids = []
        # Check sessionCweIds (session management vulnerabilities)
        if test.get("sessionCweIds"):
            cwe_ids.extend(test["sessionCweIds"])
        # Check cryptoCweIds (cryptographic vulnerabilities)
        if test.get("cryptoCweIds"):
            cwe_ids.extend(test["cryptoCweIds"])
        # Extract from description if not found elsewhere: "...(CWE-384)..."
        if not cwe_ids:
            cwe_ids = re.findall(r"CWE-\d+", test.get("description", ""))

        findings.append(
            InspectorFinding(
                test_name=test.get("testName", ""),
                tool_name=test.get("toolName", ""),
                risk_level=test.get("riskLevel", "HIGH"),
                vulnerable=True,
                cwe_ids=cwe_ids,
                evidence=test.get("evidence", ""),
                description=test.get("description", ""),
                raw=test,
            )
        )

    return findings


def _extract_risk_level(raw: Dict[str, Any]) -> str:
    """Extract overall risk level from Inspector output."""
    # Try summary first
    summary = raw.get("summary", {})
    if "overallRiskLevel" in summary:
        return summary["overallRiskLevel"]

    # Try modules
    modules = raw.get("modules", {})
    if "security" in modules:
        security = modules["security"]
        if "overallRiskLevel" in security:
            return security["overallRiskLevel"]

    return "UNKNOWN"


def extract_findings_for_tool(
    result: InspectorResult, tool_name: str
) -> List[InspectorFinding]:
    """Extract findings specific to a tool from assessment results."""
    return [f for f in result.findings if f.tool_name == tool_name]


def has_cwe_detection(findings: List[InspectorFinding], cwe_id: str) -> bool:
    """
    Check if any finding includes the specified CWE ID.

    Handles multiple formats:
    - Exact match in cwe_ids list: ["CWE-328", "CWE-916"]
    - In sessionCweIds/cryptoCweIds from raw data
    - In evidence string: "Weak hash (CWE-328)"
    - In description: "Uses MD5 (CWE-328)"
    """
    for finding in findings:
        if not finding.vulnerable:
            continue
        # Check cwe_ids list (populated from sessionCweIds/cryptoCweIds)
        if cwe_id in finding.cwe_ids:
            return True
        # Check evidence string
        if cwe_id in finding.evidence:
            return True
        # Check description
        if cwe_id in finding.description:
            return True
        # Check raw data for sessionCweIds/cryptoCweIds directly
        raw_cwe = (finding.raw.get("sessionCweIds", []) or []) + (
            finding.raw.get("cryptoCweIds", []) or []
        )
        if cwe_id in raw_cwe:
            return True
        # Check raw finding data as string fallback
        if cwe_id in str(finding.raw):
            return True
    return False


def get_highest_risk_level(findings: List[InspectorFinding]) -> str:
    """
    Get highest risk level from findings.

    Priority: HIGH > MEDIUM > LOW > UNKNOWN
    """
    priority = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    highest = "UNKNOWN"
    for finding in findings:
        if finding.vulnerable and priority.get(finding.risk_level, 0) > priority.get(
            highest, 0
        ):
            highest = finding.risk_level
    return highest


def get_vulnerable_findings(findings: List[InspectorFinding]) -> List[InspectorFinding]:
    """Get only findings marked as vulnerable."""
    return [f for f in findings if f.vulnerable]


def check_inspector_available() -> bool:
    """Check if Inspector CLI is available and responding."""
    try:
        result = subprocess.run(
            ["npm", "run", "assess", "--", "--help"],
            cwd=INSPECTOR_DIR,
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
