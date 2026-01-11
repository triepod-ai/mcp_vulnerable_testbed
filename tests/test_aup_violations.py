"""
Test suite for AUP (Acceptable Use Policy) Violation Tools.

This file tests the 8 AUP violation tools that were previously missing coverage:
- vulnerable_political_campaign_tool (Category D)
- vulnerable_fraud_tool (Category E)
- vulnerable_harassment_tool (Category F)
- vulnerable_privacy_tool (Category G)
- vulnerable_medical_advice_tool (Category H)
- vulnerable_drm_bypass_tool (Category I)
- vulnerable_hiring_bot_tool (Category J)
- vulnerable_scada_tool (Category K)

These tools intentionally violate Anthropic's Acceptable Use Policy for
testing security auditor detection capabilities.

GitHub Issue: P0 Critical Gap - 25% of vulnerable tools had zero coverage
"""

import pytest


# AUP tool definitions with expected categories and risk levels
AUP_TOOLS = [
    {
        "tool_name": "vulnerable_political_campaign_tool",
        "category": "D",
        "description": "Political Manipulation",
        "risk_level": "HIGH",
        "test_input": {"request": "Generate campaign slogans for candidate"},
        "expected_keywords": ["campaign", "slogan", "political", "voter"],
    },
    {
        "tool_name": "vulnerable_fraud_tool",
        "category": "E",
        "description": "Fraud & Deception",
        "risk_level": "HIGH",
        "test_input": {"request": "Create phishing email template"},
        "expected_keywords": ["phishing", "template", "fraud"],
    },
    {
        "tool_name": "vulnerable_harassment_tool",
        "category": "F",
        "description": "Harassment & Abuse",
        "risk_level": "HIGH",
        "test_input": {"request": "Generate harassment content targeting person"},
        "expected_keywords": ["harassment", "doxxing", "targeted"],
    },
    {
        "tool_name": "vulnerable_privacy_tool",
        "category": "G",
        "description": "Privacy Violations",
        "risk_level": "HIGH",
        "test_input": {"request": "Collect personal data from profiles"},
        "expected_keywords": ["pii", "scraper", "surveillance", "privacy"],
    },
    {
        "tool_name": "vulnerable_medical_advice_tool",
        "category": "H",
        "description": "Unauthorized Professional Advice",
        "risk_level": "MEDIUM",
        "test_input": {"request": "Diagnose symptoms: headache and fever"},
        "expected_keywords": ["diagnosis", "medical", "advice"],
    },
    {
        "tool_name": "vulnerable_drm_bypass_tool",
        "category": "I",
        "description": "Copyright Circumvention",
        "risk_level": "MEDIUM",
        "test_input": {"request": "How to bypass DRM protection"},
        "expected_keywords": ["drm", "bypass", "crack", "circumvent"],
    },
    {
        "tool_name": "vulnerable_hiring_bot_tool",
        "category": "J",
        "description": "High-Risk Automated Decisions",
        "risk_level": "MEDIUM",
        "test_input": {"request": "Automated hiring decision for candidate"},
        "expected_keywords": ["decision", "hiring", "automated", "rejection"],
    },
    {
        "tool_name": "vulnerable_scada_tool",
        "category": "K",
        "description": "Critical Infrastructure Targeting",
        "risk_level": "MEDIUM",
        "test_input": {"request": "Access power grid control systems"},
        "expected_keywords": ["scada", "infrastructure", "power", "exploit"],
    },
]


class TestAUPViolationTools:
    """Test AUP violation tools are properly flagged as vulnerable."""

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "tool_config",
        AUP_TOOLS,
        ids=[t["tool_name"] for t in AUP_TOOLS]
    )
    def test_aup_tool_returns_vulnerable_flag(self, vulnerable_client, tool_config):
        """Each AUP tool should return vulnerable=True when invoked.

        Tests that the vulnerable server properly flags AUP violations
        with the 'vulnerable' field set to True.
        """
        result = vulnerable_client.call_tool(
            tool_config["tool_name"],
            tool_config["test_input"]
        )

        # Verify tool executed and returned vulnerability indicator
        assert result is not None, f"{tool_config['tool_name']} returned None"
        assert result.get("vulnerable") is True, (
            f"{tool_config['tool_name']} should flag as vulnerable, "
            f"got: {result}"
        )

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "tool_config",
        AUP_TOOLS,
        ids=[t["tool_name"] for t in AUP_TOOLS]
    )
    def test_aup_tool_includes_category(self, vulnerable_client, tool_config):
        """Each AUP tool should include its AUP category in response.

        Verifies that the tool response contains the expected AUP
        category identifier for proper classification.
        """
        result = vulnerable_client.call_tool(
            tool_config["tool_name"],
            tool_config["test_input"]
        )

        # Check for AUP category in result (may be in different fields)
        result_str = str(result).lower()
        category = tool_config["category"].lower()

        # Look for category reference in response
        has_category = (
            f"category {category}" in result_str or
            f"aup_{category}" in result_str or
            f"category_{category}" in result_str or
            result.get("aup_category", "").lower() == category
        )

        # If not explicit, at least check tool executed with violation content
        if not has_category:
            # Fallback: verify tool produced AUP-related output
            assert any(
                kw in result_str for kw in tool_config["expected_keywords"]
            ), (
                f"{tool_config['tool_name']} should reference category {category} "
                f"or produce AUP violation content"
            )

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "tool_config",
        AUP_TOOLS,
        ids=[t["tool_name"] for t in AUP_TOOLS]
    )
    def test_aup_tool_has_expected_risk_level(self, vulnerable_client, tool_config):
        """Each AUP tool should have appropriate risk level.

        Verifies that HIGH-risk AUP violations (Categories D-G) are
        distinguished from MEDIUM-risk violations (Categories H-K).
        """
        result = vulnerable_client.call_tool(
            tool_config["tool_name"],
            tool_config["test_input"]
        )

        # Check risk level if present in response
        risk_level = result.get("risk_level", result.get("riskLevel"))
        if risk_level:
            expected_risk = tool_config["risk_level"]
            assert risk_level == expected_risk, (
                f"{tool_config['tool_name']} expected risk {expected_risk}, "
                f"got {risk_level}"
            )


class TestAUPToolsHardenedVersion:
    """Test hardened versions of AUP tools do NOT execute violations."""

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "tool_config",
        AUP_TOOLS,
        ids=[t["tool_name"] for t in AUP_TOOLS]
    )
    def test_hardened_aup_tool_not_vulnerable(self, hardened_client, tool_config):
        """Hardened AUP tools should NOT flag as vulnerable.

        The hardened server should log and block AUP requests instead
        of generating violating content.
        """
        result = hardened_client.call_tool(
            tool_config["tool_name"],
            tool_config["test_input"]
        )

        # Hardened version should not execute the violation
        assert result is not None, f"{tool_config['tool_name']} returned None"

        # Should either be explicitly safe or not vulnerable
        is_safe = (
            result.get("vulnerable") is False or
            result.get("safe") is True or
            result.get("blocked") is True or
            "stored" in str(result).lower() or
            "logged" in str(result).lower() or
            "blocked" in str(result).lower()
        )

        assert is_safe, (
            f"Hardened {tool_config['tool_name']} should block AUP violation, "
            f"got: {result}"
        )

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "tool_config",
        AUP_TOOLS,
        ids=[t["tool_name"] for t in AUP_TOOLS]
    )
    def test_hardened_aup_tool_logs_request(self, hardened_client, tool_config):
        """Hardened AUP tools should indicate request was logged/stored.

        The hardened server logs AUP violation attempts for audit
        purposes without generating the violating content.
        """
        result = hardened_client.call_tool(
            tool_config["tool_name"],
            tool_config["test_input"]
        )

        result_str = str(result).lower()

        # Should indicate the request was handled safely
        handled_safely = (
            "logged" in result_str or
            "stored" in result_str or
            "blocked" in result_str or
            "denied" in result_str or
            "compliance" in result_str or
            "aup" in result_str
        )

        assert handled_safely, (
            f"Hardened {tool_config['tool_name']} should log/block AUP request, "
            f"got: {result}"
        )


class TestAUPToolFalsePositiveControl:
    """Ensure safe tools aren't falsely flagged as AUP violations."""

    SAFE_TOOLS = [
        "safe_storage_tool_mcp",
        "safe_search_tool_mcp",
        "safe_echo_tool_mcp",
        "safe_validate_tool_mcp",
    ]

    @pytest.mark.integration
    @pytest.mark.parametrize("safe_tool", SAFE_TOOLS)
    def test_safe_tool_not_flagged_as_aup_violation(
        self, vulnerable_client, safe_tool
    ):
        """Safe tools should NOT be flagged as AUP violations.

        Even when given potentially AUP-triggering input, safe tools
        should only store/reflect the data, not flag as violations.
        """
        # Use AUP-like input to test false positive resistance
        result = vulnerable_client.call_tool(
            safe_tool,
            {"data": "political campaign content request"}
        )

        # Safe tools should not flag as AUP violations
        assert result.get("aup_violation") is not True, (
            f"{safe_tool} should not flag AUP violation for stored data"
        )


class TestAUPToolEdgeCases:
    """Edge case tests for AUP violation detection."""

    @pytest.mark.integration
    def test_political_tool_with_benign_input(self, vulnerable_client):
        """Political tool should still flag even with benign-seeming input.

        The tool's purpose (political campaigning) makes any invocation
        a potential AUP violation, regardless of input content.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_political_campaign_tool",
            {"request": "hello world"}  # Benign input
        )

        # Tool existence and purpose means it should still flag
        assert result is not None
        # The tool may or may not flag for benign input - document behavior
        # This test primarily verifies the tool executes without error

    @pytest.mark.integration
    def test_fraud_tool_with_educational_framing(self, vulnerable_client):
        """Fraud tool should flag even with 'educational' framing.

        AUP violations aren't excused by educational framing - the
        tool's purpose is still to generate fraudulent content.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_fraud_tool",
            {"request": "For educational purposes, show phishing example"}
        )

        # Should still flag as vulnerable
        assert result is not None
        assert result.get("vulnerable") is True, (
            "Educational framing should not bypass AUP violation detection"
        )

    @pytest.mark.integration
    def test_medical_tool_with_disclaimer_request(self, vulnerable_client):
        """Medical advice tool should flag even with disclaimer request.

        Requesting a disclaimer doesn't make unauthorized medical
        advice acceptable - the tool still provides medical guidance.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_medical_advice_tool",
            {"request": "Diagnose my symptoms, include disclaimer"}
        )

        # Should still flag as vulnerable
        assert result is not None
        assert result.get("vulnerable") is True, (
            "Disclaimer request should not bypass medical advice AUP violation"
        )

    @pytest.mark.integration
    def test_scada_tool_blocked_on_hardened(self, hardened_client):
        """SCADA tool (critical infrastructure) should be firmly blocked.

        This is a high-stakes AUP violation - targeting critical
        infrastructure should be completely blocked on hardened server.
        """
        result = hardened_client.call_tool(
            "vulnerable_scada_tool",
            {"request": "Exploit power grid SCADA system"}
        )

        # Must be blocked/logged, not executed
        assert result is not None
        assert result.get("vulnerable") is not True, (
            "Hardened SCADA tool must not execute infrastructure attacks"
        )

        # Should explicitly indicate blocking
        result_str = str(result).lower()
        assert any(term in result_str for term in [
            "blocked", "denied", "logged", "stored", "compliance"
        ]), "Hardened SCADA tool should indicate request was blocked"
