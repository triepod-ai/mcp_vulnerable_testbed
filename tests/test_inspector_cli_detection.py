"""
MCP Inspector CLI Detection Tests for Challenges #12 and #13

Tests that MCP Inspector CLI (`npm run assess`) detects session management
and cryptographic vulnerabilities. Validates CLI integration and output parsing.

Inspector v1.30+ includes detection for:
- Session Management: CWE-384, CWE-330, CWE-613, CWE-200
- Cryptographic Failures: CWE-328, CWE-327, CWE-321, CWE-916, CWE-326, CWE-208

Challenges tested:
- Challenge #12: Session Management Vulnerabilities
- Challenge #13: Cryptographic Failures - OWASP A02:2021

Usage:
    pytest tests/test_inspector_cli_detection.py -v
    pytest tests/test_inspector_cli_detection.py -v -m inspector
    pytest tests/test_inspector_cli_detection.py -v -k "Challenge12"
    pytest tests/test_inspector_cli_detection.py -v -k "Challenge13"

GitHub Issue: https://github.com/triepod-ai/mcp_vulnerable_testbed/issues/6
"""

import pytest
from typing import Optional

from inspector_cli_helper import (
    run_inspector_assessment,
    extract_findings_for_tool,
    has_cwe_detection,
    get_highest_risk_level,
    get_vulnerable_findings,
    InspectorResult,
)


# All tests in this file require Inspector CLI
pytestmark = [pytest.mark.integration, pytest.mark.inspector]


# ============================================================================
# Inspector CLI Availability Tests
# ============================================================================


class TestInspectorCLIAvailability:
    """Verify Inspector CLI is available for detection tests."""

    def test_inspector_cli_responds(self, inspector_cli_available):
        """Inspector CLI should respond to --help."""
        if not inspector_cli_available:
            pytest.skip("MCP Inspector CLI not available")
        assert inspector_cli_available, "Inspector CLI should be available"


# ============================================================================
# Challenge #12: Session Management Vulnerability Detection
# ============================================================================


class TestInspectorCLIChallenge12:
    """
    Challenge #12: Session Management Vulnerability Detection via Inspector CLI

    Tests that MCP Inspector CLI detects session management vulnerabilities.
    Inspector v1.30+ includes session management detection patterns.

    Target CWEs:
    - CWE-384: Session Fixation
    - CWE-330: Predictable Session Tokens
    - CWE-613: No Session Timeout
    - CWE-200: Session ID Exposure in URL
    """

    @pytest.fixture(scope="class")
    def session_tool_assessment(
        self,
        inspector_cli_available,
        inspector_config_file
    ) -> Optional[InspectorResult]:
        """Run Inspector CLI against vulnerable_session_tool (class-scoped)."""
        if not inspector_cli_available:
            pytest.skip("MCP Inspector CLI not available")

        return run_inspector_assessment(
            server_name="testbed-session-12",
            config_path=inspector_config_file,
            tool_name="vulnerable_session_tool",
            modules=["security"],
            timeout=180
        )

    def test_inspector_cli_invocation_succeeds(self, session_tool_assessment):
        """Inspector CLI should successfully complete assessment."""
        # Verify we got a valid result with parsed output
        assert session_tool_assessment is not None, "Should get assessment result"
        assert session_tool_assessment.server_name == "testbed-session-12"
        assert "security" in session_tool_assessment.modules_run

    def test_inspector_returns_findings_structure(self, session_tool_assessment):
        """Inspector should return properly structured findings."""
        # Even if no vulnerabilities detected, structure should be valid
        assert hasattr(session_tool_assessment, 'findings')
        assert hasattr(session_tool_assessment, 'overall_status')
        assert hasattr(session_tool_assessment, 'raw_output')

    def test_challenge_12_session_vulnerabilities_detected(self, session_tool_assessment):
        """Main test: vulnerable_session_tool should be flagged with vulnerabilities."""
        findings = extract_findings_for_tool(
            session_tool_assessment,
            "vulnerable_session_tool"
        )
        vulnerable_findings = get_vulnerable_findings(findings)

        assert len(vulnerable_findings) > 0, \
            "Inspector should detect vulnerabilities in session tool"

    def test_session_tool_high_risk(self, session_tool_assessment):
        """Session vulnerabilities should be rated HIGH risk."""
        findings = extract_findings_for_tool(
            session_tool_assessment,
            "vulnerable_session_tool"
        )
        risk_level = get_highest_risk_level(findings)

        assert risk_level == "HIGH", \
            f"Expected HIGH risk level, got {risk_level}"

    def test_session_fixation_cwe384_in_output(self, session_tool_assessment):
        """CWE-384 (Session Fixation) should be in findings."""
        findings = extract_findings_for_tool(
            session_tool_assessment,
            "vulnerable_session_tool"
        )

        # Check for CWE-384 or related session fixation indicators
        has_cwe = has_cwe_detection(findings, "CWE-384")
        has_fixation = any(
            "fixation" in str(f.raw).lower() or "fixate" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_fixation, \
            "Session fixation (CWE-384) should be detected"

    def test_predictable_tokens_cwe330_in_output(self, session_tool_assessment):
        """CWE-330 (Predictable Tokens) should be in findings."""
        findings = extract_findings_for_tool(
            session_tool_assessment,
            "vulnerable_session_tool"
        )

        has_cwe = has_cwe_detection(findings, "CWE-330")
        has_predictable = any(
            "predictable" in str(f.raw).lower() or "random" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_predictable, \
            "Predictable tokens (CWE-330) should be detected"

    def test_no_timeout_cwe613_in_output(self, session_tool_assessment):
        """CWE-613 (No Session Timeout) should be in findings."""
        findings = extract_findings_for_tool(
            session_tool_assessment,
            "vulnerable_session_tool"
        )

        has_cwe = has_cwe_detection(findings, "CWE-613")
        has_timeout = any(
            "timeout" in str(f.raw).lower() or "expir" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_timeout, \
            "No session timeout (CWE-613) should be detected"

    def test_id_exposure_cwe200_in_output(self, session_tool_assessment):
        """CWE-200 (Session ID in URL) should be in findings."""
        findings = extract_findings_for_tool(
            session_tool_assessment,
            "vulnerable_session_tool"
        )

        has_cwe = has_cwe_detection(findings, "CWE-200")
        has_exposure = any(
            "url" in str(f.raw).lower() or "expos" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_exposure, \
            "Session ID exposure (CWE-200) should be detected"


# ============================================================================
# Challenge #13a: Cryptographic Tool Vulnerability Detection
# ============================================================================


class TestInspectorCLIChallenge13Crypto:
    """
    Challenge #13a: Cryptographic Tool Vulnerability Detection via Inspector CLI

    Tests that MCP Inspector CLI detects cryptographic vulnerabilities.
    Inspector v1.30+ includes cryptographic failure detection patterns.

    Target CWEs:
    - CWE-328: Weak Hash (MD5)
    - CWE-916: Static Salt
    - CWE-330: Predictable RNG
    - CWE-208: Timing Attack
    """

    @pytest.fixture(scope="class")
    def crypto_tool_assessment(
        self,
        inspector_cli_available,
        inspector_config_file
    ) -> Optional[InspectorResult]:
        """Run Inspector CLI against vulnerable_crypto_tool_endpoint (class-scoped)."""
        if not inspector_cli_available:
            pytest.skip("MCP Inspector CLI not available")

        return run_inspector_assessment(
            server_name="testbed-crypto-13a",
            config_path=inspector_config_file,
            tool_name="vulnerable_crypto_tool_endpoint",
            modules=["security"],
            timeout=180
        )

    def test_inspector_cli_invocation_succeeds(self, crypto_tool_assessment):
        """Inspector CLI should successfully complete assessment."""
        assert crypto_tool_assessment is not None, "Should get assessment result"
        assert crypto_tool_assessment.server_name == "testbed-crypto-13a"
        assert "security" in crypto_tool_assessment.modules_run

    def test_inspector_returns_findings_structure(self, crypto_tool_assessment):
        """Inspector should return properly structured findings."""
        assert hasattr(crypto_tool_assessment, 'findings')
        assert hasattr(crypto_tool_assessment, 'overall_status')
        assert hasattr(crypto_tool_assessment, 'raw_output')

    def test_owasp_a02_crypto_tool_detected(self, crypto_tool_assessment):
        """Main test: vulnerable_crypto_tool_endpoint should be flagged."""
        findings = extract_findings_for_tool(
            crypto_tool_assessment,
            "vulnerable_crypto_tool_endpoint"
        )
        vulnerable_findings = get_vulnerable_findings(findings)

        assert len(vulnerable_findings) > 0, \
            "Inspector should detect crypto vulnerabilities"

    def test_crypto_tool_high_risk(self, crypto_tool_assessment):
        """Crypto vulnerabilities should be rated HIGH risk."""
        findings = extract_findings_for_tool(
            crypto_tool_assessment,
            "vulnerable_crypto_tool_endpoint"
        )
        risk_level = get_highest_risk_level(findings)

        assert risk_level == "HIGH", \
            f"Expected HIGH risk level, got {risk_level}"

    def test_weak_hash_cwe328_in_output(self, crypto_tool_assessment):
        """CWE-328 (MD5 hashing) should be in findings."""
        findings = extract_findings_for_tool(
            crypto_tool_assessment,
            "vulnerable_crypto_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-328")
        has_md5 = any(
            "md5" in str(f.raw).lower() or "weak hash" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_md5, \
            "Weak hash MD5 (CWE-328) should be detected"

    def test_static_salt_cwe916_in_output(self, crypto_tool_assessment):
        """CWE-916 (Static Salt) should be in findings."""
        findings = extract_findings_for_tool(
            crypto_tool_assessment,
            "vulnerable_crypto_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-916")
        has_salt = any(
            "salt" in str(f.raw).lower() or "static" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_salt, \
            "Static salt (CWE-916) should be detected"

    def test_predictable_rng_cwe330_in_output(self, crypto_tool_assessment):
        """CWE-330 (Predictable RNG) should be in findings."""
        findings = extract_findings_for_tool(
            crypto_tool_assessment,
            "vulnerable_crypto_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-330")
        has_rng = any(
            "random" in str(f.raw).lower() or "predict" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_rng, \
            "Predictable RNG (CWE-330) should be detected"

    def test_timing_attack_cwe208_in_output(self, crypto_tool_assessment):
        """CWE-208 (Timing Attack) should be in findings."""
        findings = extract_findings_for_tool(
            crypto_tool_assessment,
            "vulnerable_crypto_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-208")
        has_timing = any(
            "timing" in str(f.raw).lower() or "constant" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_timing, \
            "Timing attack (CWE-208) should be detected"


# ============================================================================
# Challenge #13b: Encryption Tool Vulnerability Detection
# ============================================================================


class TestInspectorCLIChallenge13Encryption:
    """
    Challenge #13b: Encryption Tool Vulnerability Detection via Inspector CLI

    Tests that MCP Inspector CLI detects encryption vulnerabilities.
    Inspector v1.30+ includes encryption failure detection patterns.

    Target CWEs:
    - CWE-327: ECB Mode
    - CWE-321: Hardcoded Key
    - CWE-916: Weak Key Derivation
    - CWE-326: Weak HMAC Key
    """

    @pytest.fixture(scope="class")
    def encryption_tool_assessment(
        self,
        inspector_cli_available,
        inspector_config_file
    ) -> Optional[InspectorResult]:
        """Run Inspector CLI against vulnerable_encryption_tool_endpoint (class-scoped)."""
        if not inspector_cli_available:
            pytest.skip("MCP Inspector CLI not available")

        return run_inspector_assessment(
            server_name="testbed-encryption-13b",
            config_path=inspector_config_file,
            tool_name="vulnerable_encryption_tool_endpoint",
            modules=["security"],
            timeout=180
        )

    def test_inspector_cli_invocation_succeeds(self, encryption_tool_assessment):
        """Inspector CLI should successfully complete assessment."""
        assert encryption_tool_assessment is not None, "Should get assessment result"
        assert encryption_tool_assessment.server_name == "testbed-encryption-13b"
        assert "security" in encryption_tool_assessment.modules_run

    def test_inspector_returns_findings_structure(self, encryption_tool_assessment):
        """Inspector should return properly structured findings."""
        assert hasattr(encryption_tool_assessment, 'findings')
        assert hasattr(encryption_tool_assessment, 'overall_status')
        assert hasattr(encryption_tool_assessment, 'raw_output')

    def test_owasp_a02_encryption_tool_detected(self, encryption_tool_assessment):
        """Main test: vulnerable_encryption_tool_endpoint should be flagged."""
        findings = extract_findings_for_tool(
            encryption_tool_assessment,
            "vulnerable_encryption_tool_endpoint"
        )
        vulnerable_findings = get_vulnerable_findings(findings)

        assert len(vulnerable_findings) > 0, \
            "Inspector should detect encryption vulnerabilities"

    def test_encryption_tool_high_risk(self, encryption_tool_assessment):
        """Encryption vulnerabilities should be rated HIGH risk."""
        findings = extract_findings_for_tool(
            encryption_tool_assessment,
            "vulnerable_encryption_tool_endpoint"
        )
        risk_level = get_highest_risk_level(findings)

        assert risk_level == "HIGH", \
            f"Expected HIGH risk level, got {risk_level}"

    def test_ecb_mode_cwe327_in_output(self, encryption_tool_assessment):
        """CWE-327 (ECB Mode) should be in findings."""
        findings = extract_findings_for_tool(
            encryption_tool_assessment,
            "vulnerable_encryption_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-327")
        has_ecb = any(
            "ecb" in str(f.raw).lower() or "block" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_ecb, \
            "ECB mode (CWE-327) should be detected"

    def test_hardcoded_key_cwe321_in_output(self, encryption_tool_assessment):
        """CWE-321 (Hardcoded Key) should be in findings."""
        findings = extract_findings_for_tool(
            encryption_tool_assessment,
            "vulnerable_encryption_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-321")
        has_hardcoded = any(
            "hardcoded" in str(f.raw).lower() or "embedded" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_hardcoded, \
            "Hardcoded key (CWE-321) should be detected"

    def test_weak_kdf_cwe916_in_output(self, encryption_tool_assessment):
        """CWE-916 (Weak Key Derivation) should be in findings."""
        findings = extract_findings_for_tool(
            encryption_tool_assessment,
            "vulnerable_encryption_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-916")
        has_kdf = any(
            "deriv" in str(f.raw).lower() or "pbkdf" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_kdf, \
            "Weak KDF (CWE-916) should be detected"

    def test_weak_hmac_cwe326_in_output(self, encryption_tool_assessment):
        """CWE-326 (Weak HMAC Key) should be in findings."""
        findings = extract_findings_for_tool(
            encryption_tool_assessment,
            "vulnerable_encryption_tool_endpoint"
        )

        has_cwe = has_cwe_detection(findings, "CWE-326")
        has_hmac = any(
            "hmac" in str(f.raw).lower() or "key length" in str(f.raw).lower()
            for f in findings if f.vulnerable
        )

        assert has_cwe or has_hmac, \
            "Weak HMAC key (CWE-326) should be detected"


# ============================================================================
# Hardened Versions Should NOT Be Flagged (False Positive Testing)
# ============================================================================


class TestInspectorCLIHardenedNotFlagged:
    """
    A/B Comparison: Verify hardened versions are NOT flagged via Inspector CLI.

    All hardened tools should show zero vulnerabilities in Inspector output.
    """

    def test_hardened_session_zero_vulnerabilities(
        self,
        inspector_cli_available,
        hardened_inspector_config
    ):
        """Hardened session tool should NOT be flagged as vulnerable."""
        if not inspector_cli_available:
            pytest.skip("MCP Inspector CLI not available")

        result = run_inspector_assessment(
            server_name="testbed-hardened-session",
            config_path=hardened_inspector_config,
            tool_name="vulnerable_session_tool",
            modules=["security"],
            timeout=180
        )

        findings = extract_findings_for_tool(result, "vulnerable_session_tool")
        vulnerable_findings = get_vulnerable_findings(findings)

        assert len(vulnerable_findings) == 0, \
            f"Hardened session tool should NOT be flagged, found: {[f.test_name for f in vulnerable_findings]}"

    def test_hardened_crypto_zero_vulnerabilities(
        self,
        inspector_cli_available,
        hardened_inspector_config
    ):
        """Hardened crypto tool should NOT be flagged as vulnerable."""
        if not inspector_cli_available:
            pytest.skip("MCP Inspector CLI not available")

        result = run_inspector_assessment(
            server_name="testbed-hardened-crypto",
            config_path=hardened_inspector_config,
            tool_name="vulnerable_crypto_tool_endpoint",
            modules=["security"],
            timeout=180
        )

        findings = extract_findings_for_tool(result, "vulnerable_crypto_tool_endpoint")
        vulnerable_findings = get_vulnerable_findings(findings)

        assert len(vulnerable_findings) == 0, \
            f"Hardened crypto tool should NOT be flagged, found: {[f.test_name for f in vulnerable_findings]}"

    def test_hardened_encryption_zero_vulnerabilities(
        self,
        inspector_cli_available,
        hardened_inspector_config
    ):
        """Hardened encryption tool should NOT be flagged as vulnerable."""
        if not inspector_cli_available:
            pytest.skip("MCP Inspector CLI not available")

        result = run_inspector_assessment(
            server_name="testbed-hardened-encryption",
            config_path=hardened_inspector_config,
            tool_name="vulnerable_encryption_tool_endpoint",
            modules=["security"],
            timeout=180
        )

        findings = extract_findings_for_tool(result, "vulnerable_encryption_tool_endpoint")
        vulnerable_findings = get_vulnerable_findings(findings)

        assert len(vulnerable_findings) == 0, \
            f"Hardened encryption tool should NOT be flagged, found: {[f.test_name for f in vulnerable_findings]}"
