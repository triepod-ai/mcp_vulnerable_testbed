"""
Cryptographic Vulnerability Tests (OWASP A02:2021)

Tests cryptographic failure patterns against the MCP Vulnerable Testbed server.
Validates weak hashing, ECB mode, hardcoded keys, and predictable RNG.

Issue: #2 - feat: Add cryptographic failure tools (OWASP A02:2021)

Usage:
    pytest tests/test_crypto_vulnerabilities.py -v
    pytest tests/test_crypto_vulnerabilities.py -v -k "md5"
    pytest tests/test_crypto_vulnerabilities.py -v --tb=short
"""

import json
from typing import Dict, Any


def check_evidence(result: Dict[str, Any], pattern: str) -> bool:
    """Check if result contains evidence matching the pattern."""
    result_str = json.dumps(result).lower()
    patterns = pattern.lower().split("|")
    return any(p in result_str for p in patterns)


class TestCryptoVulnerabilities:
    """Tests for vulnerable_crypto_tool - weak hashing and RNG patterns."""

    def test_md5_hashing(self, vulnerable_client):
        """Test that crypto tool uses MD5 for password hashing (CWE-328)."""
        result = vulnerable_client.call_tool(
            "vulnerable_crypto_tool_endpoint", {"password": "test123", "action": "hash"}
        )
        assert result.get("vulnerable") is True
        assert result.get("algorithm") == "MD5"
        assert "CWE-328" in str(result.get("cwe_ids", []))
        # MD5 of "test123" is "cc03e747a6afbbcbf8be7668acfebee5"
        assert result.get("hash") is not None

    def test_static_salt_sha1(self, vulnerable_client):
        """Test that crypto tool uses static salt (CWE-916)."""
        result = vulnerable_client.call_tool(
            "vulnerable_crypto_tool_endpoint",
            {"password": "mypassword", "action": "salt_hash"},
        )
        assert result.get("vulnerable") is True
        assert result.get("algorithm") == "SHA1"
        assert result.get("salt") == "static_salt_123"
        assert result.get("salt_type") == "static"
        assert "CWE-916" in str(result.get("cwe_ids", []))

    def test_predictable_rng(self, vulnerable_client):
        """Test that crypto tool uses predictable RNG (CWE-330)."""
        result = vulnerable_client.call_tool(
            "vulnerable_crypto_tool_endpoint", {"password": "seed", "action": "random"}
        )
        assert result.get("vulnerable") is True
        assert result.get("rng_type") == "random.random()"
        assert result.get("cryptographically_secure") is False
        assert "CWE-330" in str(result.get("cwe_ids", []))

    def test_timing_attack_vulnerability(self, vulnerable_client):
        """Test that crypto tool uses non-constant-time comparison (CWE-208)."""
        result = vulnerable_client.call_tool(
            "vulnerable_crypto_tool_endpoint", {"password": "test", "action": "verify"}
        )
        assert result.get("vulnerable") is True
        assert result.get("timing_safe") is False
        assert "CWE-208" in str(result.get("cwe_ids", []))


class TestEncryptionVulnerabilities:
    """Tests for vulnerable_encryption_tool - ECB mode and hardcoded keys."""

    def test_ecb_mode_encryption(self, vulnerable_client):
        """Test that encryption tool uses AES-ECB mode (CWE-327)."""
        result = vulnerable_client.call_tool(
            "vulnerable_encryption_tool_endpoint",
            {"data": "AAAAAAAAAAAAAAAA", "action": "encrypt"},
        )
        assert result.get("vulnerable") is True
        assert result.get("mode") in ["ECB", "stream"]  # ECB or XOR fallback
        assert result.get("key_source") == "hardcoded"
        assert "CWE-327" in str(result.get("cwe_ids", []))

    def test_hardcoded_encryption_key(self, vulnerable_client):
        """Test that encryption tool uses hardcoded key (CWE-321)."""
        result = vulnerable_client.call_tool(
            "vulnerable_encryption_tool_endpoint",
            {"data": "secret message", "action": "encrypt"},
        )
        assert result.get("vulnerable") is True
        assert result.get("key_source") == "hardcoded"
        # Key preview should show part of the hardcoded key
        assert "hardcode" in result.get("key_preview", "").lower()
        assert "CWE-321" in str(result.get("cwe_ids", []))

    def test_weak_key_derivation(self, vulnerable_client):
        """Test that encryption tool uses MD5 for key derivation (CWE-916)."""
        result = vulnerable_client.call_tool(
            "vulnerable_encryption_tool_endpoint",
            {"data": "mypassword", "action": "derive_key"},
        )
        assert result.get("vulnerable") is True
        assert result.get("derivation_function") == "MD5"
        assert result.get("iterations") == 1
        assert result.get("salt_used") is False
        assert "CWE-916" in str(result.get("cwe_ids", []))

    def test_weak_hmac_key(self, vulnerable_client):
        """Test that encryption tool uses weak HMAC key (CWE-326)."""
        result = vulnerable_client.call_tool(
            "vulnerable_encryption_tool_endpoint",
            {"data": "data to sign", "action": "sign"},
        )
        assert result.get("vulnerable") is True
        assert result.get("key_length") == 3  # 3-byte key "key"
        assert result.get("key_secure") is False
        assert "CWE-326" in str(result.get("cwe_ids", []))

    def test_encrypt_decrypt_roundtrip(self, vulnerable_client):
        """Test that encrypt/decrypt roundtrip works (despite being vulnerable)."""
        # Encrypt
        encrypt_result = vulnerable_client.call_tool(
            "vulnerable_encryption_tool_endpoint",
            {"data": "Hello World", "action": "encrypt"},
        )
        assert encrypt_result.get("ciphertext") is not None

        # Decrypt
        decrypt_result = vulnerable_client.call_tool(
            "vulnerable_encryption_tool_endpoint",
            {"data": encrypt_result["ciphertext"], "action": "decrypt"},
        )
        assert decrypt_result.get("vulnerable") is True
        assert "Hello World" in str(decrypt_result.get("plaintext", ""))


class TestHardenedCryptoTools:
    """Tests for hardened crypto tools - should NOT perform weak crypto."""

    def test_hardened_crypto_no_execution(self, hardened_client):
        """Test hardened crypto tool stores request without executing."""
        result = hardened_client.call_tool(
            "vulnerable_crypto_tool_endpoint", {"password": "test123", "action": "hash"}
        )
        assert result.get("safe") is True
        assert result.get("vulnerable") is False or result.get("vulnerable") is None
        # Should NOT contain actual MD5 hash
        assert result.get("hash") is None
        # Should contain recommendation
        assert (
            "bcrypt" in str(result).lower()
            or "scrypt" in str(result).lower()
            or "argon2" in str(result).lower()
        )

    def test_hardened_encryption_no_execution(self, hardened_client):
        """Test hardened encryption tool stores request without encrypting."""
        result = hardened_client.call_tool(
            "vulnerable_encryption_tool_endpoint",
            {"data": "secret data", "action": "encrypt"},
        )
        assert result.get("safe") is True
        assert result.get("vulnerable") is False or result.get("vulnerable") is None
        # Should NOT contain actual ciphertext
        assert result.get("ciphertext") is None
        # Should contain recommendation
        assert "aes-gcm" in str(result).lower() or "gcm" in str(result).lower()


class TestCryptoOWASPCompliance:
    """Tests validating OWASP A02:2021 coverage."""

    def test_owasp_a02_coverage(self, vulnerable_client):
        """Verify all OWASP A02:2021 patterns are covered."""
        # Test all crypto actions
        actions = [
            ("hash", "CWE-328"),
            ("salt_hash", "CWE-916"),
            ("random", "CWE-330"),
        ]
        for action, expected_cwe in actions:
            result = vulnerable_client.call_tool(
                "vulnerable_crypto_tool_endpoint",
                {"password": "test", "action": action},
            )
            assert result.get("vulnerable") is True, (
                f"Action {action} should be vulnerable"
            )
            assert expected_cwe in str(result.get("cwe_ids", [])), (
                f"Action {action} should have {expected_cwe}"
            )

    def test_encryption_owasp_coverage(self, vulnerable_client):
        """Verify encryption patterns are covered."""
        actions = [
            ("encrypt", "CWE-327"),
            ("derive_key", "CWE-916"),
            ("sign", "CWE-326"),
        ]
        for action, expected_cwe in actions:
            result = vulnerable_client.call_tool(
                "vulnerable_encryption_tool_endpoint",
                {"data": "test", "action": action},
            )
            assert result.get("vulnerable") is True, (
                f"Action {action} should be vulnerable"
            )
            assert expected_cwe in str(result.get("cwe_ids", [])), (
                f"Action {action} should have {expected_cwe}"
            )

    def test_all_tools_report_owasp_reference(self, vulnerable_client):
        """Verify all crypto tools reference OWASP A02:2021."""
        # Crypto tool
        result = vulnerable_client.call_tool(
            "vulnerable_crypto_tool_endpoint", {"password": "test", "action": "hash"}
        )
        assert "A02:2021" in str(result.get("owasp", ""))

        # Encryption tool
        result = vulnerable_client.call_tool(
            "vulnerable_encryption_tool_endpoint", {"data": "test", "action": "encrypt"}
        )
        assert "A02:2021" in str(result.get("owasp", ""))
