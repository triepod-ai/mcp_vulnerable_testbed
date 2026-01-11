"""
Content Type Confusion Vulnerability Tests (Challenge #20)

Tests for 4 content type confusion vulnerabilities:
1. CWE-436: MIME Type Mismatch (polyglot attacks)
2. CWE-20/CWE-400: Blind Base64 Decode (DoS via resource exhaustion)
3. CWE-611: Embedded URI SSRF (file:// scheme access)
4. CWE-434: Magic Byte Bypass (header-only validation)

Usage:
    pytest tests/test_content_type_confusion.py -v
    pytest tests/test_content_type_confusion.py -v -k "mime"
    pytest tests/test_content_type_confusion.py -v -k "base64"
    pytest tests/test_content_type_confusion.py -v -k "ssrf"
"""

import base64
import pytest


class TestMimeMismatch:
    """Tests for CWE-436: MIME type mismatch vulnerabilities."""

    def test_polyglot_png_javascript(self, vulnerable_client):
        """CWE-436: PNG magic bytes + JavaScript payload accepted."""
        # Create polyglot: PNG header + JavaScript
        png_magic = b"\x89PNG\r\n\x1a\n"
        js_payload = b"alert('xss');"
        polyglot = base64.b64encode(png_magic + js_payload).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": polyglot,
                "mime_type": "image/png",
                "encoding": "base64",
            },
        )

        assert result.get("vulnerable") is True
        assert result.get("mime_validated") is False
        assert result.get("magic_valid") is True  # Only magic bytes checked
        # Payload after magic should be exposed
        assert result.get("payload_after_magic") is not None

    def test_declared_vs_actual_mismatch(self, vulnerable_client):
        """CWE-436: Accepts content that doesn't match declared MIME type."""
        # Send plain text but claim it's JSON
        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "This is not JSON at all",
                "mime_type": "application/json",
                "encoding": "utf-8",
            },
        )

        assert result.get("vulnerable") is True
        assert "CWE-436" in result.get("cwe_ids", [])
        assert result.get("mime_validated") is False

    def test_jpeg_magic_with_malicious_payload(self, vulnerable_client):
        """CWE-434: JPEG magic + malicious payload passes validation."""
        # JPEG magic bytes + PHP code
        jpeg_magic = b"\xff\xd8\xff"
        php_payload = b"<?php system($_GET['cmd']); ?>"
        polyglot = base64.b64encode(jpeg_magic + php_payload).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": polyglot,
                "mime_type": "image/jpeg",
                "encoding": "base64",
            },
        )

        assert result.get("vulnerable") is True
        assert result.get("magic_valid") is True
        assert result.get("full_content_validated") is False


class TestBase64Bomb:
    """Tests for CWE-20/CWE-400: Blind base64 decode vulnerabilities."""

    def test_base64_decode_no_size_limit(self, vulnerable_client):
        """CWE-400: Base64 decoding without size validation."""
        # Create moderately large base64 content
        large_data = base64.b64encode(b"A" * 10000).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": large_data,
                "mime_type": "text/plain",
                "encoding": "base64",
            },
        )

        assert result.get("vulnerable") is True
        assert result.get("size_validated") is False
        assert "CWE-20" in result.get("cwe_ids", []) or "CWE-400" in result.get("cwe_ids", [])
        assert result.get("decoded_size") == 10000

    def test_base64_implicit_encoding(self, vulnerable_client):
        """CWE-20: Base64 triggered by MIME type containing 'base64'."""
        data = base64.b64encode(b"test data").decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": data,
                "mime_type": "application/base64",  # Triggers decode
                "encoding": "utf-8",  # Encoding says utf-8, but MIME type overrides
            },
        )

        assert result.get("vulnerable") is True
        assert "blind_base64_decode" in result.get("vulnerabilities_triggered", [])

    def test_expansion_ratio_tracked(self, vulnerable_client):
        """Verify expansion ratio is tracked for potential bomb detection."""
        # Base64 typically has 4:3 expansion ratio
        data = base64.b64encode(b"X" * 1000).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": data,
                "mime_type": "text/plain",
                "encoding": "base64",
            },
        )

        assert result.get("vulnerable") is True
        assert "expansion_ratio" in result
        # Base64 decodes to 75% of encoded size
        assert result.get("decoded_size") == 1000


class TestEmbeddedURISSRF:
    """Tests for CWE-611: Embedded URI SSRF vulnerabilities."""

    def test_file_uri_ssrf(self, vulnerable_client):
        """CWE-611: file:// URIs are processed and expose sensitive files."""
        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "Check this file: file:///etc/passwd",
                "mime_type": "text/plain",
                "encoding": "utf-8",
            },
        )

        assert result.get("vulnerable") is True
        assert result.get("ssrf_blocked") is False
        assert "CWE-611" in result.get("cwe_ids", [])
        assert result.get("embedded_uris_found") > 0
        # Verify file content was returned
        uri_contents = result.get("uri_contents", {})
        assert "file:///etc/passwd" in uri_contents
        assert "root:" in uri_contents.get("file:///etc/passwd", "")

    def test_multiple_embedded_uris(self, vulnerable_client):
        """CWE-611: Multiple URIs are all processed."""
        content = """
        File 1: file:///etc/passwd
        File 2: file:///app/private/credentials.txt
        Remote: https://evil.com/steal
        """

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": content,
                "mime_type": "text/plain",
                "encoding": "utf-8",
            },
        )

        assert result.get("vulnerable") is True
        assert result.get("embedded_uris_found") >= 2
        assert "embedded_uri_processing" in result.get("vulnerabilities_triggered", [])

    def test_sensitive_file_credentials(self, vulnerable_client):
        """CWE-611: Credential files are exposed via file:// SSRF."""
        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "Config: file:///app/private/credentials.txt",
                "mime_type": "text/plain",
                "encoding": "utf-8",
            },
        )

        assert result.get("vulnerable") is True
        uri_contents = result.get("uri_contents", {})
        credentials_content = uri_contents.get("file:///app/private/credentials.txt", "")
        # Verify sensitive data was exposed
        assert "PRODUCTION CREDENTIALS" in credentials_content or "Password" in credentials_content


class TestMagicByteBypass:
    """Tests for CWE-434: Magic byte bypass vulnerabilities."""

    def test_png_magic_with_executable(self, vulnerable_client):
        """CWE-434: PNG magic + executable code passes validation."""
        # PNG magic + shell script
        png_magic = b"\x89PNG\r\n\x1a\n"
        shell_script = b"#!/bin/bash\nrm -rf /\n"
        payload = base64.b64encode(png_magic + shell_script).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": payload,
                "mime_type": "image/png",
                "encoding": "base64",
            },
        )

        assert result.get("vulnerable") is True
        assert result.get("magic_valid") is True
        assert result.get("full_content_validated") is False
        assert "CWE-434" in result.get("cwe_ids", [])

    def test_gif_magic_with_javascript(self, vulnerable_client):
        """CWE-434: GIF magic + JavaScript accepted."""
        gif_magic = b"GIF89a"
        js_code = b"*/=alert('XSS')/*"
        payload = base64.b64encode(gif_magic + js_code).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": payload,
                "mime_type": "image/gif",
                "encoding": "base64",
            },
        )

        assert result.get("vulnerable") is True
        assert result.get("magic_valid") is True

    def test_payload_after_magic_exposed(self, vulnerable_client):
        """CWE-434: Payload after magic bytes is exposed in response."""
        # Create payload with magic + known malicious content
        png_magic = b"\x89PNG\r\n\x1a\n"
        malicious = b"MALICIOUS_PAYLOAD_HERE"
        payload = base64.b64encode(png_magic + malicious).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": payload,
                "mime_type": "image/png",
                "encoding": "base64",
            },
        )

        assert result.get("vulnerable") is True
        # Payload after magic should be returned (in hex)
        payload_hex = result.get("payload_after_magic")
        assert payload_hex is not None
        # "MALICIOUS" in hex (uppercase comparison)
        assert "4D414C4943494F5553" in payload_hex.upper()


class TestHardenedContentProcessor:
    """Tests for hardened version - should NOT be vulnerable."""

    def test_base64_blocked(self, hardened_client):
        """Hardened: Base64 encoding is blocked entirely."""
        data = base64.b64encode(b"test").decode()

        result = hardened_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": data,
                "mime_type": "text/plain",
                "encoding": "base64",
            },
        )

        assert result.get("safe") is True or result.get("vulnerable") is False
        assert result.get("encoding_blocked") is True
        assert result.get("status") == "rejected"

    def test_mime_type_allowlist(self, hardened_client):
        """Hardened: Only text-based MIME types accepted."""
        result = hardened_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "test content",
                "mime_type": "image/png",  # Binary type rejected
                "encoding": "utf-8",
            },
        )

        assert result.get("safe") is True or result.get("vulnerable") is False
        assert result.get("type_in_allowlist") is False
        assert result.get("status") == "rejected"

    def test_dangerous_uris_blocked(self, hardened_client):
        """Hardened: Dangerous URI schemes are blocked."""
        result = hardened_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "Attack: file:///etc/passwd",
                "mime_type": "text/plain",
                "encoding": "utf-8",
            },
        )

        assert result.get("safe") is True or result.get("vulnerable") is False
        assert result.get("ssrf_blocked") is True
        assert result.get("status") == "rejected"

    def test_safe_content_stored_with_hash(self, hardened_client):
        """Hardened: Safe content stored with hash reference."""
        result = hardened_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "This is safe plain text content",
                "mime_type": "text/plain",
                "encoding": "utf-8",
            },
        )

        assert result.get("safe") is True or result.get("vulnerable") is False
        assert result.get("status") == "stored_for_review"
        assert "content_hash" in result
        assert result.get("content_hash").startswith("sha256:")


class TestDocumentation:
    """Tests for documentation requirements."""

    def test_docstring_contains_challenge_reference(self):
        """Validates Challenge #20 is documented in the function."""
        from pathlib import Path

        src_file = Path(__file__).parent.parent / "src" / "vulnerable_tools.py"
        source_code = src_file.read_text()

        # Find the vulnerable_content_processor function
        func_start = source_code.find("def vulnerable_content_processor(")
        assert func_start > 0, "Function vulnerable_content_processor should exist"

        # Extract docstring
        docstring_start = source_code.find('"""', func_start)
        docstring_end = source_code.find('"""', docstring_start + 3)
        docstring = source_code[docstring_start + 3:docstring_end]

        assert "Challenge #20" in docstring, "Docstring should reference Challenge #20"
        assert "CWE-436" in docstring or "MIME" in docstring.upper()
        assert "CWE-434" in docstring or "Magic" in docstring
        assert "CWE-611" in docstring or "SSRF" in docstring.upper()


class TestCWECoverage:
    """Tests to verify all claimed CWEs are detectable."""

    def test_cwe_436_mime_mismatch(self, vulnerable_client):
        """Verify CWE-436 (Interpretation Conflict) is reported."""
        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "plain text content",
                "mime_type": "image/png",  # Mismatch
                "encoding": "utf-8",
            },
        )

        assert "CWE-436" in result.get("cwe_ids", [])

    def test_cwe_434_file_type_bypass(self, vulnerable_client):
        """Verify CWE-434 (Unrestricted Upload) is reported."""
        png_magic = b"\x89PNG\r\n\x1a\n" + b"malicious"
        payload = base64.b64encode(png_magic).decode()

        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": payload,
                "mime_type": "image/png",
                "encoding": "base64",
            },
        )

        assert "CWE-434" in result.get("cwe_ids", [])

    def test_cwe_20_improper_input(self, vulnerable_client):
        """Verify CWE-20 (Improper Input Validation) is reported."""
        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": base64.b64encode(b"data").decode(),
                "mime_type": "text/plain",
                "encoding": "base64",
            },
        )

        assert "CWE-20" in result.get("cwe_ids", [])

    def test_cwe_611_ssrf(self, vulnerable_client):
        """Verify CWE-611 (SSRF via URI) is reported."""
        result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool",
            {
                "content": "file:///etc/passwd",
                "mime_type": "text/plain",
                "encoding": "utf-8",
            },
        )

        assert "CWE-611" in result.get("cwe_ids", [])


class TestDualValidation:
    """Side-by-side comparison tests."""

    def test_same_input_different_outcomes(self, vulnerable_client, hardened_client):
        """Same polyglot payload produces different results."""
        # PNG magic + JavaScript
        png_magic = b"\x89PNG\r\n\x1a\n"
        js_payload = b"alert('xss');"
        polyglot = base64.b64encode(png_magic + js_payload).decode()

        params = {
            "content": polyglot,
            "mime_type": "image/png",
            "encoding": "base64",
        }

        vuln_result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool", params
        )
        hard_result = hardened_client.call_tool(
            "vulnerable_content_processor_tool", params
        )

        # Vulnerable server processes content
        assert vuln_result.get("vulnerable") is True
        assert vuln_result.get("magic_valid") is True

        # Hardened server rejects
        assert hard_result.get("safe") is True or hard_result.get("vulnerable") is False
        assert hard_result.get("encoding_blocked") is True or hard_result.get("type_in_allowlist") is False

    def test_file_uri_blocked_vs_processed(self, vulnerable_client, hardened_client):
        """File URI is processed on vulnerable, blocked on hardened."""
        params = {
            "content": "file:///etc/passwd",
            "mime_type": "text/plain",
            "encoding": "utf-8",
        }

        vuln_result = vulnerable_client.call_tool(
            "vulnerable_content_processor_tool", params
        )
        hard_result = hardened_client.call_tool(
            "vulnerable_content_processor_tool", params
        )

        # Vulnerable server exposes file contents
        assert vuln_result.get("vulnerable") is True
        assert vuln_result.get("ssrf_blocked") is False
        assert "root:" in str(vuln_result.get("uri_contents", {}))

        # Hardened server blocks
        assert hard_result.get("ssrf_blocked") is True
        assert hard_result.get("status") == "rejected"
