"""
Tests for Challenge #24: Binary Resource Attacks

This module tests MCP binary resources with path traversal, blob generation,
and polyglot file attacks:
- binary://{filepath} - Path traversal to read system files (CWE-22, CWE-434)
- blob://{size}/{content_type} - Memory exhaustion DoS (CWE-409, CWE-400)
- polyglot://{base_type}/{hidden_type} - Dual-format file injection (CWE-434, CWE-436)

Usage:
    pytest tests/test_binary_resource_attacks.py -v
    pytest tests/test_binary_resource_attacks.py -v -k "path_traversal"

Coverage: Challenge #24 (Binary Resource Attacks)
CWEs: CWE-22, CWE-400, CWE-409, CWE-434, CWE-436
Source: MCP Conformance Suite - resources.ts
"""

import base64
import json
import pytest


def _extract_result(result: dict) -> dict:
    """Extract result dict from resource response.

    Helper function for all test classes to parse MCP resource responses.
    Handles both dict results and contents-based formats.
    """
    if isinstance(result, dict):
        # Check if it's wrapped in contents
        if "contents" in result:
            contents = result["contents"]
            if isinstance(contents, list) and len(contents) > 0:
                first_content = contents[0]
                if "text" in first_content:
                    try:
                        return json.loads(first_content["text"])
                    except (json.JSONDecodeError, TypeError):
                        pass
        # Direct dict result
        return result
    return {}


def _extract_blob(result: dict) -> bytes:
    """Extract binary blob from resource result.

    Returns decoded binary content from base64 blob field.
    """
    extracted = _extract_result(result)
    if "contents" in extracted:
        contents = extracted["contents"]
        if isinstance(contents, list) and len(contents) > 0:
            blob_b64 = contents[0].get("blob", "")
            if blob_b64:
                return base64.b64decode(blob_b64)
    if "simulated_content_b64" in extracted:
        return base64.b64decode(extracted["simulated_content_b64"])
    return b""


class TestBinaryPathTraversal:
    """Tests for binary://{filepath} path traversal vulnerability (CWE-22).

    Note: FastMCP resource templates match single path segments, so deep
    path traversal (../../../../etc/passwd) is normalized by MCP. We test:
    1. Normal file access (image.png, document.pdf)
    2. Simulated sensitive files (etc/passwd, etc/shadow, proc/self/environ)
    3. Vulnerability indicators and CWE codes
    """

    def test_normal_file_png(self, vulnerable_client):
        """Normal PNG file access returns binary content."""
        result = vulnerable_client.read_resource("binary://image.png")
        extracted = _extract_result(result)
        assert extracted.get("file_found") is True
        assert extracted.get("mime_type") == "image/png"
        blob = _extract_blob(result)
        # PNG magic bytes
        assert blob[:4] == b"\x89PNG"

    def test_normal_file_pdf(self, vulnerable_client):
        """Normal PDF file access returns binary content."""
        result = vulnerable_client.read_resource("binary://document.pdf")
        extracted = _extract_result(result)
        assert extracted.get("file_found") is True
        assert extracted.get("mime_type") == "application/pdf"
        blob = _extract_blob(result)
        # PDF magic bytes
        assert blob[:5] == b"%PDF-"

    def test_normal_file_zip(self, vulnerable_client):
        """Normal ZIP file access returns binary content."""
        result = vulnerable_client.read_resource("binary://archive.zip")
        extracted = _extract_result(result)
        assert extracted.get("file_found") is True
        assert extracted.get("mime_type") == "application/zip"
        blob = _extract_blob(result)
        # ZIP magic bytes
        assert blob[:2] == b"PK"

    def test_sensitive_file_passwd(self, vulnerable_client):
        """Accessing passwd file (simulated) returns sensitive content."""
        # Note: MCP normalizes paths, so we access the simulated file directly
        result = vulnerable_client.read_resource("binary://passwd")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("file_found") is True
        blob = _extract_blob(result)
        assert b"root:" in blob

    def test_sensitive_file_shadow(self, vulnerable_client):
        """Accessing shadow file (simulated) returns password hashes."""
        result = vulnerable_client.read_resource("binary://shadow")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("file_found") is True
        blob = _extract_blob(result)
        # Shadow file contains password hash
        assert b"$6$" in blob or b"root:" in blob

    def test_sensitive_file_environ(self, vulnerable_client):
        """Accessing environ file (simulated) exposes secrets."""
        result = vulnerable_client.read_resource("binary://environ")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("file_found") is True
        blob = _extract_blob(result)
        # Environ contains secrets
        assert b"SECRET" in blob or b"PATH" in blob

    def test_path_with_dotdot_detected(self, vulnerable_client):
        """Path with .. component is detected and flagged."""
        # Note: Even single ../ is detected
        result = vulnerable_client.read_resource("binary://..passwd")
        extracted = _extract_result(result)
        # Should detect path traversal attempt
        assert extracted.get("vulnerable") is True
        assert extracted.get("path_traversal_detected") is True

    def test_cwe_22_indicator(self, vulnerable_client):
        """Response includes CWE-22 (Path Traversal) indicator."""
        result = vulnerable_client.read_resource("binary://passwd")
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert "CWE-22" in cwe_ids

    def test_nonexistent_file_error(self, vulnerable_client):
        """Nonexistent file returns error message."""
        result = vulnerable_client.read_resource("binary://nonexistent_file_xyz.txt")
        extracted = _extract_result(result)
        assert extracted.get("file_found") is False
        assert "error" in extracted

    def test_mcp_blob_format(self, vulnerable_client):
        """Response includes MCP-compliant blob format."""
        result = vulnerable_client.read_resource("binary://image.png")
        extracted = _extract_result(result)
        assert "contents" in extracted
        contents = extracted["contents"]
        assert isinstance(contents, list)
        assert len(contents) > 0
        assert "blob" in contents[0]
        assert "mimeType" in contents[0]


class TestBlobGenerator:
    """Tests for blob://{size}/{mime_base}/{mime_subtype} DoS vulnerability (CWE-409, CWE-400).

    Note: URI format is blob://SIZE/MIME_BASE/MIME_SUBTYPE to handle MCP path segments.
    Example: blob://100/application/octet-stream (size=100, mime=application/octet-stream)
    """

    def test_small_blob_generation(self, vulnerable_client):
        """Small blob (100 bytes) is generated successfully."""
        result = vulnerable_client.read_resource("blob://100/application/octet-stream")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("requested_size") == 100
        assert extracted.get("actual_size") == 100
        blob = _extract_blob(result)
        assert len(blob) == 100

    def test_large_blob_request(self, vulnerable_client):
        """Large blob request (100MB) shows vulnerability but is capped for safety."""
        result = vulnerable_client.read_resource("blob://100000000/application/zip")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("requested_size") == 100000000
        # Demo server caps at 10KB for safety
        assert extracted.get("actual_size") <= 10 * 1024
        assert extracted.get("size_limit_applied") is True

    def test_massive_blob_dos_risk_high(self, vulnerable_client):
        """1GB blob request shows HIGH DoS risk."""
        result = vulnerable_client.read_resource("blob://1000000000/application/octet-stream")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("dos_risk") == "HIGH - Large blob requested"

    def test_moderate_blob_dos_risk_medium(self, vulnerable_client):
        """50KB blob request shows MEDIUM DoS risk."""
        result = vulnerable_client.read_resource("blob://50000/application/octet-stream")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("dos_risk") == "MEDIUM - Moderate blob size"

    def test_arbitrary_mime_type(self, vulnerable_client):
        """Arbitrary MIME type is accepted (vulnerability)."""
        result = vulnerable_client.read_resource("blob://100/application/x-malicious-type")
        extracted = _extract_result(result)
        assert extracted.get("content_type_accepted") == "application/x-malicious-type"
        # MIME flows to MCP content
        contents = extracted.get("contents", [])
        if contents:
            assert contents[0].get("mimeType") == "application/x-malicious-type"

    def test_executable_mime_type(self, vulnerable_client):
        """Executable MIME type is accepted (vulnerability)."""
        result = vulnerable_client.read_resource("blob://1024/application/x-executable")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("content_type_accepted") == "application/x-executable"

    def test_invalid_size_defaults_to_1024(self, vulnerable_client):
        """Invalid size parameter defaults to 1024 bytes."""
        result = vulnerable_client.read_resource("blob://invalid_size/text/plain")
        extracted = _extract_result(result)
        assert extracted.get("requested_size") == 1024

    def test_cwe_400_409_indicators(self, vulnerable_client):
        """Response includes CWE-400 and CWE-409 indicators."""
        result = vulnerable_client.read_resource("blob://1000000/application/zip")
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert "CWE-400" in cwe_ids
        assert "CWE-409" in cwe_ids

    def test_mcp_blob_format(self, vulnerable_client):
        """Response includes MCP-compliant blob format."""
        result = vulnerable_client.read_resource("blob://100/text/plain")
        extracted = _extract_result(result)
        assert "contents" in extracted
        contents = extracted["contents"]
        assert isinstance(contents, list)
        assert "blob" in contents[0]


class TestPolyglotResource:
    """Tests for polyglot://{base_type}/{hidden_type} file confusion (CWE-434, CWE-436)."""

    def test_gif_javascript_polyglot(self, vulnerable_client):
        """GIF-JavaScript polyglot is generated."""
        result = vulnerable_client.read_resource("polyglot://gif/javascript")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("polyglot_known") is True
        assert "GIF" in extracted.get("polyglot_description", "")
        blob = _extract_blob(result)
        # GIF magic bytes
        assert blob[:6] == b"GIF89a"
        # Contains JavaScript
        assert b"alert" in blob or b"=" in blob

    def test_image_javascript_polyglot(self, vulnerable_client):
        """Image/JavaScript polyglot is generated."""
        result = vulnerable_client.read_resource("polyglot://image/javascript")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("polyglot_known") is True

    def test_png_html_polyglot(self, vulnerable_client):
        """PNG-HTML polyglot is generated."""
        result = vulnerable_client.read_resource("polyglot://png/html")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("polyglot_known") is True
        blob = _extract_blob(result)
        # PNG magic bytes
        assert blob[:4] == b"\x89PNG"
        # Contains HTML
        assert b"<script>" in blob or b"<!--" in blob

    def test_pdf_javascript_polyglot(self, vulnerable_client):
        """PDF-JavaScript polyglot is generated."""
        result = vulnerable_client.read_resource("polyglot://pdf/javascript")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("polyglot_known") is True
        blob = _extract_blob(result)
        # PDF magic bytes
        assert blob[:5] == b"%PDF-"
        # Contains JavaScript
        assert b"JavaScript" in blob or b"JS" in blob

    def test_zip_html_polyglot(self, vulnerable_client):
        """ZIP-HTML polyglot is generated."""
        result = vulnerable_client.read_resource("polyglot://zip/html")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("polyglot_known") is True
        blob = _extract_blob(result)
        # ZIP magic bytes
        assert blob[:2] == b"PK"

    def test_jpeg_php_polyglot(self, vulnerable_client):
        """JPEG-PHP polyglot is generated."""
        result = vulnerable_client.read_resource("polyglot://jpeg/php")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("polyglot_known") is True
        blob = _extract_blob(result)
        # JPEG magic bytes
        assert blob[:2] == b"\xff\xd8"
        # Contains PHP
        assert b"<?php" in blob

    def test_unknown_polyglot_combination(self, vulnerable_client):
        """Unknown polyglot combination returns custom message."""
        result = vulnerable_client.read_resource("polyglot://unknown/unknown")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("polyglot_known") is False
        # Server returns "Custom polyglot attempt - no known pattern"
        assert "no known pattern" in extracted.get("polyglot_description", "").lower()

    def test_cwe_434_436_indicators(self, vulnerable_client):
        """Response includes CWE-434 and CWE-436 indicators."""
        result = vulnerable_client.read_resource("polyglot://image/javascript")
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert "CWE-434" in cwe_ids
        assert "CWE-436" in cwe_ids

    def test_mime_type_from_base_type(self, vulnerable_client):
        """MIME type is derived from base_type."""
        result = vulnerable_client.read_resource("polyglot://pdf/javascript")
        extracted = _extract_result(result)
        contents = extracted.get("contents", [])
        if contents:
            assert contents[0].get("mimeType") == "application/pdf"

    def test_mcp_blob_format(self, vulnerable_client):
        """Response includes MCP-compliant blob format."""
        result = vulnerable_client.read_resource("polyglot://gif/javascript")
        extracted = _extract_result(result)
        assert "contents" in extracted
        contents = extracted["contents"]
        assert isinstance(contents, list)
        assert "blob" in contents[0]
        assert "mimeType" in contents[0]


class TestBinaryResourceVulnerabilityIndicators:
    """Tests verifying vulnerability indicators across all binary resources."""

    @pytest.mark.parametrize(
        "uri",
        [
            "binary://passwd",
            "blob://1000000/application/zip",
            "polyglot://image/javascript",
        ],
    )
    def test_vulnerable_flag_present(self, vulnerable_client, uri):
        """All vulnerable resources have vulnerable=True flag."""
        result = vulnerable_client.read_resource(uri)
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True

    @pytest.mark.parametrize(
        "uri,expected_cwe",
        [
            ("binary://passwd", "CWE-22"),
            ("blob://1000000/application/zip", "CWE-400"),
            ("polyglot://image/javascript", "CWE-434"),
        ],
    )
    def test_cwe_ids_present(self, vulnerable_client, uri, expected_cwe):
        """Resources include appropriate CWE identifiers."""
        result = vulnerable_client.read_resource(uri)
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert expected_cwe in cwe_ids

    @pytest.mark.parametrize(
        "uri",
        [
            "binary://image.png",
            "blob://100/text/plain",
            "polyglot://gif/javascript",
        ],
    )
    def test_mcp_contents_format(self, vulnerable_client, uri):
        """All resources return MCP-compliant contents structure."""
        result = vulnerable_client.read_resource(uri)
        extracted = _extract_result(result)
        assert "contents" in extracted
        contents = extracted["contents"]
        assert isinstance(contents, list)
        assert len(contents) > 0
        assert "uri" in contents[0]
        assert "mimeType" in contents[0]
        assert "blob" in contents[0]


class TestMimeMismatch:
    """Tests for mime://{declared}/{actual} MIME type mismatch resource (CWE-436).

    This resource creates content with magic bytes from the "actual" type
    but declares a different MIME type in the response. Used to test
    inspector MIME type validation capabilities.

    URI format: mime://{declared_base}/{declared_sub}/{actual_base}/{actual_sub}
    Example: mime://image/jpeg/image/png (declares JPEG, returns PNG magic bytes)

    Coverage: Inspector Issue #127 - Binary Resource Vulnerability Detection
    CWE: CWE-436 (Interpretation Conflict)
    """

    def test_mime_mismatch_png_as_jpeg(self, vulnerable_client):
        """PNG magic bytes declared as JPEG - should be flagged as mismatch."""
        result = vulnerable_client.read_resource("mime://image/jpeg/image/png")
        extracted = _extract_result(result)

        assert extracted.get("vulnerable") is True
        assert extracted.get("mime_mismatch") is True
        assert extracted.get("declared_mime") == "image/jpeg"
        assert extracted.get("actual_mime") == "image/png"
        assert "CWE-436" in extracted.get("cwe_ids", [])

        # Verify content has PNG magic bytes
        blob = _extract_blob(result)
        assert blob[:4] == b"\x89PNG"

    def test_mime_mismatch_gif_as_text(self, vulnerable_client):
        """GIF magic bytes declared as text/plain - should be flagged."""
        result = vulnerable_client.read_resource("mime://text/plain/image/gif")
        extracted = _extract_result(result)

        assert extracted.get("vulnerable") is True
        assert extracted.get("mime_mismatch") is True
        assert extracted.get("declared_mime") == "text/plain"
        assert extracted.get("actual_mime") == "image/gif"

        # Verify content has GIF magic bytes
        blob = _extract_blob(result)
        assert blob[:6] == b"GIF89a"

    def test_mime_mismatch_pdf_as_zip(self, vulnerable_client):
        """ZIP magic bytes declared as PDF - should be flagged."""
        result = vulnerable_client.read_resource("mime://application/pdf/application/zip")
        extracted = _extract_result(result)

        assert extracted.get("vulnerable") is True
        assert extracted.get("mime_mismatch") is True
        assert extracted.get("declared_mime") == "application/pdf"
        assert extracted.get("actual_mime") == "application/zip"

        # Verify content has ZIP magic bytes (PK)
        blob = _extract_blob(result)
        assert blob[:2] == b"PK"

    def test_mime_matching_passes(self, vulnerable_client):
        """Same type for declared and actual - should NOT be flagged as vulnerable."""
        result = vulnerable_client.read_resource("mime://image/png/image/png")
        extracted = _extract_result(result)

        assert extracted.get("vulnerable") is False
        assert extracted.get("mime_mismatch") is False
        assert extracted.get("declared_mime") == "image/png"
        assert extracted.get("actual_mime") == "image/png"
        assert extracted.get("cwe_ids") == []  # No CWEs when types match

        # Verify content has PNG magic bytes
        blob = _extract_blob(result)
        assert blob[:4] == b"\x89PNG"

    def test_mime_vulnerability_indicators(self, vulnerable_client):
        """Verify vulnerability indicators are present in response."""
        result = vulnerable_client.read_resource("mime://image/jpeg/image/png")
        extracted = _extract_result(result)

        assert "vulnerable" in extracted
        assert "mime_mismatch" in extracted
        assert "declared_mime" in extracted
        assert "actual_mime" in extracted
        assert "cwe_ids" in extracted
        assert "description" in extracted

    def test_mime_unknown_type(self, vulnerable_client):
        """Unknown MIME type should return fallback content."""
        result = vulnerable_client.read_resource("mime://image/jpeg/unknown/type")
        extracted = _extract_result(result)

        assert extracted.get("vulnerable") is True  # Still a mismatch
        assert extracted.get("actual_mime") == "unknown/type"
        blob = _extract_blob(result)
        assert b"Unknown type" in blob

    def test_mime_mcp_contents_format(self, vulnerable_client):
        """MIME resource returns MCP-compliant contents structure."""
        result = vulnerable_client.read_resource("mime://image/jpeg/image/png")
        extracted = _extract_result(result)

        assert "contents" in extracted
        contents = extracted["contents"]
        assert isinstance(contents, list)
        assert len(contents) > 0
        assert "uri" in contents[0]
        assert "mimeType" in contents[0]
        assert "blob" in contents[0]

        # Declared mimeType should be the "wrong" one
        assert contents[0]["mimeType"] == "image/jpeg"

    @pytest.mark.parametrize(
        "declared,actual,expected_magic",
        [
            ("image/jpeg/image/png", "image/png", b"\x89PNG"),
            ("text/plain/image/jpeg", "image/jpeg", b"\xff\xd8\xff"),
            ("application/zip/application/pdf", "application/pdf", b"%PDF-"),
        ],
    )
    def test_mime_magic_bytes_correct(self, vulnerable_client, declared, actual, expected_magic):
        """Verify actual content magic bytes match the actual type parameter."""
        uri = f"mime://{declared}"
        result = vulnerable_client.read_resource(uri)
        blob = _extract_blob(result)
        assert blob[: len(expected_magic)] == expected_magic
