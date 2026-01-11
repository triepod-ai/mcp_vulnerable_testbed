"""
Tests for Resource Registry Completeness (TEST-REQ-001).

This module validates that all documented MCP resources in CLAUDE.md
are actually implemented in the server, preventing documentation drift.

Purpose:
- Detect missing resource implementations (like ISSUE-001)
- Detect undocumented resources
- Ensure documentation stays in sync with code

Related:
- ISSUE-001: CLAUDE.md documented non-existent resources (trusted://config, system://logs)
- FIX-001: Corrected documentation to match actual resources
- TEST-REQ-001: Automated detection of documentation/implementation drift

Usage:
    pytest tests/test_resource_registry.py -v
"""

import pytest


# ============================================================================
# Expected Resources (from CLAUDE.md Challenge #14 and #24)
# ============================================================================

# Challenge #14: Resource-Based Prompt Injection
# Note: Only resources without URI parameters appear in resources/list
CHALLENGE_14_LISTED_RESOURCES = [
    "internal://secrets",
    "public://announcements",
    "public://help",
]

# Resources with URI templates (not listed by FastMCP, but still accessible)
CHALLENGE_14_TEMPLATE_RESOURCES = [
    ("notes://{user_id}", "notes://user1"),  # (template, example)
    ("company://data/{department}", "company://data/engineering"),
]

# Challenge #24: Binary Resource Attacks (all use URI templates)
CHALLENGE_24_TEMPLATE_RESOURCES = [
    ("binary://{filepath}", "binary://image.png"),
    ("blob://{size}/{mime_base}/{mime_subtype}", "blob://1024/image/png"),
    ("polyglot://{base_type}/{hidden_type}", "polyglot://png/js"),
]

# All resources that should appear in resources/list
ALL_LISTED_RESOURCES = CHALLENGE_14_LISTED_RESOURCES


@pytest.mark.integration
class TestResourceRegistryCompleteness:
    """Tests that documented resources match implementation.

    Validates FIX-001 (corrected resource URIs in CLAUDE.md).
    """

    def test_all_listed_resources_exist(self, vulnerable_client):
        """Verify all non-templated resources exist in server (TEST-REQ-001 happy path).

        This test would have caught ISSUE-001 where CLAUDE.md documented:
        - trusted://config (did not exist)
        - system://logs (did not exist)

        FIX-001 corrected these to:
        - public://announcements (exists)
        - public://help (exists)

        Note: FastMCP only lists resources without URI parameters in resources/list.
        Templated resources (notes://{user_id}, binary://{filepath}, etc.) are
        tested separately for accessibility.
        """
        # Get actual resources from server
        resources = vulnerable_client.list_resources()
        assert resources is not None, "Server did not return resources list"

        actual_uris = [r["uri"] for r in resources]

        # Verify each documented non-templated resource exists
        missing = []
        for expected_uri in ALL_LISTED_RESOURCES:
            if expected_uri not in actual_uris:
                missing.append(expected_uri)

        assert (
            len(missing) == 0
        ), f"Documented non-templated resources not found in server: {missing}"

    def test_no_undocumented_resources(self, vulnerable_client):
        """Verify no undocumented resources exist (TEST-REQ-001 edge case).

        This catches the inverse problem: resources implemented but not
        documented in CLAUDE.md Challenge #14 or #24.
        """
        # Get actual resources from server
        resources = vulnerable_client.list_resources()
        assert resources is not None, "Server did not return resources list"

        actual_uris = [r["uri"] for r in resources]

        # Check for undocumented resources
        undocumented = []
        for actual_uri in actual_uris:
            if actual_uri not in ALL_LISTED_RESOURCES:
                undocumented.append(actual_uri)

        assert (
            len(undocumented) == 0
        ), f"Undocumented resources found in server: {undocumented}\n\nPlease update CLAUDE.md Challenge #14 or #24 documentation."

    def test_challenge_14_listed_resources_accessible(self, vulnerable_client):
        """Verify Challenge #14 listed resources are accessible.

        This test validates the non-templated resources from Challenge #14.
        Validates FIX-001 (corrected resource URIs).
        """
        resources = vulnerable_client.list_resources()
        actual_uris = [r["uri"] for r in resources]

        # Check listed resources (validates FIX-001)
        for uri in CHALLENGE_14_LISTED_RESOURCES:
            assert (
                uri in actual_uris
            ), f"Challenge #14 resource {uri} not found in server"

    def test_challenge_14_template_resources_accessible(self, vulnerable_client):
        """Verify Challenge #14 template resources can be accessed.

        Template resources (notes://{user_id}, company://data/{department})
        don't appear in resources/list but should be accessible via read.
        """
        for template, example_uri in CHALLENGE_14_TEMPLATE_RESOURCES:
            result = vulnerable_client.read_resource(example_uri)
            assert result is not None, f"Template resource {template} not accessible"
            assert not result.get("error"), f"Template resource {template} returned error: {result.get('result')}"

    def test_challenge_24_template_resources_accessible(self, vulnerable_client):
        """Verify Challenge #24 binary resources can be accessed.

        All Challenge #24 resources use URI templates and are tested for
        accessibility rather than listing.
        """
        for template, example_uri in CHALLENGE_24_TEMPLATE_RESOURCES:
            result = vulnerable_client.read_resource(example_uri)
            assert result is not None, f"Challenge #24 resource {template} not accessible"
            assert not result.get("error"), f"Challenge #24 resource {template} returned error: {result.get('result')}"

    def test_resource_count_matches_documentation(self, vulnerable_client):
        """Verify listed resource count matches documented count (TEST-REQ-001 error case).

        Quick sanity check: if count changes, documentation needs review.
        """
        resources = vulnerable_client.list_resources()
        actual_count = len(resources)
        expected_count = len(ALL_LISTED_RESOURCES)

        assert (
            actual_count == expected_count
        ), f"Listed resource count mismatch: expected {expected_count}, got {actual_count}\n\nThis indicates documentation drift. Please review CLAUDE.md."


@pytest.mark.integration
class TestBlobURIFormat:
    """Tests that blob URI format is correctly documented (TEST-REQ-002).

    Validates FIX-003 (corrected blob URI format in CLAUDE.md).
    """

    def test_blob_resource_accepts_three_segments(self, vulnerable_client):
        """Verify blob resource works with 3-segment format: blob://{size}/{mime_base}/{mime_subtype}.

        This test validates FIX-003 which corrected ISSUE-003 where CLAUDE.md
        documented incorrect format: blob://{size}/{content_type}

        Correct format: blob://{size}/{mime_base}/{mime_subtype}
        Example: blob://1024/image/png

        Note: Existing tests in test_binary_resource_attacks.py use correct
        format but did not explicitly document the contract. This test
        makes the contract explicit to prevent future regressions.
        """
        # Test with valid 3-segment blob URI
        result = vulnerable_client.read_resource("blob://1024/image/png")

        # Should succeed (not throw error)
        assert result is not None, "Blob resource failed with 3-segment format"
        assert not result.get("error"), f"Blob resource returned error: {result.get('result')}"

    def test_blob_uri_format_documented_in_claude_md(self):
        """Verify CLAUDE.md documents correct blob URI format (meta-test).

        This test reads CLAUDE.md directly to ensure documentation is correct.
        Prevents future regressions where code is correct but docs revert.
        """
        import re
        from pathlib import Path

        claude_md_path = Path(__file__).parent.parent / "CLAUDE.md"
        assert claude_md_path.exists(), "CLAUDE.md not found"

        claude_md_content = claude_md_path.read_text()

        # Search for blob URI documentation in Challenge #24
        # Should find: blob://{size}/{mime_base}/{mime_subtype}
        correct_format_pattern = r"blob://\{size\}/\{mime_base\}/\{mime_subtype\}"
        assert re.search(
            correct_format_pattern, claude_md_content
        ), "CLAUDE.md does not document correct 3-segment blob URI format"

        # Anti-pattern: ensure old format is NOT documented
        wrong_format_pattern = r"blob://\{size\}/\{content_type\}"
        assert not re.search(
            wrong_format_pattern, claude_md_content
        ), "CLAUDE.md still contains incorrect 2-segment blob URI format (ISSUE-003)"
