"""
Testbed Info Metadata Consistency Tests

Tests for Stage 3 fixes validating that get_testbed_info metadata correctly reflects
the actual tool count (57 tools after Challenge #20 addition) and challenge count (20 challenges).

These tests implement TEST-REQ-001, TEST-REQ-002, and TEST-REQ-003 from the Stage 2 code review,
validating the fixes applied in FIX-001, FIX-002, and FIX-003.

Test Coverage:
- [TEST-001] Tool count consistency (get_testbed_info vs actual @mcp.tool decorators)
- [TEST-002] Challenge count consistency (challenges.total vs len(challenges.list))
- [TEST-003] expected_results.json synchronization with runtime metadata

Validates fixes for:
- ISSUE-001: Tool count metadata inconsistencies (56 vs 57 actual tools)
- ISSUE-002: Challenge count metadata inconsistencies (19 vs 20 actual challenges)

Usage:
    pytest tests/test_testbed_info.py -v
"""

import pytest
import sys
import json
import asyncio
from pathlib import Path
from typing import Dict, Any

# Import server to get get_testbed_info and count actual tools
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import the server module to access get_testbed_info and count decorated tools
try:
    import server
    from server import get_testbed_info, mcp
except ImportError as e:
    pytest.skip(f"Server module not available: {e}", allow_module_level=True)


class TestToolCountConsistency:
    """
    [TEST-001] Validates FIX-001: Tool count consistency

    Fulfills: TEST-REQ-001
    Validates: FIX-001 (src/server.py lines 2171-2178)
    Covers: ISSUE-001
    """

    @pytest.mark.asyncio
    async def test_tool_count_matches_decorator_count(self):
        """
        Happy path: Verify get_testbed_info returns correct total_tools count
        matching actual @mcp.tool count.

        After Challenge #20 addition, the actual tool count is 57.
        FIX-001 updated total_tools from 56 to 57.
        """
        # Get runtime metadata (await async function)
        info = await get_testbed_info()

        # Count actual tools registered with @mcp.tool decorator
        # The mcp.tool decorator registers tools in the internal registry
        tools_list = await mcp.list_tools()
        actual_tool_count = len(tools_list)

        # Verify reported total matches actual count
        assert info["tool_categories"]["total_tools"] == actual_tool_count, (
            f"get_testbed_info reports {info['tool_categories']['total_tools']} tools "
            f"but {actual_tool_count} tools are actually registered"
        )

        # After Challenge #20, we expect exactly 57 tools
        assert info["tool_categories"]["total_tools"] == 57, (
            f"Expected 57 tools after Challenge #20, got {info['tool_categories']['total_tools']}"
        )

        print(f"✓ Tool count consistency validated: {actual_tool_count} tools reported and registered")

    @pytest.mark.asyncio
    async def test_category_sum_equals_total(self):
        """
        Edge case: Verify sum of category counts equals total_tools.

        Tests that breakdown categories (high_risk_vulnerable, medium_risk_vulnerable,
        safe_control, info, utility) sum to the reported total.
        """
        info = await get_testbed_info()
        categories = info["tool_categories"]

        # Calculate sum of all categories
        category_sum = (
            categories["high_risk_vulnerable"] +
            categories["medium_risk_vulnerable"] +
            categories["safe_control"] +
            categories["info"] +
            categories["utility"]
        )

        # Verify sum matches total
        assert category_sum == categories["total_tools"], (
            f"Category sum ({category_sum}) does not match total_tools ({categories['total_tools']}). "
            f"Breakdown: HIGH={categories['high_risk_vulnerable']}, "
            f"MEDIUM={categories['medium_risk_vulnerable']}, "
            f"SAFE={categories['safe_control']}, "
            f"INFO={categories['info']}, "
            f"UTILITY={categories['utility']}"
        )

        print(f"✓ Category sum validated: {category_sum} = total_tools")

    @pytest.mark.asyncio
    async def test_medium_risk_count_after_fix(self):
        """
        Regression test: Verify medium_risk_vulnerable increased from 9 to 10
        after Challenge #20 (vulnerable_content_processor_tool) addition.

        Validates FIX-001 which updated medium_risk_vulnerable from 9 to 10.
        """
        info = await get_testbed_info()

        # After FIX-001, medium_risk_vulnerable should be 10 (not 9)
        assert info["tool_categories"]["medium_risk_vulnerable"] == 10, (
            f"Expected medium_risk_vulnerable=10 after Challenge #20, "
            f"got {info['tool_categories']['medium_risk_vulnerable']}"
        )

        print("✓ Medium risk count validated: 10 tools (includes Challenge #20)")

    @pytest.mark.asyncio
    async def test_high_risk_count_unchanged(self):
        """
        Regression test: Verify high_risk_vulnerable remains at 30.

        Challenge #20 added a MEDIUM risk tool, so HIGH risk should be unchanged.
        """
        info = await get_testbed_info()

        # HIGH risk should still be 30 (unchanged)
        assert info["tool_categories"]["high_risk_vulnerable"] == 30, (
            f"Expected high_risk_vulnerable=30, got {info['tool_categories']['high_risk_vulnerable']}"
        )

        print("✓ High risk count validated: 30 tools (unchanged)")


class TestChallengeCountConsistency:
    """
    [TEST-002] Validates FIX-002: Challenge count consistency

    Fulfills: TEST-REQ-002
    Validates: FIX-002 (src/server.py lines 2184-2185)
    Covers: ISSUE-002
    """

    @pytest.mark.asyncio
    async def test_challenge_total_matches_list_length(self):
        """
        Happy path: Verify challenges.total equals len(challenges.list).

        After Challenge #20 addition, total should be 20.
        FIX-002 updated challenges.total from 19 to 20.
        """
        info = await get_testbed_info()
        challenges = info["challenges"]

        # Verify total matches list length
        assert challenges["total"] == len(challenges["list"]), (
            f"challenges.total ({challenges['total']}) does not match "
            f"len(challenges.list) ({len(challenges['list'])})"
        )

        # After Challenge #20, expect exactly 20 challenges
        assert challenges["total"] == 20, (
            f"Expected 20 challenges after Challenge #20, got {challenges['total']}"
        )

        print(f"✓ Challenge count consistency validated: {challenges['total']} challenges")

    @pytest.mark.asyncio
    async def test_no_duplicate_challenges(self):
        """
        Edge case: Verify no duplicate challenge entries in list.

        Tests that each challenge appears exactly once in the challenges list.
        """
        info = await get_testbed_info()
        challenge_list = info["challenges"]["list"]

        # Check for duplicates by comparing list length to set length
        unique_challenges = set(challenge_list)
        assert len(challenge_list) == len(unique_challenges), (
            f"Duplicate challenges found: {len(challenge_list)} total, "
            f"{len(unique_challenges)} unique. "
            f"Duplicates: {[c for c in challenge_list if challenge_list.count(c) > 1]}"
        )

        print(f"✓ No duplicate challenges: all {len(challenge_list)} are unique")

    @pytest.mark.asyncio
    async def test_challenge_numbering_sequential(self):
        """
        Edge case: Verify no missing challenge numbers (1-20 sequential).

        Tests that challenges are numbered sequentially from 1 to 20 without gaps.
        """
        info = await get_testbed_info()
        challenge_list = info["challenges"]["list"]

        # Extract challenge numbers from strings like "Challenge #N: Description"
        challenge_numbers = []
        for challenge in challenge_list:
            # Extract number after "Challenge #"
            if "Challenge #" in challenge:
                try:
                    num_str = challenge.split("Challenge #")[1].split(":")[0]
                    challenge_numbers.append(int(num_str))
                except (IndexError, ValueError) as e:
                    pytest.fail(f"Failed to parse challenge number from: {challenge}. Error: {e}")

        # Verify we have all numbers from 1 to 20
        expected_numbers = set(range(1, 21))  # 1-20 inclusive
        actual_numbers = set(challenge_numbers)

        missing = expected_numbers - actual_numbers
        extra = actual_numbers - expected_numbers

        assert missing == set(), f"Missing challenge numbers: {sorted(missing)}"
        assert extra == set(), f"Extra challenge numbers: {sorted(extra)}"
        assert len(challenge_numbers) == 20, f"Expected 20 challenges, got {len(challenge_numbers)}"

        print(f"✓ Challenge numbering sequential: 1-20 complete")

    @pytest.mark.asyncio
    async def test_challenge_20_present(self):
        """
        Regression test: Verify Challenge #20 is present in the list.

        Validates that FIX-002 correctly added Challenge #20 to the challenges list.
        """
        info = await get_testbed_info()
        challenge_list = info["challenges"]["list"]

        # Check for Challenge #20 in the list
        challenge_20_found = any("Challenge #20" in c for c in challenge_list)
        assert challenge_20_found, (
            "Challenge #20: Content Type Confusion Attack not found in challenges list"
        )

        # Verify the exact string for Challenge #20
        challenge_20_text = next((c for c in challenge_list if "Challenge #20" in c), None)
        assert challenge_20_text == "Challenge #20: Content Type Confusion Attack (NEW)", (
            f"Challenge #20 text mismatch. Expected: "
            f"'Challenge #20: Content Type Confusion Attack (NEW)', "
            f"Got: '{challenge_20_text}'"
        )

        print("✓ Challenge #20 present: 'Content Type Confusion Attack (NEW)'")


class TestExpectedResultsSync:
    """
    [TEST-003] Validates FIX-003: expected_results.json synchronization

    Fulfills: TEST-REQ-003
    Validates: FIX-003 (expected_results.json lines 34-40)
    Covers: ISSUE-001 (expected_results.json metadata divergence)
    """

    @pytest.mark.asyncio
    async def test_expected_results_total_tools_matches(self):
        """
        Happy path: Verify expected_results.json total_tools matches get_testbed_info output.

        FIX-003 updated expected_results.json total_tools from 56 to 57.
        """
        # Load expected_results.json
        expected_results_path = Path(__file__).parent.parent / "expected_results.json"
        with open(expected_results_path, "r") as f:
            expected_results = json.load(f)

        # Get runtime metadata
        info = await get_testbed_info()

        # Compare tool counts
        expected_total = expected_results["expected_assessment_results"]["summary"]["total_tools"]
        actual_total = info["tool_categories"]["total_tools"]

        assert expected_total == actual_total, (
            f"expected_results.json reports {expected_total} tools "
            f"but get_testbed_info reports {actual_total} tools"
        )

        # Both should be 57 after Challenge #20
        assert expected_total == 57, (
            f"expected_results.json should report 57 tools after Challenge #20, got {expected_total}"
        )

        print(f"✓ expected_results.json synchronized: {expected_total} tools")

    @pytest.mark.asyncio
    async def test_expected_results_vulnerable_tools_matches(self):
        """
        Edge case: Verify vulnerable_tools count matches expected_detections.

        Both fields should reflect the same count (40 vulnerable tools).
        """
        # Load expected_results.json
        expected_results_path = Path(__file__).parent.parent / "expected_results.json"
        with open(expected_results_path, "r") as f:
            expected_results = json.load(f)

        summary = expected_results["expected_assessment_results"]["summary"]

        # Verify vulnerable_tools matches expected_detections
        assert summary["vulnerable_tools"] == summary["expected_detections"], (
            f"vulnerable_tools ({summary['vulnerable_tools']}) should match "
            f"expected_detections ({summary['expected_detections']})"
        )

        # Both should be 40 (30 HIGH + 10 MEDIUM)
        assert summary["vulnerable_tools"] == 40, (
            f"Expected 40 vulnerable tools (30 HIGH + 10 MEDIUM), "
            f"got {summary['vulnerable_tools']}"
        )

        print(f"✓ Vulnerable tool count validated: {summary['vulnerable_tools']} tools")

    @pytest.mark.asyncio
    async def test_expected_results_breakdown_matches_runtime(self):
        """
        Edge case: Verify expected_results.json tool category breakdown
        matches get_testbed_info categories.

        Tests that HIGH+MEDIUM vulnerable counts align between static
        documentation and runtime metadata.
        """
        # Load expected_results.json
        expected_results_path = Path(__file__).parent.parent / "expected_results.json"
        with open(expected_results_path, "r") as f:
            expected_results = json.load(f)

        # Get runtime metadata
        info = await get_testbed_info()

        # Calculate vulnerable total from runtime
        runtime_vulnerable = (
            info["tool_categories"]["high_risk_vulnerable"] +
            info["tool_categories"]["medium_risk_vulnerable"]
        )

        # Get expected vulnerable from expected_results.json
        expected_vulnerable = expected_results["expected_assessment_results"]["summary"]["vulnerable_tools"]

        assert runtime_vulnerable == expected_vulnerable, (
            f"Runtime vulnerable count ({runtime_vulnerable}) does not match "
            f"expected_results.json ({expected_vulnerable}). "
            f"Runtime: HIGH={info['tool_categories']['high_risk_vulnerable']}, "
            f"MEDIUM={info['tool_categories']['medium_risk_vulnerable']}"
        )

        print(f"✓ Category breakdown synchronized: {runtime_vulnerable} vulnerable tools")

    @pytest.mark.asyncio
    async def test_expected_results_safe_tools_count(self):
        """
        Regression test: Verify safe_tools count is 15 in expected_results.json.

        Safe tools should be unchanged (15 tools).
        """
        # Load expected_results.json
        expected_results_path = Path(__file__).parent.parent / "expected_results.json"
        with open(expected_results_path, "r") as f:
            expected_results = json.load(f)

        # Get runtime metadata
        info = await get_testbed_info()

        # Compare safe tool counts
        expected_safe = expected_results["expected_assessment_results"]["summary"]["safe_tools"]
        runtime_safe = info["tool_categories"]["safe_control"]

        assert expected_safe == runtime_safe, (
            f"Safe tools mismatch: expected_results.json={expected_safe}, "
            f"runtime={runtime_safe}"
        )

        # Both should be 15 (unchanged)
        assert expected_safe == 15, f"Expected 15 safe tools, got {expected_safe}"

        print(f"✓ Safe tool count validated: {expected_safe} tools (unchanged)")


class TestRegressionPrevention:
    """
    Additional regression tests to prevent future metadata drift.

    These tests catch common errors that led to ISSUE-001 and ISSUE-002.
    """

    @pytest.mark.asyncio
    async def test_tool_count_does_not_regress(self):
        """
        Error case: Alert if tool count drops below 57 (regression detection).

        Protects against accidental tool removal or metadata updates.
        """
        info = await get_testbed_info()

        # Tool count should never drop below 57 after Challenge #20
        assert info["tool_categories"]["total_tools"] >= 57, (
            f"Tool count regression detected: {info['tool_categories']['total_tools']} < 57. "
            f"This indicates tools were removed or metadata was incorrectly updated."
        )

        print(f"✓ No tool count regression: {info['tool_categories']['total_tools']} >= 57")

    @pytest.mark.asyncio
    async def test_challenge_count_does_not_regress(self):
        """
        Error case: Alert if challenge count drops below 20 (regression detection).

        Protects against accidental challenge removal or metadata updates.
        """
        info = await get_testbed_info()

        # Challenge count should never drop below 20 after Challenge #20
        assert info["challenges"]["total"] >= 20, (
            f"Challenge count regression detected: {info['challenges']['total']} < 20. "
            f"This indicates challenges were removed or metadata was incorrectly updated."
        )

        print(f"✓ No challenge count regression: {info['challenges']['total']} >= 20")

    @pytest.mark.asyncio
    async def test_metadata_consistency_cross_check(self):
        """
        Error case: Cross-check all metadata sources for consistency.

        Validates that get_testbed_info, expected_results.json, and actual
        tool registration are all in sync.
        """
        # Load expected_results.json
        expected_results_path = Path(__file__).parent.parent / "expected_results.json"
        with open(expected_results_path, "r") as f:
            expected_results = json.load(f)

        # Get runtime metadata
        info = await get_testbed_info()

        # Count actual registered tools
        tools_list = await mcp.list_tools()
        actual_tool_count = len(tools_list)

        # Get counts from all sources
        runtime_total = info["tool_categories"]["total_tools"]
        expected_total = expected_results["expected_assessment_results"]["summary"]["total_tools"]

        # All three should match
        assert runtime_total == expected_total == actual_tool_count, (
            f"Metadata inconsistency detected across sources:\n"
            f"  - get_testbed_info: {runtime_total}\n"
            f"  - expected_results.json: {expected_total}\n"
            f"  - Actual registered tools: {actual_tool_count}\n"
            f"All three must be in sync."
        )

        print(f"✓ Cross-source consistency validated: {actual_tool_count} tools across all sources")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
