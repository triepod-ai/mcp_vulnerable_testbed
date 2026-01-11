"""
Performance Validation Tests

Tests resource consumption, concurrency handling, and performance characteristics
of both vulnerable and hardened servers.

Usage:
    pytest tests/test_performance_validation.py -v
    pytest tests/test_performance_validation.py -v -k "concurrent"
"""

import pytest
import time
import concurrent.futures
from typing import Dict, Any

# Mark entire module as slow - skipped in CI with -m "not slow"
pytestmark = pytest.mark.slow

# Fixtures provided by conftest.py: vulnerable_client, hardened_client


class TestConcurrentRequests:
    """Test server handling of concurrent requests."""

    def test_concurrent_requests_vulnerable(self, vulnerable_client):
        """Vulnerable server should handle concurrent requests."""
        num_requests = 20
        results = []

        def make_request(i: int) -> Dict[str, Any]:
            return vulnerable_client.call_tool(
                "vulnerable_calculator_tool", {"query": f"2+{i}"}
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All requests should complete
        assert len(results) == num_requests, (
            f"Expected {num_requests} results, got {len(results)}"
        )

        # All should be valid responses
        for i, result in enumerate(results):
            assert isinstance(result, dict), (
                f"Result {i} should be dict, got: {type(result)}"
            )

    def test_concurrent_requests_hardened(self, hardened_client):
        """Hardened server should handle concurrent requests."""
        num_requests = 20
        results = []

        def make_request(i: int) -> Dict[str, Any]:
            return hardened_client.call_tool(
                "safe_storage_tool_mcp", {"data": f"concurrent_data_{i}"}
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All requests should complete
        assert len(results) == num_requests, (
            f"Expected {num_requests} results, got {len(results)}"
        )

    def test_mixed_tool_concurrent_requests(self, vulnerable_client):
        """Server should handle concurrent requests to different tools."""
        tools = [
            ("vulnerable_calculator_tool", {"query": "2+2"}),
            ("vulnerable_system_exec_tool", {"command": "pwd"}),
            ("vulnerable_data_leak_tool", {"query": "test"}),
            ("safe_storage_tool_mcp", {"data": "test"}),
            ("safe_echo_tool_mcp", {"message": "test"}),
        ]

        def make_request(tool_args):
            tool_name, args = tool_args
            return vulnerable_client.call_tool(tool_name, args)

        # 4 requests per tool = 20 total
        all_requests = tools * 4

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, ta) for ta in all_requests]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 20, f"Expected 20 results, got {len(results)}"


class TestResponseTime:
    """Test response time characteristics."""

    def test_simple_request_response_time(self, vulnerable_client):
        """Simple requests should complete quickly."""
        start = time.time()

        result = vulnerable_client.call_tool("safe_echo_tool_mcp", {"message": "hello"})

        elapsed = time.time() - start

        assert elapsed < 5.0, f"Simple request took too long: {elapsed:.2f}s"
        assert isinstance(result, dict), "Should return valid response"

    def test_average_response_time(self, vulnerable_client):
        """Average response time should be reasonable."""
        times = []

        for i in range(10):
            start = time.time()
            vulnerable_client.call_tool("safe_storage_tool_mcp", {"data": f"test_{i}"})
            times.append(time.time() - start)

        avg_time = sum(times) / len(times)
        max_time = max(times)

        print(f"\nResponse times: avg={avg_time:.3f}s, max={max_time:.3f}s")

        assert avg_time < 2.0, f"Average response time too high: {avg_time:.2f}s"
        assert max_time < 5.0, f"Max response time too high: {max_time:.2f}s"


class TestMemoryHandling:
    """Test memory handling with various payload sizes."""

    @pytest.mark.parametrize("size", [1000, 5000, 10000, 50000])
    def test_increasing_payload_sizes(self, vulnerable_client, size: int):
        """Server should handle increasing payload sizes."""
        payload = "X" * size

        start = time.time()
        result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool", {"query": payload}
        )
        elapsed = time.time() - start

        assert isinstance(result, dict), f"Should return dict for {size} bytes"

        # Larger payloads may be slower but should still complete
        max_time = 10.0 if size > 10000 else 5.0
        assert elapsed < max_time, (
            f"Payload of {size} bytes took too long: {elapsed:.2f}s"
        )

    def test_many_small_requests(self, vulnerable_client):
        """Server should handle many small requests without memory leak."""
        for i in range(100):
            result = vulnerable_client.call_tool(
                "safe_storage_tool_mcp", {"data": f"small_data_{i}"}
            )
            assert isinstance(result, dict), f"Request {i} failed"

        # Final request should still work
        final = vulnerable_client.call_tool("get_testbed_info", {})
        assert isinstance(final, dict), "Server should still be responsive"


class TestRugPullStateMemory:
    """Test memory usage of rug pull state tracking."""

    def test_rug_pull_state_scaling(self, vulnerable_client):
        """Rug pull state tracking should not cause memory issues."""
        vulnerable_client.reset_state()

        # Make many rug pull calls
        for i in range(100):
            result = vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool", {"action": f"action_{i}"}
            )
            assert isinstance(result, dict), f"Call {i} failed"

        # Server should still be responsive
        info = vulnerable_client.call_tool("get_testbed_info", {})
        assert isinstance(info, dict), (
            "Server should be responsive after many rug pull calls"
        )


class TestErrorRecovery:
    """Test server recovery after errors."""

    def test_recovery_after_invalid_requests(self, vulnerable_client):
        """Server should recover after invalid requests."""
        # Send some invalid/edge case requests
        invalid_requests = [
            ("nonexistent_tool", {}),
            ("vulnerable_calculator_tool", {"wrong_param": "test"}),
            ("vulnerable_calculator_tool", {"query": None}),
        ]

        for tool_name, args in invalid_requests:
            try:
                vulnerable_client.call_tool(tool_name, args)
            except:
                pass  # Errors are expected

        # Server should still work
        result = vulnerable_client.call_tool(
            "safe_echo_tool_mcp", {"message": "still working"}
        )
        assert isinstance(result, dict), "Server should recover after invalid requests"

    def test_recovery_after_timeout_prone_requests(self, vulnerable_client):
        """Server should recover after slow requests."""
        # Large payload that might be slow
        vulnerable_client.call_tool(
            "vulnerable_calculator_tool", {"query": "A" * 50000}
        )

        # Normal request should still work
        result = vulnerable_client.call_tool(
            "safe_echo_tool_mcp", {"message": "quick request"}
        )
        assert isinstance(result, dict), "Server should handle requests after slow ones"


class TestServerStability:
    """Test overall server stability."""

    def test_sustained_load(self, vulnerable_client):
        """Server should remain stable under sustained load."""
        start_time = time.time()
        request_count = 0
        errors = 0

        # Run for 10 seconds or 50 requests, whichever comes first
        while time.time() - start_time < 10 and request_count < 50:
            try:
                result = vulnerable_client.call_tool(
                    "safe_storage_tool_mcp", {"data": f"load_test_{request_count}"}
                )
                if not isinstance(result, dict):
                    errors += 1
            except:
                errors += 1

            request_count += 1

        error_rate = errors / request_count if request_count > 0 else 1.0

        print(
            f"\nSustained load: {request_count} requests, {errors} errors ({error_rate:.1%})"
        )

        assert error_rate < 0.1, f"Error rate too high: {error_rate:.1%}"

    def test_both_servers_stable(self, vulnerable_client, hardened_client):
        """Both servers should remain stable under identical load."""

        def load_test(client, server_name: str) -> Dict[str, Any]:
            start_time = time.time()
            success = 0
            errors = 0

            for i in range(20):
                try:
                    result = client.call_tool(
                        "safe_storage_tool_mcp", {"data": f"stability_test_{i}"}
                    )
                    if isinstance(result, dict):
                        success += 1
                    else:
                        errors += 1
                except:
                    errors += 1

            elapsed = time.time() - start_time

            return {
                "server": server_name,
                "success": success,
                "errors": errors,
                "elapsed": elapsed,
                "rate": success / elapsed if elapsed > 0 else 0,
            }

        vuln_stats = load_test(vulnerable_client, "vulnerable")
        hard_stats = load_test(hardened_client, "hardened")

        print(f"\nVulnerable: {vuln_stats}")
        print(f"Hardened: {hard_stats}")

        # Both should have >90% success rate
        assert vuln_stats["errors"] < vuln_stats["success"] * 0.1, (
            f"Vulnerable server error rate too high: {vuln_stats}"
        )
        assert hard_stats["errors"] < hard_stats["success"] * 0.1, (
            f"Hardened server error rate too high: {hard_stats}"
        )


class TestPerformanceSummary:
    """Summary performance validation."""

    def test_performance_baseline(self, vulnerable_client, hardened_client):
        """
        Establish performance baseline for both servers.
        """

        def measure_performance(client, name: str) -> Dict[str, float]:
            # Warm up
            client.call_tool("safe_echo_tool_mcp", {"message": "warmup"})

            # Measure
            times = []
            for _ in range(10):
                start = time.time()
                client.call_tool("safe_echo_tool_mcp", {"message": "test"})
                times.append(time.time() - start)

            return {
                "server": name,
                "min": min(times),
                "max": max(times),
                "avg": sum(times) / len(times),
                "p95": sorted(times)[int(len(times) * 0.95)],
            }

        vuln_perf = measure_performance(vulnerable_client, "vulnerable")
        hard_perf = measure_performance(hardened_client, "hardened")

        print("\n=== Performance Baseline ===")
        print(
            f"Vulnerable: min={vuln_perf['min']:.3f}s, avg={vuln_perf['avg']:.3f}s, max={vuln_perf['max']:.3f}s"
        )
        print(
            f"Hardened:   min={hard_perf['min']:.3f}s, avg={hard_perf['avg']:.3f}s, max={hard_perf['max']:.3f}s"
        )

        # Both should have reasonable performance
        assert vuln_perf["avg"] < 2.0, (
            f"Vulnerable avg too slow: {vuln_perf['avg']:.2f}s"
        )
        assert hard_perf["avg"] < 2.0, f"Hardened avg too slow: {hard_perf['avg']:.2f}s"
