"""
SSRF Coverage Tests

Comprehensive testing of SSRF attack patterns including:
- Cloud metadata endpoints (AWS, GCP, Azure)
- Internal network ranges
- Localhost variants
- IPv6 addresses
- URL bypass techniques

Usage:
    pytest tests/test_ssrf_coverage.py -v
    pytest tests/test_ssrf_coverage.py -v -k "aws"
"""

import pytest


# Fixtures provided by conftest.py: vulnerable_client, hardened_client


class TestCloudMetadataEndpoints:
    """Test SSRF detection for cloud provider metadata endpoints."""

    @pytest.mark.parametrize(
        "url,provider,description",
        [
            # AWS
            pytest.param(
                "http://169.254.169.254/latest/meta-data/",
                "AWS",
                "Instance metadata root",
                id="aws-metadata-root",
            ),
            pytest.param(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "AWS",
                "IAM credentials",
                id="aws-iam-credentials",
            ),
            pytest.param(
                "http://169.254.169.254/latest/user-data/",
                "AWS",
                "User data (may contain secrets)",
                id="aws-user-data",
            ),
            # GCP
            pytest.param(
                "http://metadata.google.internal/computeMetadata/v1/",
                "GCP",
                "Compute metadata root",
                id="gcp-metadata-root",
            ),
            pytest.param(
                "http://169.254.169.254/computeMetadata/v1/project/project-id",
                "GCP",
                "Project ID via link-local",
                id="gcp-project-id",
            ),
            # Azure
            pytest.param(
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "Azure",
                "Instance metadata",
                id="azure-metadata",
            ),
            pytest.param(
                "http://169.254.169.254/metadata/identity/oauth2/token",
                "Azure",
                "Managed identity token",
                id="azure-identity-token",
            ),
            # DigitalOcean
            pytest.param(
                "http://169.254.169.254/metadata/v1/",
                "DigitalOcean",
                "Droplet metadata",
                id="digitalocean-metadata",
            ),
        ],
    )
    def test_cloud_metadata_ssrf(
        self, vulnerable_client, url: str, provider: str, description: str
    ):
        """Verify SSRF vulnerability triggers on cloud metadata URLs."""
        result = vulnerable_client.call_tool("vulnerable_fetcher_tool", {"url": url})

        assert result.get("vulnerable") is True, (
            f"{provider} metadata SSRF ({description}) should be detected. Got: {result}"
        )

        result_str = str(result).lower()
        assert (
            "ssrf" in result_str or "internal" in result_str or "169.254" in result_str
        ), f"Should have SSRF evidence for {provider}. Got: {result_str[:200]}"


class TestInternalNetworkRanges:
    """Test SSRF detection for internal/private network ranges."""

    @pytest.mark.parametrize(
        "url,network_class",
        [
            # Class A private
            pytest.param("http://10.0.0.1/admin", "10.x.x.x", id="class-a-10-0-0-1"),
            pytest.param("http://10.255.255.255/", "10.x.x.x", id="class-a-10-255"),
            # Class B private
            pytest.param(
                "http://172.16.0.1/config", "172.16-31.x.x", id="class-b-172-16"
            ),
            pytest.param(
                "http://172.31.255.255/", "172.16-31.x.x", id="class-b-172-31"
            ),
            # Class C private
            pytest.param("http://192.168.0.1/", "192.168.x.x", id="class-c-192-168-0"),
            pytest.param(
                "http://192.168.255.255/", "192.168.x.x", id="class-c-192-168-255"
            ),
            # Link-local
            pytest.param("http://169.254.1.1/", "169.254.x.x", id="link-local-169-254"),
        ],
    )
    def test_private_network_ssrf(
        self, vulnerable_client, url: str, network_class: str
    ):
        """Verify SSRF detection on private network ranges."""
        result = vulnerable_client.call_tool("vulnerable_fetcher_tool", {"url": url})

        assert result.get("vulnerable") is True, (
            f"Private network SSRF ({network_class}) should be detected. Got: {result}"
        )


class TestLocalhostVariants:
    """Test SSRF detection for various localhost representations."""

    @pytest.mark.parametrize(
        "url,variant",
        [
            # Standard localhost
            pytest.param("http://localhost/admin", "localhost", id="localhost-word"),
            pytest.param(
                "http://localhost:8080/", "localhost:port", id="localhost-port"
            ),
            # IPv4 localhost
            pytest.param("http://127.0.0.1/", "127.0.0.1", id="ipv4-127-0-0-1"),
            pytest.param("http://127.0.0.1:6379/", "127.0.0.1:port", id="ipv4-redis"),
            pytest.param("http://127.1/", "127.1 (short)", id="ipv4-127-1"),
            # 0.0.0.0
            pytest.param("http://0.0.0.0/", "0.0.0.0", id="ipv4-0-0-0-0"),
            pytest.param(
                "http://0.0.0.0:9200/", "0.0.0.0:port", id="ipv4-elasticsearch"
            ),
            # Common service ports
            pytest.param("http://localhost:3306/", "MySQL", id="mysql-port"),
            pytest.param("http://localhost:5432/", "PostgreSQL", id="postgres-port"),
            pytest.param("http://localhost:27017/", "MongoDB", id="mongodb-port"),
            pytest.param("http://localhost:11211/", "Memcached", id="memcached-port"),
        ],
    )
    def test_localhost_ssrf(self, vulnerable_client, url: str, variant: str):
        """Verify SSRF detection on localhost variants."""
        result = vulnerable_client.call_tool("vulnerable_fetcher_tool", {"url": url})

        assert result.get("vulnerable") is True, (
            f"Localhost SSRF ({variant}) should be detected. Got: {result}"
        )


class TestIPv6SSRF:
    """Test SSRF detection for IPv6 addresses."""

    @pytest.mark.parametrize(
        "url,description",
        [
            pytest.param("http://[::1]/", "IPv6 localhost", id="ipv6-localhost"),
            pytest.param(
                "http://[::1]:8080/",
                "IPv6 localhost with port",
                id="ipv6-localhost-port",
            ),
            pytest.param("http://[::]/", "IPv6 any address", id="ipv6-any"),
            pytest.param(
                "http://[::ffff:127.0.0.1]/",
                "IPv6-mapped IPv4 localhost",
                id="ipv6-mapped-ipv4",
            ),
            pytest.param(
                "http://[::ffff:169.254.169.254]/",
                "IPv6-mapped metadata",
                id="ipv6-mapped-metadata",
            ),
        ],
    )
    def test_ipv6_ssrf(self, vulnerable_client, url: str, description: str):
        """Verify SSRF detection on IPv6 addresses."""
        result = vulnerable_client.call_tool("vulnerable_fetcher_tool", {"url": url})

        # IPv6 SSRF should be detected
        assert result.get("vulnerable") is True, (
            f"IPv6 SSRF ({description}) should be detected. Got: {result}"
        )


class TestURLBypassTechniques:
    """Test SSRF detection with various bypass techniques."""

    @pytest.mark.parametrize(
        "url,technique",
        [
            # IP encoding tricks
            pytest.param(
                "http://2130706433/",
                "Decimal IP (127.0.0.1 = 2130706433)",
                id="decimal-ip",
            ),
            pytest.param(
                "http://0x7f000001/", "Hex IP (127.0.0.1 = 0x7f000001)", id="hex-ip"
            ),
            pytest.param("http://017700000001/", "Octal IP (127.0.0.1)", id="octal-ip"),
            # URL encoding
            pytest.param(
                "http://localhost%00.evil.com/", "Null byte injection", id="null-byte"
            ),
            pytest.param(
                "http://127.0.0.1%2f@evil.com/", "URL encoded slash", id="encoded-slash"
            ),
            # Domain tricks
            pytest.param(
                "http://localtest.me/", "DNS rebinding domain", id="dns-rebinding"
            ),
            pytest.param(
                "http://spoofed.burpcollaborator.net/",
                "Collaborator domain",
                id="collaborator",
            ),
            # Internal hostnames
            pytest.param(
                "http://internal.corp.example.com/",
                "Internal hostname",
                id="internal-hostname",
            ),
            pytest.param("http://intranet/", "Intranet hostname", id="intranet"),
        ],
    )
    def test_ssrf_bypass_techniques(self, vulnerable_client, url: str, technique: str):
        """Verify SSRF detection with bypass techniques."""
        result = vulnerable_client.call_tool("vulnerable_fetcher_tool", {"url": url})

        # These should be detected as SSRF or at least flagged as external fetch
        assert result.get("vulnerable") is True, (
            f"SSRF bypass ({technique}) should be detected. Got: {result}"
        )


class TestFileProtocolSSRF:
    """Test SSRF/LFI via file:// protocol."""

    @pytest.mark.parametrize(
        "url,target",
        [
            pytest.param("file:///etc/passwd", "/etc/passwd", id="etc-passwd"),
            pytest.param("file:///etc/shadow", "/etc/shadow", id="etc-shadow"),
            pytest.param("file:///etc/hosts", "/etc/hosts", id="etc-hosts"),
            pytest.param(
                "file:///proc/self/environ", "process environment", id="proc-environ"
            ),
            pytest.param(
                "file:///proc/self/cmdline", "process cmdline", id="proc-cmdline"
            ),
            pytest.param(
                "file:///app/config.py", "application config", id="app-config"
            ),
        ],
    )
    def test_file_protocol_ssrf(self, vulnerable_client, url: str, target: str):
        """Verify file:// protocol SSRF detection."""
        result = vulnerable_client.call_tool("vulnerable_fetcher_tool", {"url": url})

        assert result.get("vulnerable") is True, (
            f"File protocol SSRF ({target}) should be detected. Got: {result}"
        )


class TestHardenedBlocksAllSSRF:
    """Verify hardened server blocks all SSRF patterns."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/",
            "http://localhost:8080/",
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "file:///etc/passwd",
        ],
    )
    def test_hardened_blocks_ssrf(self, hardened_client, url: str):
        """Hardened server should never perform SSRF."""
        result = hardened_client.call_tool("vulnerable_fetcher_tool", {"url": url})

        assert result.get("vulnerable", False) is False, (
            f"Hardened should block SSRF to {url}. Got: {result}"
        )

        result_str = str(result).lower()
        assert "stored" in result_str or "pending" in result_str, (
            f"Should store URL, not fetch. Got: {result_str[:200]}"
        )


class TestSSRFCoverageSummary:
    """Summary of SSRF coverage."""

    def test_ssrf_coverage_complete(self, vulnerable_client):
        """
        Verify comprehensive SSRF detection coverage.
        """
        categories = {
            "cloud_metadata": "http://169.254.169.254/latest/meta-data/",
            "private_network": "http://192.168.1.1/",
            "localhost": "http://localhost:8080/",
            "ipv6": "http://[::1]/",
            "file_protocol": "file:///etc/passwd",
        }

        all_detected = True
        for category, url in categories.items():
            result = vulnerable_client.call_tool(
                "vulnerable_fetcher_tool", {"url": url}
            )

            if result.get("vulnerable") is not True:
                all_detected = False
                print(f"✗ {category} not detected: {url}")
            else:
                print(f"✓ {category} detected: {url}")

        assert all_detected, "All SSRF categories should be detected"

        print("\n=== SSRF Coverage Summary ===")
        print("✓ Cloud metadata endpoints (AWS, GCP, Azure)")
        print("✓ Private network ranges (10.x, 172.16-31.x, 192.168.x)")
        print("✓ Localhost variants (localhost, 127.0.0.1, ::1)")
        print("✓ IPv6 addresses")
        print("✓ File protocol (file://)")
