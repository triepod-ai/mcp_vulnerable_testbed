"""
Tests for Challenge #23: Multi-Parameter Template Resource Injection

This module tests MCP resources with 4 parameters each, where each parameter
represents an independent injection point:
- database://{schema}/{table}/{column}/{filter} - SQL injection, schema traversal
- api://{version}/{service}/{endpoint}/{param} - Version downgrade, enumeration
- file://{env}/{app}/{path}/{filename} - Environment hopping, path traversal

Usage:
    pytest tests/test_multi_param_injection.py -v
    pytest tests/test_multi_param_injection.py -v -k "database"
    pytest tests/test_multi_param_injection.py -v -k "cross_parameter"

Coverage: Challenge #23 (Multi-Parameter Template Resource Injection)
CWEs: CWE-610, CWE-22, CWE-89, CWE-943
Source: MCP Conformance Suite - resources.ts
"""

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


class TestDatabaseResource:
    """Tests for database://{schema}/{table}/{column}/{filter} resource.

    Tests SQL injection, schema traversal, wildcard columns, and
    multi-parameter attack combinations.
    """

    def test_normal_access_public_users(self, vulnerable_client):
        """Normal access to public.users returns user data."""
        result = vulnerable_client.read_resource("database://public/users/id/1")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("schema") == "public"
        assert extracted.get("table") == "users"
        assert extracted.get("data_exposed") is True
        assert "id" in extracted.get("columns_available", [])

    def test_wildcard_column_access(self, vulnerable_client):
        """Wildcard (*) in column parameter exposes all columns."""
        result = vulnerable_client.read_resource("database://public/users/*/1")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("data_exposed") is True
        # Check injection detected
        injection_vectors = extracted.get("injection_vectors_detected", [])
        assert any("Wildcard" in v for v in injection_vectors)

    def test_sql_injection_in_filter(self, vulnerable_client):
        """SQL injection in filter parameter is detected."""
        result = vulnerable_client.read_resource(
            "database://public/users/id/1 OR 1=1"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        injection_vectors = extracted.get("injection_vectors_detected", [])
        assert any("SQL injection" in v for v in injection_vectors)

    def test_path_traversal_in_schema(self, vulnerable_client):
        """Path traversal patterns in schema parameter are detected."""
        # Note: FastMCP normalizes URI paths, so we embed traversal chars
        # within the parameter value rather than using standalone '..'
        result = vulnerable_client.read_resource(
            "database://..internal/secrets/key/1"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        injection_vectors = extracted.get("injection_vectors_detected", [])
        # Should detect the traversal pattern in the schema parameter
        assert any("Path traversal" in v for v in injection_vectors)

    def test_sql_chars_in_table(self, vulnerable_client):
        """SQL special characters in table parameter are detected."""
        result = vulnerable_client.read_resource(
            "database://public/users';DROP TABLE--/id/1"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        injection_vectors = extracted.get("injection_vectors_detected", [])
        assert any("SQL chars" in v for v in injection_vectors)

    def test_internal_secrets_access(self, vulnerable_client):
        """Direct access to internal.secrets should return sensitive data."""
        result = vulnerable_client.read_resource(
            "database://internal/secrets/key/1"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("data_exposed") is True
        # Should leak secrets
        data = extracted.get("data", [])
        if data:
            assert any("api_key" in str(d) for d in data)

    def test_schema_enumeration(self, vulnerable_client):
        """Schema names are leaked in response (information disclosure)."""
        result = vulnerable_client.read_resource("database://public/users/id/1")
        extracted = _extract_result(result)
        available_schemas = extracted.get("available_schemas", [])
        assert "public" in available_schemas
        assert "internal" in available_schemas  # Leaks internal schema

    def test_cwe_codes_present(self, vulnerable_client):
        """Response includes appropriate CWE codes."""
        result = vulnerable_client.read_resource("database://public/users/id/1")
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert "CWE-610" in cwe_ids
        assert "CWE-89" in cwe_ids


class TestApiResource:
    """Tests for api://{version}/{service}/{endpoint}/{param} resource.

    Tests version downgrade, service enumeration, path traversal,
    and parameter injection attacks.
    """

    def test_normal_v2_access(self, vulnerable_client):
        """Normal v2 API access returns secure response."""
        result = vulnerable_client.read_resource("api://v2/users/list/page=1")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("version") == "v2"
        assert "warning" not in extracted  # No warning for v2

    def test_version_downgrade_v1(self, vulnerable_client):
        """Version downgrade to v1 is detected and exploitable."""
        result = vulnerable_client.read_resource("api://v1/auth/login/x")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("version") == "v1"
        assert "warning" in extracted
        assert "deprecated" in extracted.get("warning", "").lower()
        # Check injection detected
        injection_vectors = extracted.get("injection_vectors_detected", [])
        assert any("downgrade" in v.lower() for v in injection_vectors)

    def test_v1_admin_bypass(self, vulnerable_client):
        """V1 admin endpoint has authentication bypass."""
        result = vulnerable_client.read_resource("api://v1/auth/admin/token")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("admin_access_granted") is True
        assert "admin_token" in extracted

    def test_path_traversal_across_params(self, vulnerable_client):
        """Path traversal patterns spanning service/endpoint parameters."""
        # Embed traversal pattern within parameter value
        result = vulnerable_client.read_resource(
            "api://v2/users..admin/..internal/x"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("path_traversal_detected") is True
        injection_vectors = extracted.get("injection_vectors_detected", [])
        assert any("Path traversal" in v for v in injection_vectors)

    def test_parameter_injection(self, vulnerable_client):
        """Parameter injection in param field is detected."""
        result = vulnerable_client.read_resource(
            "api://v2/auth/login/token=admin"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        injection_vectors = extracted.get("injection_vectors_detected", [])
        assert any("Parameter injection" in v for v in injection_vectors)

    def test_service_enumeration(self, vulnerable_client):
        """Available services are leaked in response."""
        result = vulnerable_client.read_resource("api://v2/users/list/x")
        extracted = _extract_result(result)
        available_services = extracted.get("available_services", [])
        assert len(available_services) > 0
        assert "auth" in available_services or "users" in available_services

    def test_version_enumeration(self, vulnerable_client):
        """Available versions are leaked in response."""
        result = vulnerable_client.read_resource("api://v2/users/list/x")
        extracted = _extract_result(result)
        available_versions = extracted.get("available_versions", [])
        assert "v1" in available_versions
        assert "v2" in available_versions

    def test_cwe_codes_present(self, vulnerable_client):
        """Response includes appropriate CWE codes."""
        result = vulnerable_client.read_resource("api://v2/users/list/x")
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert "CWE-610" in cwe_ids
        assert "CWE-22" in cwe_ids


class TestFileResource:
    """Tests for file://{env}/{app}/{path}/{filename} resource.

    Tests environment hopping, app isolation bypass, path traversal,
    and null byte injection attacks.
    """

    def test_normal_file_access(self, vulnerable_client):
        """Normal file access in sandbox environment."""
        result = vulnerable_client.read_resource(
            "file://sandbox/app/config/settings.json"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("env") == "sandbox"
        # Sandbox should not trigger environment access warning
        assert "environment_access" not in extracted

    def test_production_environment_access(self, vulnerable_client):
        """Production environment access is unrestricted."""
        result = vulnerable_client.read_resource(
            "file://production/app/config/db.yml"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert "environment_access" in extracted
        assert "production" in extracted.get("environment_access", "")

    def test_path_traversal_to_etc_passwd(self, vulnerable_client):
        """Path traversal to sensitive files returns simulated content."""
        # FastMCP normalizes paths, so we embed traversal patterns in values
        result = vulnerable_client.read_resource(
            "file://prod/app/..etc../passwd"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("traversal_successful") is True
        assert extracted.get("sensitive_file_requested") is True
        assert "root:x:0:0" in extracted.get("simulated_content", "")

    def test_env_file_access(self, vulnerable_client):
        """Access to .env files exposes credentials."""
        result = vulnerable_client.read_resource(
            "file://production/app/config/.env"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("env_file_requested") is True
        assert extracted.get("data_exposed") is True
        assert "DB_PASSWORD" in extracted.get("simulated_content", "")

    def test_environment_hopping(self, vulnerable_client):
        """Environment hopping via traversal patterns in env parameter."""
        # Embed traversal pattern in env parameter
        result = vulnerable_client.read_resource(
            "file://production..staging/secrets/config/.env"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        injection_vectors = extracted.get("injection_vectors_detected", [])
        # Either hopping or traversal pattern should be detected
        assert any("hopping" in v.lower() or "traversal" in v.lower() for v in injection_vectors)

    def test_app_isolation_bypass(self, vulnerable_client):
        """App isolation bypass via traversal pattern in app parameter."""
        # Embed traversal pattern in app parameter
        result = vulnerable_client.read_resource(
            "file://prod/app1..app2/config/secrets.key"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        injection_vectors = extracted.get("injection_vectors_detected", [])
        # Traversal pattern should be detected in the combined path
        assert any("traversal" in v.lower() for v in injection_vectors)

    def test_null_byte_injection(self, vulnerable_client):
        """Null byte injection in filename is detected."""
        result = vulnerable_client.read_resource(
            "file://prod/app/config/db.yml%00.txt"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("null_byte_injection") is True
        assert extracted.get("effective_filename") == "db.yml"

    def test_secret_file_access(self, vulnerable_client):
        """Access to secret/key files exposes private keys."""
        result = vulnerable_client.read_resource(
            "file://production/app/keys/private.key"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("secret_file_requested") is True
        assert "RSA PRIVATE KEY" in extracted.get("simulated_content", "")

    def test_traversal_count(self, vulnerable_client):
        """Traversal patterns are detected and counted in response."""
        # Multiple .. patterns embedded in parameter values
        result = vulnerable_client.read_resource(
            "file://prod../app../etc../passwd"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        # Either traversal count or detection should be present
        assert extracted.get("traversal_successful") is True or extracted.get("traversal_count", 0) >= 1

    def test_cwe_codes_present(self, vulnerable_client):
        """Response includes appropriate CWE codes."""
        result = vulnerable_client.read_resource(
            "file://production/app/config/file.txt"
        )
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert "CWE-22" in cwe_ids
        assert "CWE-610" in cwe_ids


class TestCrossParameterAttacks:
    """Tests for compound attacks that combine multiple parameter injections.

    These tests verify that vulnerabilities can be chained across
    parameter boundaries for more severe exploits.
    """

    def test_database_compound_attack(self, vulnerable_client):
        """Compound attack: traversal pattern + wildcard + SQL injection."""
        # Combine multiple injection patterns without breaking template
        result = vulnerable_client.read_resource(
            "database://..internal/secrets/*/1 OR 1=1"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        injection_count = extracted.get("injection_count", 0)
        # Should detect multiple injection vectors
        assert injection_count >= 2

    def test_api_compound_attack(self, vulnerable_client):
        """Compound attack: version downgrade + admin + param injection."""
        result = vulnerable_client.read_resource(
            "api://v1/auth/admin/token=superuser"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        # Should grant admin access via v1 bypass
        assert extracted.get("admin_access_granted") is True
        # Should detect multiple issues
        injection_count = extracted.get("injection_count", 0)
        assert injection_count >= 2

    def test_file_compound_attack(self, vulnerable_client):
        """Compound attack: env hopping + traversal + sensitive file."""
        # Multiple traversal patterns embedded in parameter values
        result = vulnerable_client.read_resource(
            "file://prod..staging/..secrets/..etc/passwd"
        )
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True
        assert extracted.get("traversal_successful") is True
        # Multiple traversal indicators
        assert len(extracted.get("injection_vectors_detected", [])) >= 1

    def test_all_parameters_injectable(self, vulnerable_client):
        """Each parameter in database:// is independently injectable."""
        # Test each parameter individually
        test_cases = [
            ("database://../x/y/z", "Path traversal in schema"),
            ("database://x/';--/y/z", "SQL chars in table"),
            ("database://x/y/*/z", "Wildcard in column"),
            ("database://x/y/z/1 OR 1=1", "SQL injection in filter"),
        ]
        for uri, expected_pattern in test_cases:
            result = vulnerable_client.read_resource(uri)
            extracted = _extract_result(result)
            injection_vectors = extracted.get("injection_vectors_detected", [])
            assert len(injection_vectors) > 0, f"No injection detected for {uri}"


class TestVulnerabilityIndicators:
    """Tests verifying vulnerability indicators and metadata are properly set."""

    def test_database_vulnerability_flag(self, vulnerable_client):
        """database:// resource always marks vulnerable=True."""
        result = vulnerable_client.read_resource("database://public/users/id/1")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True

    def test_api_vulnerability_flag(self, vulnerable_client):
        """api:// resource always marks vulnerable=True."""
        result = vulnerable_client.read_resource("api://v2/users/list/x")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True

    def test_file_vulnerability_flag(self, vulnerable_client):
        """file:// resource always marks vulnerable=True."""
        result = vulnerable_client.read_resource("file://sandbox/app/config/x")
        extracted = _extract_result(result)
        assert extracted.get("vulnerable") is True

    def test_uri_reflected_in_response(self, vulnerable_client):
        """URI is reflected in response for traceability."""
        uri = "database://public/users/email/test"
        result = vulnerable_client.read_resource(uri)
        extracted = _extract_result(result)
        assert extracted.get("uri") == uri

    @pytest.mark.parametrize(
        "uri,expected_cwe",
        [
            ("database://public/users/id/1", "CWE-89"),
            ("api://v2/users/list/x", "CWE-22"),
            ("file://prod/app/config/x", "CWE-22"),
        ],
    )
    def test_cwe_codes_by_resource(self, vulnerable_client, uri, expected_cwe):
        """Each resource includes appropriate CWE codes."""
        result = vulnerable_client.read_resource(uri)
        extracted = _extract_result(result)
        cwe_ids = extracted.get("cwe_ids", [])
        assert expected_cwe in cwe_ids
