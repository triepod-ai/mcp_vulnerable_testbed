"""
Response Schema Validation Tests

Validates that tool responses conform to expected schemas.
Ensures consistent response structure for reliable parsing.
"""

import pytest
from jsonschema import validate, ValidationError
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from response_factory import (
    create_response,
    create_vulnerable_response,
    create_safe_response,
)


# JSON Schemas for response validation
VULNERABLE_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["result", "vulnerable"],
    "properties": {
        "result": {"type": "string"},
        "vulnerable": {"type": "boolean", "const": True},
        "evidence": {"type": "string"},
    },
    "additionalProperties": True,
}

SAFE_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["result", "safe"],
    "properties": {
        "result": {"type": "string"},
        "safe": {"type": "boolean", "const": True},
        "vulnerable": {"type": "boolean", "const": False},
        "note": {"type": "string"},
    },
    "additionalProperties": True,
}

NEUTRAL_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["result"],
    "properties": {
        "result": {"type": "string"},
        "vulnerable": {"type": "boolean"},
    },
    "additionalProperties": True,
}


class TestResponseFactory:
    """Tests for the response factory functions."""

    def test_create_vulnerable_response(self):
        """Vulnerable response has required fields."""
        response = create_vulnerable_response(
            "Executed: 2+2 = 4", "eval() executed user input"
        )
        validate(response, VULNERABLE_RESPONSE_SCHEMA)
        assert response["vulnerable"] is True
        assert response["evidence"] == "eval() executed user input"

    def test_create_safe_response(self):
        """Safe response has required fields."""
        response = create_safe_response(
            "Data stored successfully", "Input treated as data only"
        )
        validate(response, SAFE_RESPONSE_SCHEMA)
        assert response["safe"] is True
        assert response["vulnerable"] is False

    def test_create_response_with_extra_fields(self):
        """Response factory accepts extra fields."""
        response = create_response(
            "Fetched URL",
            vulnerable=True,
            evidence="SSRF detected",
            status_code=200,
            content_length=1234,
        )
        assert response["status_code"] == 200
        assert response["content_length"] == 1234

    def test_neutral_response(self):
        """Neutral response without vulnerable or safe flags."""
        response = create_response("Operation completed")
        validate(response, NEUTRAL_RESPONSE_SCHEMA)
        assert response["vulnerable"] is False

    def test_vulnerable_response_requires_evidence(self):
        """Vulnerable response should include evidence."""
        response = create_vulnerable_response(
            "Command executed", "subprocess.run() called"
        )
        assert "evidence" in response
        assert len(response["evidence"]) > 0


class TestSchemaValidation:
    """Tests for schema validation of actual tool responses."""

    def test_calculator_response_schema(self):
        """Calculator vulnerable response matches schema."""
        # Simulated response from vulnerable_calculator
        response = {
            "result": "Calculated: 15 + 37 = 52",
            "vulnerable": True,
            "evidence": "eval() executed mathematical expression",
            "expression": "15 + 37",
            "computed_value": 52,
        }
        validate(response, VULNERABLE_RESPONSE_SCHEMA)

    def test_safe_storage_response_schema(self):
        """Safe storage response matches schema."""
        response = {
            "result": "Stored in collection 'test': some data",
            "id": 1,
            "collection": "test",
            "total_items": 1,
            "safe": True,
            "vulnerable": False,
            "note": "Data stored safely without execution",
        }
        validate(response, SAFE_RESPONSE_SCHEMA)

    def test_fetcher_response_schema(self):
        """Fetcher vulnerable response matches schema."""
        response = {
            "result": "Fetched: http://localhost:8080",
            "vulnerable": True,
            "evidence": "SSRF: Accessed internal network address",
            "status_code": 200,
            "content_length": 1024,
            "content": "<!DOCTYPE html>...",
        }
        validate(response, VULNERABLE_RESPONSE_SCHEMA)

    def test_rug_pull_response_schema(self):
        """Rug pull response includes invocation count."""
        # Before threshold
        response_safe = {
            "result": "Action completed safely",
            "vulnerable": False,
            "invocation_count": 5,
        }
        validate(response_safe, NEUTRAL_RESPONSE_SCHEMA)

        # After threshold
        response_malicious = {
            "result": "Rug pull activated!",
            "vulnerable": True,
            "evidence": "Behavior changed after 10+ invocations",
            "invocation_count": 11,
        }
        validate(response_malicious, VULNERABLE_RESPONSE_SCHEMA)


class TestInvalidResponses:
    """Tests that invalid responses fail validation."""

    def test_missing_result_fails(self):
        """Response without 'result' field should fail."""
        invalid_response = {"vulnerable": True}
        with pytest.raises(ValidationError):
            validate(invalid_response, VULNERABLE_RESPONSE_SCHEMA)

    def test_wrong_vulnerable_type_fails(self):
        """Vulnerable field must be boolean."""
        invalid_response = {
            "result": "test",
            "vulnerable": "yes",  # Should be boolean
        }
        with pytest.raises(ValidationError):
            validate(invalid_response, VULNERABLE_RESPONSE_SCHEMA)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
