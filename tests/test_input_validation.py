"""
tests/test_input_validation.py

Unit tests for input validation and sanitization (Phase 4 hardening).
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.input_validation import (
    RequestValidationRules,
    PolicyRequest,
    IntakeRequest,
    BulkPolicyRequest,
    ValidationError,
    sanitize_input,
    validate_json_depth,
    validate_array_size,
)
from pydantic import ValidationError as PydanticValidationError


class TestServiceNameValidation:
    """Test service name validation rules."""

    def test_valid_service_names(self):
        """Valid service names are accepted."""
        valid = [
            "web-server",
            "db_replica_01",
            "api.example.com",
            "smtp-mx-1",
            "a",  # Single char
            "a" * 255,  # Max length
        ]
        for name in valid:
            validated = RequestValidationRules.validate_service_name(name)
            assert validated == name

    def test_invalid_service_names(self):
        """Invalid service names are rejected."""
        invalid = [
            "",  # Empty
            "a" * 256,  # Too long
            "server@1",  # @ not allowed
            "server:1",  # : not allowed
            "server/1",  # / not allowed
            "server*",  # * not allowed
        ]
        for name in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_service_name(name)

    def test_service_name_null_bytes_rejected(self):
        """Null bytes in service name rejected."""
        with pytest.raises(ValidationError):
            RequestValidationRules.validate_service_name("server\x00name")


class TestPortValidation:
    """Test port number validation."""

    def test_valid_ports(self):
        """Valid ports accepted."""
        valid = [1, 22, 80, 443, 8080, 65535]
        for port in valid:
            validated = RequestValidationRules.validate_port(port)
            assert validated == port

    def test_invalid_ports(self):
        """Invalid ports rejected."""
        invalid = [0, -1, 65536, 70000]
        for port in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_port(port)

    def test_port_non_integer_rejected(self):
        """Non-integer ports rejected."""
        with pytest.raises(ValidationError):
            RequestValidationRules.validate_port("8080")


class TestProtocolValidation:
    """Test protocol validation."""

    def test_valid_protocols(self):
        """Valid protocols accepted."""
        valid = ["tcp", "udp", "icmp", "esp", "gre"]
        for proto in valid:
            validated = RequestValidationRules.validate_protocol(proto)
            assert validated == proto.lower()

    def test_protocol_case_insensitive(self):
        """Protocol validation is case-insensitive."""
        assert RequestValidationRules.validate_protocol("TCP") == "tcp"
        assert RequestValidationRules.validate_protocol("UDP") == "udp"

    def test_invalid_protocols(self):
        """Invalid protocols rejected."""
        invalid = ["http", "ftp", "xyz", ""]
        for proto in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_protocol(proto)


class TestDirectionValidation:
    """Test direction validation."""

    def test_valid_directions(self):
        """Valid directions accepted."""
        valid = ["in", "out", "both"]
        for direction in valid:
            validated = RequestValidationRules.validate_direction(direction)
            assert validated == direction.lower()

    def test_invalid_directions(self):
        """Invalid directions rejected."""
        invalid = ["inbound", "outbound", "bidirectional", ""]
        for direction in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_direction(direction)


class TestActionValidation:
    """Test action validation."""

    def test_valid_actions(self):
        """Valid actions accepted."""
        valid = ["allow", "deny", "log", "drop", "reject"]
        for action in valid:
            validated = RequestValidationRules.validate_action(action)
            assert validated == action.lower()

    def test_invalid_actions(self):
        """Invalid actions rejected."""
        invalid = ["accept", "permit", "block", ""]
        for action in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_action(action)


class TestRequestIDValidation:
    """Test request ID validation."""

    def test_valid_request_ids(self):
        """Valid 32-hex request IDs accepted."""
        valid = [
            "a" * 32,
            "0" * 32,
            "f" * 32,
            "abcdef0123456789abcdef0123456789",
        ]
        for rid in valid:
            validated = RequestValidationRules.validate_request_id(rid)
            assert validated == rid

    def test_invalid_request_ids(self):
        """Invalid request IDs rejected."""
        invalid = [
            "a" * 31,  # Too short
            "a" * 33,  # Too long
            "g" * 32,  # Invalid hex char
            "A" * 32,  # Uppercase (should be lowercase)
            "a" * 32 + "-",  # Extra chars
        ]
        for rid in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_request_id(rid)


class TestEmailValidation:
    """Test email validation."""

    def test_valid_emails(self):
        """Valid emails accepted."""
        valid = [
            "user@example.com",
            "john.doe@company.co.uk",
            "test+tag@domain.org",
            "a@b.c",
        ]
        for email in valid:
            validated = RequestValidationRules.validate_email(email)
            assert validated == email

    def test_invalid_emails(self):
        """Invalid emails rejected."""
        invalid = [
            "user",  # No @
            "@example.com",  # No local part
            "user@",  # No domain
            "user name@example.com",  # Space
            "a" * 255 + "@example.com",  # Too long
        ]
        for email in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_email(email)


class TestIPValidation:
    """Test IP address validation."""

    def test_valid_ipv4(self):
        """Valid IPv4 addresses accepted."""
        valid = ["192.168.1.1", "10.0.0.0", "255.255.255.255", "0.0.0.0"]
        for ip in valid:
            validated = RequestValidationRules.validate_ipv4(ip)
            assert validated == ip

    def test_invalid_ipv4(self):
        """Invalid IPv4 addresses rejected."""
        invalid = ["256.1.1.1", "1.1.1", "1.1.1.1.1", "not.an.ip"]
        for ip in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_ipv4(ip)

    def test_valid_cidr(self):
        """Valid CIDR notation accepted."""
        valid = ["192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"]
        for cidr in valid:
            validated = RequestValidationRules.validate_cidr(cidr)
            assert validated == cidr

    def test_invalid_cidr(self):
        """Invalid CIDR notation rejected."""
        invalid = [
            "192.168.0.0",  # No prefix
            "192.168.0.0/33",  # Prefix too large
            "192.168.0.0/-1",  # Negative prefix
        ]
        for cidr in invalid:
            with pytest.raises(ValidationError):
                RequestValidationRules.validate_cidr(cidr)


class TestPolicyRequestModel:
    """Test Pydantic model validation for /evaluate endpoint."""

    def test_valid_policy_request(self):
        """Valid policy requests accepted."""
        req = PolicyRequest(
            svc_name="web-server",
            dst_port=443,
            protocol="tcp",
            direction="in",
            request_id="a" * 32,
        )
        assert req.svc_name == "web-server"
        assert req.dst_port == 443

    def test_missing_required_fields(self):
        """Missing required fields rejected."""
        with pytest.raises(PydanticValidationError):
            PolicyRequest(
                svc_name="web-server",
                dst_port=443,
                protocol="tcp",
                # Missing request_id
            )

    def test_invalid_field_types(self):
        """Invalid field types coerced or rejected."""
        # Pydantic v2 coerces string "443" to int 443 automatically
        req = PolicyRequest(
            svc_name="web-server",
            dst_port="443",  # Pydantic will coerce to int
            protocol="tcp",
            request_id="a" * 32,
        )
        assert req.dst_port == 443  # Coerced to int

    def test_port_range_validation(self):
        """Port range enforced."""
        with pytest.raises(PydanticValidationError):
            PolicyRequest(
                svc_name="web-server",
                dst_port=0,  # Out of range
                protocol="tcp",
                request_id="a" * 32,
            )

    def test_default_direction(self):
        """Default direction is 'in'."""
        req = PolicyRequest(
            svc_name="web-server",
            dst_port=443,
            protocol="tcp",
            request_id="a" * 32,
        )
        assert req.direction == "in"


class TestBulkPolicyRequest:
    """Test bulk request validation."""

    def test_valid_bulk_request(self):
        """Valid bulk requests accepted."""
        reqs = [
            PolicyRequest(
                svc_name="web-server",
                dst_port=443,
                protocol="tcp",
                request_id=f"{i:032x}",
            )
            for i in range(5)
        ]
        bulk = BulkPolicyRequest(requests=reqs)
        assert len(bulk.requests) == 5

    def test_bulk_min_items(self):
        """Bulk requests require at least 1 item."""
        with pytest.raises(PydanticValidationError):
            BulkPolicyRequest(requests=[])

    def test_bulk_max_items(self):
        """Bulk requests limited to 1000 items."""
        reqs = [
            PolicyRequest(
                svc_name="web-server",
                dst_port=443,
                protocol="tcp",
                request_id=f"{i:032x}",
            )
            for i in range(1001)
        ]
        with pytest.raises(PydanticValidationError):
            BulkPolicyRequest(requests=reqs)

    def test_duplicate_request_ids_rejected(self):
        """Duplicate request IDs in bulk rejected."""
        same_id = "a" * 32
        reqs = [
            PolicyRequest(
                svc_name="web-server",
                dst_port=443,
                protocol="tcp",
                request_id=same_id,
            ),
            PolicyRequest(
                svc_name="db-server",
                dst_port=5432,
                protocol="tcp",
                request_id=same_id,  # Duplicate
            ),
        ]
        with pytest.raises(PydanticValidationError):
            BulkPolicyRequest(requests=reqs)


class TestIntakeRequest:
    """Test intake request with source IP/CIDR validation."""

    def test_valid_intake_request(self):
        """Valid intake requests accepted."""
        req = IntakeRequest(
            svc_name="api-server",
            dst_port=8080,
            protocol="tcp",
            request_id="a" * 32,
            src_ip="192.168.1.100",
            src_cidr="192.168.0.0/24",
        )
        assert req.src_ip == "192.168.1.100"

    def test_intake_optional_source_fields(self):
        """Source fields are optional."""
        req = IntakeRequest(
            svc_name="api-server",
            dst_port=8080,
            protocol="tcp",
            request_id="a" * 32,
        )
        assert req.src_ip is None
        assert req.src_cidr is None

    def test_invalid_src_ip(self):
        """Invalid source IP raises validation error."""
        # Custom ValidationError from our validators gets wrapped by Pydantic
        from api.input_validation import ValidationError
        with pytest.raises((PydanticValidationError, ValidationError)):
            IntakeRequest(
                svc_name="api-server",
                dst_port=8080,
                protocol="tcp",
                request_id="a" * 32,
                src_ip="not.an.ip",
            )


class TestSanitization:
    """Test input sanitization."""

    def test_sanitize_removes_null_bytes(self):
        """Null bytes are removed."""
        dirty = "hello\x00world"
        clean = sanitize_input(dirty)
        assert clean == "helloworld"
        assert "\x00" not in clean

    def test_sanitize_removes_control_chars(self):
        """Control characters are removed (except tab/newline)."""
        dirty = "hello\x01world\x02test"
        clean = sanitize_input(dirty)
        assert "\x01" not in clean
        assert "\x02" not in clean

    def test_sanitize_preserves_whitespace(self):
        """Tab and newline are preserved."""
        with_whitespace = "hello\tworld\ntest"
        clean = sanitize_input(with_whitespace)
        assert clean == with_whitespace

    def test_sanitize_non_string(self):
        """Non-string inputs are converted."""
        assert sanitize_input(123) == "123"
        assert sanitize_input(True) == "True"


class TestJSONDepthValidation:
    """Test JSON bomb protection."""

    def test_shallow_json_accepted(self):
        """Shallow JSON structures accepted."""
        shallow = {"a": {"b": {"c": "value"}}}
        validate_json_depth(shallow, max_depth=10)  # Should not raise

    def test_deep_json_rejected(self):
        """Deeply nested JSON rejected."""
        # Create deeply nested structure
        deep = {"a": 1}
        current = deep
        for _ in range(15):
            current["nested"] = {}
            current = current["nested"]

        with pytest.raises(ValidationError, match="exceeds maximum"):
            validate_json_depth(deep, max_depth=10)

    def test_array_depth_validation(self):
        """Array nesting depth validated."""
        nested_array = [[[[[[[[[[[1]]]]]]]]]]]  # 11 levels
        with pytest.raises(ValidationError):
            validate_json_depth(nested_array, max_depth=10)


class TestArraySizeValidation:
    """Test array size limits."""

    def test_small_array_accepted(self):
        """Small arrays accepted."""
        small = list(range(100))
        validate_array_size(small, max_items=1000)  # Should not raise

    def test_large_array_rejected(self):
        """Large arrays rejected."""
        large = list(range(1001))
        with pytest.raises(ValidationError, match="exceeds maximum"):
            validate_array_size(large, max_items=1000)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
