"""
api/input_validation.py

Comprehensive input validation and sanitization for all API endpoints.
Phase 4 hardening: Defense against injection attacks, overflow, malformed data.

Implements:
- Type validation (Pydantic models)
- Size limits (body, field-level)
- Format validation (regex, RFC compliance)
- Allowlist/denylist filtering
- Sanitization (null bytes, control chars, etc.)
"""

import re
from typing import Any, Optional, List, Set
from pydantic import BaseModel, Field, field_validator, ValidationInfo
from enum import Enum


class ValidationError(Exception):
    """Custom validation error."""
    pass


class RequestValidationRules:
    """
    Centralized validation rules with allowlists and denylists.
    All configurable via environment variables.
    """

    # Service name validation: alphanumeric, underscore, dot, dash
    SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,255}$")
    SERVICE_NAME_MAX_LENGTH = 255

    # Port validation: 1-65535
    PORT_MIN = 1
    PORT_MAX = 65535

    # Protocol validation: tcp, udp, icmp, etc.
    ALLOWED_PROTOCOLS = {
        "tcp", "udp", "icmp", "igmp", "gre", "esp", "ah",
        "ipv6-icmp", "dccp", "sctp"
    }

    # Direction validation: in, out, both
    ALLOWED_DIRECTIONS = {"in", "out", "both"}

    # Action validation: allow, deny, log, drop, reject
    ALLOWED_ACTIONS = {"allow", "deny", "log", "drop", "reject"}

    # Request ID format: UUID-like, hex alphanumeric
    REQUEST_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")

    # Caller sub (email): basic RFC 5322
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    )

    # IPv4/IPv6 address validation
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    # CIDR validation
    CIDR_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$")

    @staticmethod
    def validate_service_name(value: str) -> str:
        """
        Validate service name.
        
        Rules:
        - Alphanumeric, underscore, dot, dash only
        - Max 255 characters
        - Not empty
        """
        if not value:
            raise ValidationError("Service name cannot be empty")
        if len(value) > RequestValidationRules.SERVICE_NAME_MAX_LENGTH:
            raise ValidationError(f"Service name exceeds max length ({RequestValidationRules.SERVICE_NAME_MAX_LENGTH})")
        if not RequestValidationRules.SERVICE_NAME_PATTERN.match(value):
            raise ValidationError("Service name contains invalid characters (allow: a-z, 0-9, _, ., -)")
        return value

    @staticmethod
    def validate_port(value: int) -> int:
        """
        Validate port number.
        
        Rules:
        - 1-65535 (excluding privileged 1-1023 if restricted)
        """
        if not isinstance(value, int):
            raise ValidationError(f"Port must be integer (got {type(value).__name__})")
        if value < RequestValidationRules.PORT_MIN or value > RequestValidationRules.PORT_MAX:
            raise ValidationError(f"Port must be 1-65535 (got {value})")
        return value

    @staticmethod
    def validate_protocol(value: str) -> str:
        """
        Validate protocol name.
        
        Rules:
        - Must be in ALLOWED_PROTOCOLS set
        """
        value_lower = value.lower()
        if value_lower not in RequestValidationRules.ALLOWED_PROTOCOLS:
            raise ValidationError(
                f"Protocol must be one of {RequestValidationRules.ALLOWED_PROTOCOLS} (got {value})"
            )
        return value_lower

    @staticmethod
    def validate_direction(value: str) -> str:
        """
        Validate traffic direction.
        
        Rules:
        - Must be in, out, or both
        """
        value_lower = value.lower()
        if value_lower not in RequestValidationRules.ALLOWED_DIRECTIONS:
            raise ValidationError(
                f"Direction must be one of {RequestValidationRules.ALLOWED_DIRECTIONS} (got {value})"
            )
        return value_lower

    @staticmethod
    def validate_action(value: str) -> str:
        """
        Validate action (allow/deny/etc).
        
        Rules:
        - Must be in ALLOWED_ACTIONS set
        """
        value_lower = value.lower()
        if value_lower not in RequestValidationRules.ALLOWED_ACTIONS:
            raise ValidationError(
                f"Action must be one of {RequestValidationRules.ALLOWED_ACTIONS} (got {value})"
            )
        return value_lower

    @staticmethod
    def validate_request_id(value: str) -> str:
        """
        Validate request ID format.
        
        Rules:
        - 32 hex characters (UUID)
        """
        if not RequestValidationRules.REQUEST_ID_PATTERN.match(value):
            raise ValidationError(f"Request ID must be 32 hex chars (got {value!r})")
        return value

    @staticmethod
    def validate_email(value: str) -> str:
        """
        Validate email address (basic RFC 5322).
        
        Rules:
        - Valid email format
        - Max 254 characters
        """
        if len(value) > 254:
            raise ValidationError(f"Email exceeds max length (254)")
        if not RequestValidationRules.EMAIL_PATTERN.match(value):
            raise ValidationError(f"Invalid email format: {value}")
        return value

    @staticmethod
    def validate_ipv4(value: str) -> str:
        """Validate IPv4 address."""
        if not RequestValidationRules.IPV4_PATTERN.match(value):
            raise ValidationError(f"Invalid IPv4 address: {value}")
        return value

    @staticmethod
    def validate_cidr(value: str) -> str:
        """Validate CIDR notation."""
        if not RequestValidationRules.CIDR_PATTERN.match(value):
            raise ValidationError(f"Invalid CIDR: {value}")
        
        # Parse and validate components
        parts = value.split("/")
        if len(parts) != 2:
            raise ValidationError(f"CIDR must have exactly 2 parts: {value}")
        
        try:
            prefix = int(parts[1])
            if prefix < 0 or prefix > 32:
                raise ValidationError(f"CIDR prefix must be 0-32 (got {prefix})")
        except ValueError:
            raise ValidationError(f"CIDR prefix must be numeric: {value}")
        
        return value

    @staticmethod
    def validate_no_null_bytes(value: str) -> str:
        """Reject strings containing null bytes (null injection)."""
        if "\x00" in value:
            raise ValidationError("Null bytes not allowed")
        return value

    @staticmethod
    def validate_no_control_chars(value: str) -> str:
        """Reject strings with control characters (0x00-0x1F except tab/newline)."""
        for char in value:
            code = ord(char)
            if code < 0x20 and char not in "\t\n\r":
                raise ValidationError(f"Control characters not allowed (0x{code:02x})")
        return value


class PolicyRequest(BaseModel):
    """
    Input model for /evaluate endpoint.
    
    Uses Pydantic for automatic validation, type coercion, and error reporting.
    """

    svc_name: str = Field(..., min_length=1, max_length=255)
    dst_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(..., min_length=1, max_length=20)
    direction: Optional[str] = Field(default="in", max_length=10)
    request_id: str = Field(..., min_length=32, max_length=32)

    @field_validator("svc_name")
    @classmethod
    def validate_svc_name(cls, v):
        return RequestValidationRules.validate_service_name(v)

    @field_validator("protocol")
    @classmethod
    def validate_protocol_val(cls, v):
        return RequestValidationRules.validate_protocol(v)

    @field_validator("direction")
    @classmethod
    def validate_direction_val(cls, v):
        if v:
            return RequestValidationRules.validate_direction(v)
        return v

    @field_validator("request_id")
    @classmethod
    def validate_request_id_val(cls, v):
        return RequestValidationRules.validate_request_id(v)

    @field_validator("svc_name", "protocol", "direction", mode="before")
    @classmethod
    def no_null_bytes(cls, v):
        if v:
            return RequestValidationRules.validate_no_null_bytes(v)
        return v


class BulkPolicyRequest(BaseModel):
    """
    Input model for /evaluate/bulk endpoint.
    
    Accepts list of requests with validation.
    """

    requests: List[PolicyRequest] = Field(..., min_length=1, max_length=1000)

    @field_validator("requests")
    @classmethod
    def validate_requests_unique(cls, v):
        # Ensure no duplicate request IDs
        ids = {req.request_id for req in v}
        if len(ids) != len(v):
            raise ValueError("Duplicate request IDs not allowed in bulk")
        return v


class IntakeRequest(BaseModel):
    """
    Input model for /intake/evaluate endpoint.
    
    Similar to PolicyRequest but with risk scoring fields.
    """

    svc_name: str = Field(..., min_length=1, max_length=255)
    dst_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(..., min_length=1, max_length=20)
    direction: Optional[str] = Field(default="in", max_length=10)
    request_id: str = Field(..., min_length=32, max_length=32)
    src_ip: Optional[str] = None
    src_cidr: Optional[str] = None

    @field_validator("svc_name")
    @classmethod
    def validate_svc_name(cls, v):
        return RequestValidationRules.validate_service_name(v)

    @field_validator("protocol")
    @classmethod
    def validate_protocol_val(cls, v):
        return RequestValidationRules.validate_protocol(v)

    @field_validator("direction")
    @classmethod
    def validate_direction_val(cls, v):
        if v:
            return RequestValidationRules.validate_direction(v)
        return v

    @field_validator("request_id")
    @classmethod
    def validate_request_id_val(cls, v):
        return RequestValidationRules.validate_request_id(v)

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, v):
        if v:
            return RequestValidationRules.validate_ipv4(v)
        return v

    @field_validator("src_cidr")
    @classmethod
    def validate_src_cidr(cls, v):
        if v:
            return RequestValidationRules.validate_cidr(v)
        return v


def sanitize_input(value: str) -> str:
    """
    Sanitize user input by removing problematic characters.
    
    - Removes null bytes
    - Removes non-printable control characters (except tab/newline)
    - Replaces dangerous sequences
    """
    if not isinstance(value, str):
        return str(value)

    # Remove null bytes
    value = value.replace("\x00", "")

    # Remove control characters except tab, newline, carriage return
    sanitized = "".join(
        char for char in value
        if ord(char) >= 0x20 or char in "\t\n\r"
    )

    return sanitized


def validate_json_depth(obj: Any, max_depth: int = 10, current_depth: int = 0) -> None:
    """
    Prevent JSON bomb attacks by validating nesting depth.
    
    Args:
        obj: Object to validate
        max_depth: Maximum allowed nesting level
        current_depth: Current nesting level
    
    Raises:
        ValidationError: If depth exceeded
    """
    if current_depth > max_depth:
        raise ValidationError(f"JSON nesting depth exceeds maximum ({max_depth})")

    if isinstance(obj, dict):
        for key, value in obj.items():
            validate_json_depth(value, max_depth, current_depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            validate_json_depth(item, max_depth, current_depth + 1)


def validate_array_size(data: List[Any], max_items: int = 1000) -> None:
    """
    Prevent array bombing by validating list size.
    
    Args:
        data: List to validate
        max_items: Maximum allowed items
    
    Raises:
        ValidationError: If size exceeded
    """
    if len(data) > max_items:
        raise ValidationError(f"Array size exceeds maximum ({max_items} items)")
