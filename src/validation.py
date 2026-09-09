"""
Input validation and query escaping utilities for SIEM integrations.
Prevents injection attacks by validating IOC formats and escaping query syntax.
"""

import re
from typing import Tuple

# IOC validation patterns
IOC_PATTERNS = {
    "ip": re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ),
    "domain": re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ),
    "hash": re.compile(
        r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    ),  # MD5, SHA1, SHA256
    "username": re.compile(r"^[a-zA-Z0-9._@\-]{1,256}$"),
}


def validate_ioc(indicator: str, ioc_type: str) -> Tuple[bool, str]:
    """
    Validates an indicator against its declared type.
    Implements strict validation to prevent injection attacks.

    Args:
        indicator: The IOC value to validate
        ioc_type: The type of IOC (ip, domain, hash, username)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not indicator or not isinstance(indicator, str):
        return False, "Indicator must be a non-empty string"

    if len(indicator) > 512:
        return False, "Indicator exceeds maximum length of 512 characters"

    # Reject indicators with control characters or null bytes
    if any(ord(c) < 32 or ord(c) == 127 for c in indicator):
        return False, "Indicator contains invalid control characters"

    # Reject indicators with suspicious patterns that could indicate injection attempts
    suspicious_patterns = [
        "';",
        '";',
        "||",
        "&&",
        "|",
        "/*",
        "*/",
        "--",
        "//",
        "\\x",
        "\\u",
        "%00",
        "\x00",
    ]
    for pattern in suspicious_patterns:
        if pattern in indicator:
            return False, f"Indicator contains suspicious pattern: {pattern}"

    ioc_type_lower = ioc_type.lower()
    if ioc_type_lower not in IOC_PATTERNS:
        return (
            False,
            f"Unsupported IOC type: {ioc_type}. Supported types: {', '.join(IOC_PATTERNS.keys())}",
        )

    pattern = IOC_PATTERNS[ioc_type_lower]
    if not pattern.match(indicator):
        return False, f"Indicator does not match expected format for type '{ioc_type}'"

    return True, ""


def escape_kql_string(value: str) -> str:
    """
    Escapes a string for safe use in Azure Sentinel KQL queries.
    KQL uses backslash escaping for special characters within string literals.
    This function ensures the value cannot break out of string context or inject operators.

    Args:
        value: The string to escape

    Returns:
        Escaped string safe for KQL
    """
    # Escape backslash first, then other special characters
    value = value.replace("\\", "\\\\")
    value = value.replace("'", "\\'")
    value = value.replace('"', '\\"')
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    value = value.replace("\t", "\\t")
    # Escape pipe character to prevent command chaining
    value = value.replace("|", "\\|")
    # Escape other KQL special characters
    value = value.replace("*", "\\*")
    value = value.replace("?", "\\?")
    return value


def escape_spl_string(value: str) -> str:
    """
    Escapes a string for safe use in Splunk SPL queries.
    SPL uses backslash escaping for quotes within string literals.
    This function ensures the value cannot break out of string context or inject operators.

    Args:
        value: The string to escape

    Returns:
        Escaped string safe for SPL
    """
    # Escape backslash first, then quotes
    value = value.replace("\\", "\\\\")
    value = value.replace('"', '\\"')
    # Escape pipe character to prevent command chaining
    value = value.replace("|", "\\|")
    # Escape other SPL special characters
    value = value.replace("*", "\\*")
    value = value.replace("?", "\\?")
    value = value.replace("[", "\\[")
    value = value.replace("]", "\\]")
    return value


def escape_aql_string(value: str) -> str:
    """
    Escapes a string for safe use in QRadar AQL queries.
    AQL uses quote-doubling for single quotes within string literals.
    This function ensures the value cannot break out of string context or inject operators.

    Args:
        value: The string to escape

    Returns:
        Escaped string safe for AQL
    """
    # Escape single quotes using quote-doubling
    value = value.replace("'", "''")
    # Escape percent signs to prevent LIKE wildcard injection
    value = value.replace("%", "%%")
    # Escape underscore to prevent LIKE wildcard injection
    value = value.replace("_", "\\_")
    return value


def escape_spotter_value(value: str) -> str:
    """
    Escapes a value for safe use in Securonix Spotter queries.
    Spotter query syntax requires values to be quoted and escaped.
    This function ensures the value cannot break out of string context or inject operators.

    Args:
        value: The value to escape

    Returns:
        Escaped and quoted value safe for Spotter
    """
    # Escape backslash and quotes
    value = value.replace("\\", "\\\\")
    value = value.replace('"', '\\"')
    # Escape other potentially dangerous characters
    value = value.replace("'", "\\'")
    value = value.replace("\n", " ")
    value = value.replace("\r", " ")
    # Return quoted value
    return f'"{value}"'


def escape_wazuh_filter(value: str) -> str:
    """
    Escapes a value for safe use in Wazuh API query filters.
    Wazuh uses URL-encoded query parameters with specific operators.
    We need to prevent injection of operators and ensure the value is treated as a literal.

    Args:
        value: The value to escape

    Returns:
        Escaped value safe for Wazuh filters
    """
    # Remove or escape characters that have special meaning in Wazuh query syntax
    # Wazuh operators: =, !=, <, >, ~, (, ), ;, ,
    # Also prevent logical operators and wildcards
    dangerous_chars = [
        "=",
        "!",
        "<",
        ">",
        "~",
        "(",
        ")",
        ";",
        ",",
        "&",
        "|",
        "*",
        "?",
        "[",
        "]",
        "{",
        "}",
        "$",
        "^",
    ]
    result = value
    for char in dangerous_chars:
        result = result.replace(char, "")
    # Remove any whitespace that could be used for injection
    result = result.replace(" ", "")
    return result
