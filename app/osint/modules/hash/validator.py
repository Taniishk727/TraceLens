"""
============================================================
TraceLens Hash Module - Input Validator
============================================================

Performs strict validation and normalization on candidate hash inputs.

Validation Rules:
- Rejects empty strings and whitespace-only input.
- Trims surrounding (leading/trailing) whitespace.
- Rejects internal whitespace (spaces, tabs, newlines).
- Rejects obviously invalid characters based on encoding rules.
- Normalizes hex strings to lowercase for uniform comparison, while
  preserving original input for display.
- Detects structured hash markers (e.g. `$`, `*`).

Author:
    TraceLens
"""

import re
from typing import Tuple
from app.osint.modules.hash.models import HashValidationResult


class HashValidator:
    """
    Validator for hash inputs entering the TraceLens investigation engine.
    """

    HEX_CHARS = set("0123456789abcdefABCDEF")
    HEX_LENGTHS = {16, 32, 40, 56, 64, 80, 96, 128}
    STRUCTURED_PREFIXES = ("$", "*", "{")

    @classmethod
    def validate(cls, raw_input: str) -> HashValidationResult:
        """
        Validates and normalizes a candidate hash string.

        Args:
            raw_input: Raw string received from user or dispatcher.

        Returns:
            HashValidationResult containing validation status and normalized string.
        """
        if raw_input is None:
            return HashValidationResult(
                valid=False,
                input="",
                error="Hash input cannot be None.",
                details=["Null input provided."],
            )

        # Preserve original for display
        original_display = raw_input

        # 1. Reject empty or whitespace-only
        if not raw_input or not raw_input.strip():
            return HashValidationResult(
                valid=False,
                input=original_display,
                error="Hash input cannot be empty or whitespace-only.",
                details=["Empty or whitespace input provided."],
            )

        # 2. Trim surrounding whitespace
        trimmed = raw_input.strip()

        # 3. Reject internal whitespace (spaces, newlines, tabs)
        if any(c.isspace() for c in trimmed):
            return HashValidationResult(
                valid=False,
                input=original_display,
                normalized=trimmed,
                error="Hash input contains internal whitespace.",
                details=["Hashes must not contain spaces or newlines."],
                length=len(trimmed),
            )

        # Check if structured
        is_structured = trimmed.startswith(cls.STRUCTURED_PREFIXES)

        # 4. Normalize case & check valid characters
        normalized, encoding, invalid_reason = cls._normalize_and_inspect(trimmed, is_structured)

        if invalid_reason:
            return HashValidationResult(
                valid=False,
                input=original_display,
                normalized=trimmed,
                error=invalid_reason,
                details=[invalid_reason],
                length=len(trimmed),
                encoding=encoding,
                is_structured=is_structured,
            )

        return HashValidationResult(
            valid=True,
            input=original_display,
            normalized=normalized,
            length=len(normalized),
            encoding=encoding,
            is_structured=is_structured,
            details=[f"Input length: {len(normalized)}", f"Encoding format: {encoding}"],
        )

    @classmethod
    def _normalize_and_inspect(cls, text: str, is_structured: bool) -> Tuple[str, str, str | None]:
        """
        Normalizes case where appropriate and identifies character set encoding.
        """
        if is_structured:
            # Structured hashes like $2b$..., $argon2... must preserve exact case
            if not all(32 <= ord(c) <= 126 for c in text):
                return text, "Structured", "Structured hash contains non-printable ASCII characters."
            return text, "Structured", None

        # Pure hexadecimal check
        if all(c in cls.HEX_CHARS for c in text):
            return text.lower(), "Hexadecimal", None

        # If length matches standard hex length but contains non-hex characters
        if len(text) in cls.HEX_LENGTHS:
            invalid_chars = [c for c in text if c not in cls.HEX_CHARS]
            if invalid_chars:
                return text, "Hexadecimal", f"Invalid non-hex character '{invalid_chars[0]}' in hexadecimal hash string."

        # Base64 or custom encoded string pattern
        if re.fullmatch(r"^[A-Za-z0-9+/=_.-]+$", text):
            return text, "Base64 / Encoded", None

        return text, "Unknown", f"Input contains invalid hash characters: '{text}'"
