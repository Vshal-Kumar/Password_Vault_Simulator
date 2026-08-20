"""Validation and Password Strength Evaluation utilities."""

import math
import re
from typing import Dict, Any, List, Tuple

from ..config import MIN_MASTER_PASSWORD_LENGTH

COMMON_WEAK_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "admin", "welcome",
    "password123", "master", "vault", "secret", "letmein", "changeme", "iloveyou"
}


class PasswordStrengthEvaluator:
    """Evaluates password strength, calculates entropy, and provides security recommendations."""

    @classmethod
    def calculate_entropy(cls, password: str) -> float:
        """Calculate approximate entropy in bits based on character pool diversity."""
        if not password:
            return 0.0

        pool_size = 0
        if re.search(r"[a-z]", password):
            pool_size += 26
        if re.search(r"[A-Z]", password):
            pool_size += 26
        if re.search(r"[0-9]", password):
            pool_size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            pool_size += 32

        if pool_size == 0:
            return 0.0

        return len(password) * math.log2(pool_size)

    @classmethod
    def evaluate(cls, password: str) -> Dict[str, Any]:
        """
        Evaluate password strength and return comprehensive metrics.

        Returns:
            Dictionary with score (0-100), label, entropy, checks, recommendations.
        """
        if not password:
            return {
                "score": 0,
                "label": "Empty",
                "entropy_bits": 0.0,
                "is_strong": False,
                "recommendations": ["Password cannot be empty."],
            }

        recommendations: List[str] = []
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"[0-9]", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
        length = len(password)
        entropy = cls.calculate_entropy(password)

        score = 0

        # Length score (up to 40 points)
        if length >= 16:
            score += 40
        elif length >= 12:
            score += 30
        elif length >= 8:
            score += 20
        else:
            score += length * 2
            recommendations.append(f"Increase length to at least {MIN_MASTER_PASSWORD_LENGTH} characters.")

        # Diversity score (up to 40 points)
        diversity_count = sum([has_lower, has_upper, has_digit, has_special])
        score += diversity_count * 10

        if not has_lower:
            recommendations.append("Add lowercase letters (a-z).")
        if not has_upper:
            recommendations.append("Add uppercase letters (A-Z).")
        if not has_digit:
            recommendations.append("Add numbers (0-9).")
        if not has_special:
            recommendations.append("Add special characters (e.g. !@#$%^&*).")

        # Entropy bonus (up to 20 points)
        if entropy >= 60:
            score += 20
        elif entropy >= 45:
            score += 15
        elif entropy >= 30:
            score += 10

        # Penalty for common passwords
        if password.lower() in COMMON_WEAK_PASSWORDS:
            score = min(score, 15)
            recommendations.append("This is a commonly used password that is easy to crack.")

        # Determine qualitative rating
        score = max(0, min(100, score))
        if score >= 80:
            label = "Very Strong"
        elif score >= 60:
            label = "Strong"
        elif score >= 40:
            label = "Moderate"
        elif score >= 20:
            label = "Weak"
        else:
            label = "Very Weak"

        return {
            "score": score,
            "label": label,
            "entropy_bits": round(entropy, 2),
            "is_strong": score >= 60,
            "recommendations": recommendations,
        }


class InputValidator:
    """Validates and sanitizes CLI input."""

    @staticmethod
    def validate_service_name(service: str) -> Tuple[bool, str]:
        """Validate service name."""
        cleaned = service.strip()
        if not cleaned:
            return False, "Service name cannot be empty."
        if len(cleaned) > 64:
            return False, "Service name cannot exceed 64 characters."
        if not re.match(r"^[a-zA-Z0-9_\-\.\@\+ ]+$", cleaned):
            return False, "Service name contains invalid characters."
        return True, cleaned

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate username or email."""
        cleaned = username.strip()
        if not cleaned:
            return False, "Username cannot be empty."
        if len(cleaned) > 128:
            return False, "Username cannot exceed 128 characters."
        return True, cleaned

    @staticmethod
    def validate_master_password(password: str) -> Tuple[bool, str]:
        """Validate master password criteria."""
        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            return False, f"Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters long."
        return True, ""
