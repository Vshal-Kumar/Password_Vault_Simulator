"""Cryptographically secure password generator using Python's secrets module."""

import secrets
import string
from typing import Set

AMBIGUOUS_CHARS = {"l", "1", "I", "o", "0", "O", "|", "`", "'", '"'}


class PasswordGenerator:
    """Generates high-entropy, cryptographically secure passwords."""

    @classmethod
    def generate(
        cls,
        length: int = 16,
        include_upper: bool = True,
        include_lower: bool = True,
        include_digits: bool = True,
        include_symbols: bool = True,
        exclude_ambiguous: bool = True,
    ) -> str:
        """
        Generate a secure random password satisfying specified criteria.

        Args:
            length: Password length (minimum 8, default 16).
            include_upper: Include uppercase letters (A-Z).
            include_lower: Include lowercase letters (a-z).
            include_digits: Include numbers (0-9).
            include_symbols: Include special characters.
            exclude_ambiguous: Exclude visually confusing characters (0, O, 1, l, etc.).

        Returns:
            Secure random password string.
        """
        length = max(8, length)

        lower_chars = list(string.ascii_lowercase)
        upper_chars = list(string.ascii_uppercase)
        digit_chars = list(string.digits)
        symbol_chars = list("!@#$%^&*()-_=+[]{}|;:,.<>?")

        if exclude_ambiguous:
            lower_chars = [c for c in lower_chars if c not in AMBIGUOUS_CHARS]
            upper_chars = [c for c in upper_chars if c not in AMBIGUOUS_CHARS]
            digit_chars = [c for c in digit_chars if c not in AMBIGUOUS_CHARS]
            symbol_chars = [c for c in symbol_chars if c not in AMBIGUOUS_CHARS]

        character_pools = []
        guaranteed_chars = []

        if include_lower and lower_chars:
            character_pools.append(lower_chars)
            guaranteed_chars.append(secrets.choice(lower_chars))
        if include_upper and upper_chars:
            character_pools.append(upper_chars)
            guaranteed_chars.append(secrets.choice(upper_chars))
        if include_digits and digit_chars:
            character_pools.append(digit_chars)
            guaranteed_chars.append(secrets.choice(digit_chars))
        if include_symbols and symbol_chars:
            character_pools.append(symbol_chars)
            guaranteed_chars.append(secrets.choice(symbol_chars))

        if not character_pools:
            # Fallback to standard alphanumeric
            character_pools = [string.ascii_letters + string.digits]
            guaranteed_chars = [secrets.choice(character_pools[0])]

        combined_pool = [c for pool in character_pools for c in pool]

        # Fill the remaining length
        remaining_length = length - len(guaranteed_chars)
        password_chars = guaranteed_chars + [secrets.choice(combined_pool) for _ in range(remaining_length)]

        # Cryptographically secure shuffle
        rng = secrets.SystemRandom()
        rng.shuffle(password_chars)

        return "".join(password_chars)
