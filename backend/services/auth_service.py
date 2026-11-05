from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
MAX_LENGTH = 128  # caps hashing cost per request

_hasher = PasswordHasher()  # Argon2id with the library's current defaults
_DUMMY_HASH = _hasher.hash("timing-equalizer-not-a-real-password")


class PasswordPolicyError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def validate_password(password: str, *, username: str | None = None) -> None:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        problems.append(f"must be at most {MAX_LENGTH} characters")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if len(set(password)) < 5:
        problems.append("is too repetitive")
    if problems:
        raise PasswordPolicyError(problems)


def hash_password(password: str, *, username: str | None = None) -> str:
    validate_password(password, username=username)
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    if len(password) > MAX_LENGTH:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def verify_unknown_user(password: str) -> bool:
    """Burn the same time as a real check so login timing doesn't reveal valid usernames."""
    verify_password(password, _DUMMY_HASH)
    return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)
