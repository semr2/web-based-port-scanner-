import pytest

from backend.services.auth_service import (
    MAX_LENGTH, PasswordPolicyError, hash_password,
    needs_rehash, validate_password, verify_password, verify_unknown_user,
)

GOOD = "correct horse battery staple"


def test_hash_is_argon2id_and_not_plaintext():
    h = hash_password(GOOD)
    assert h.startswith("$argon2id$")
    assert GOOD not in h


def test_same_password_hashes_differently():
    assert hash_password(GOOD) != hash_password(GOOD)


def test_correct_password_verifies():
    assert verify_password(GOOD, hash_password(GOOD)) is True


def test_wrong_password_fails():
    assert verify_password("wrong password here!", hash_password(GOOD)) is False


def test_garbage_hash_fails_safely():
    assert verify_password(GOOD, "not-a-hash") is False


def test_too_short_rejected():
    with pytest.raises(PasswordPolicyError):
        validate_password("short")


def test_too_long_rejected_and_not_verified():
    with pytest.raises(PasswordPolicyError):
        validate_password("a1" * MAX_LENGTH)
    assert verify_password("a1" * MAX_LENGTH, hash_password(GOOD)) is False


def test_username_in_password_rejected():
    with pytest.raises(PasswordPolicyError):
        validate_password("my-alice-password-123", username="alice")


def test_repetitive_rejected():
    with pytest.raises(PasswordPolicyError):
        validate_password("aaaaaaaaaaaaaaaa")


def test_unknown_user_check_returns_false():
    assert verify_unknown_user(GOOD) is False


def test_fresh_hash_does_not_need_rehash():
    assert needs_rehash(hash_password(GOOD)) is False
