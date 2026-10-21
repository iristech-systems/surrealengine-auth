"""Tests for the pure cryptographic helpers in :mod:`security`."""

import time

import pytest

from surrealengine_auth import security


class TestPasswordHashing:
    def test_argon2_hash_verifies(self):
        encoded = security.hash_password("hunter2")
        assert encoded.startswith("$argon2id$")
        assert security.verify_password("hunter2", encoded)
        assert not security.verify_password("hunter3", encoded)

    def test_salt_is_unique_per_hash(self):
        first = security.hash_password("hunter2")
        second = security.hash_password("hunter2")
        assert first != second

    def test_legacy_pbkdf2_hash_still_verifies(self):
        salt = "a" * 32
        encoded = security.hash_password(
            "hunter2", algorithm="pbkdf2", salt=salt, iterations=100_000
        )
        assert security.verify_password("hunter2", encoded, salt)
        assert not security.verify_password("wrong", encoded, salt)

    def test_legacy_hash_without_salt_fails_closed(self):
        encoded = security.hash_password(
            "hunter2", algorithm="pbkdf2", salt="a" * 32, iterations=100_000
        )
        assert not security.verify_password("hunter2", encoded, None)

    def test_legacy_hash_is_flagged_for_rehash(self):
        encoded = security.hash_password(
            "hunter2", algorithm="pbkdf2", salt="a" * 32, iterations=100_000
        )
        assert security.password_needs_rehash(encoded)
        assert not security.password_needs_rehash(security.hash_password("hunter2"))

    def test_missing_inputs_fail_closed(self):
        assert not security.verify_password("", "$argon2id$fake")
        assert not security.verify_password("hunter2", None)
        assert not security.verify_password("hunter2", "")

    def test_dummy_verify_runs(self):
        # Exists to equalise timing; must not raise.
        security.dummy_verify()
        security.dummy_verify()

    def test_dummy_verify_costs_comparable_time_to_real_verify(self):
        encoded = security.hash_password("hunter2")
        security.dummy_verify()

        start = time.perf_counter()
        security.verify_password("hunter2", encoded)
        real = time.perf_counter() - start

        start = time.perf_counter()
        security.dummy_verify()
        dummy = time.perf_counter() - start

        # Generous bound: the point is that both are in the same order of
        # magnitude, not a precise benchmark.
        assert dummy > real / 10, f"dummy {dummy:.4f}s vs real {real:.4f}s"

    def test_unknown_algorithm_rejected(self):
        with pytest.raises(ValueError):
            security.hash_password("x", algorithm="md5")


class TestApiKeys:
    def test_key_is_a_uuid4(self):
        import uuid

        key = security.generate_api_key()
        parsed = uuid.UUID(key)
        assert parsed.version == 4
        assert str(parsed) == key

    def test_keys_are_unique(self):
        assert len({security.generate_api_key() for _ in range(200)}) == 200

    def test_digest_is_deterministic(self):
        key = security.generate_api_key()
        assert security.hash_api_key(key) == security.hash_api_key(key)

    def test_digest_does_not_contain_the_key(self):
        key = security.generate_api_key()
        assert key not in security.hash_api_key(key)

    def test_app_secret_changes_the_digest(self):
        key = security.generate_api_key()
        assert security.hash_api_key(key) != security.hash_api_key(
            key, app_secret="pepper"
        )

    def test_constant_time_equals(self):
        assert security.constant_time_equals("abc", "abc")
        assert not security.constant_time_equals("abc", "abd")
        assert not security.constant_time_equals("abc", "abcd")
        assert not security.constant_time_equals(None, "abc")
        assert not security.constant_time_equals("abc", None)

    def test_constant_time_contains(self):
        codes = ["aaaa-bbbb", "cccc-dddd"]
        assert security.constant_time_contains(codes, "cccc-dddd")
        assert not security.constant_time_contains(codes, "eeee")
        assert not security.constant_time_contains([], "aaaa-bbbb")
        assert not security.constant_time_contains(None, "aaaa-bbbb")


class TestTokens:
    def test_round_trip(self):
        token = security.generate_token({"uid": "u1"}, secret="s")
        payload = security.verify_token(token, secret="s")
        assert payload["uid"] == "u1"
        assert "exp" in payload and "iat" in payload and "jti" in payload

    def test_tampered_payload_rejected(self):
        token = security.generate_token({"uid": "u1"}, secret="s")
        body, signature = token.split(".", 1)
        forged = security._b64e(b'{"uid":"admin"}') + "." + signature
        with pytest.raises(security.TokenError):
            security.verify_token(forged, secret="s")

    def test_wrong_secret_rejected(self):
        token = security.generate_token({"uid": "u1"}, secret="s")
        with pytest.raises(security.TokenError):
            security.verify_token(token, secret="other")

    @pytest.mark.parametrize("token", ["", "nodot", "a.b.c", ".", "....", None])
    def test_malformed_rejected(self, token):
        with pytest.raises(security.TokenError):
            security.verify_token(token, secret="s")

    def test_expired_rejected(self):
        token = security.generate_token({"a": 1}, secret="s", expires_in=-5)
        with pytest.raises(security.TokenError, match="expired"):
            security.verify_token(token, secret="s")

    def test_expiry_skippable_for_inspection(self):
        token = security.generate_token({"a": 1}, secret="s", expires_in=-5)
        assert security.verify_token(token, secret="s", verify_exp=False)["a"] == 1

    def test_expired_timestamps_are_expired(self):
        assert security.token_is_expired({})
        assert security.token_is_expired({"exp": "soon"})
        assert security.token_is_expired({"exp": 0})
        assert not security.token_is_expired({"exp": 4 * 10**9})

    def test_each_token_has_a_distinct_jti(self):
        first = security.verify_token(security.generate_token({}, secret="s", expires_in=1), secret="s")
        second = security.verify_token(security.generate_token({}, secret="s", expires_in=1), secret="s")
        assert first["jti"] != second["jti"]

    def test_missing_secret_raises(self):
        previous = security.TokenConfig.secret
        security.TokenConfig.secret = None
        try:
            with pytest.raises(RuntimeError):
                security.generate_token({"a": 1})
        finally:
            security.TokenConfig.secret = previous

    def test_configured_secret_is_used_by_default(self):
        previous = security.TokenConfig.secret
        security.TokenConfig.configure("configured")
        try:
            token = security.generate_token({"a": 1})
            assert security.verify_token(token)["a"] == 1
        finally:
            security.TokenConfig.secret = previous


class TestRecoveryCodes:
    def test_format(self):
        code = security.generate_recovery_code()
        parts = code.split("-")
        assert len(parts) == 4 and all(len(p) == 4 for p in parts)
        assert all(c in "0123456789abcdef" for c in code.replace("-", ""))

    def test_normalisation_accepts_retyped_codes(self):
        code = security.generate_recovery_code()
        assert security.normalise_recovery_code(code) == security.normalise_recovery_code(
            code.lower().replace("-", "")
        )

    def test_hash_is_stable_and_one_way(self):
        code = security.generate_recovery_code()
        digest = security.hash_recovery_code(code)
        assert digest == security.hash_recovery_code(code)
        assert code not in digest

    def test_pepper_changes_the_hash(self):
        code = security.generate_recovery_code()
        assert security.hash_recovery_code(
            code
        ) != security.hash_recovery_code(code, pepper="p")

    def test_non_string_input_is_empty(self):
        assert security.normalise_recovery_code(None) == ""
        assert security.normalise_recovery_code(123) == ""


class TestLoggingHygiene:
    @pytest.mark.parametrize(
        "key", ["password", "password_hash", "salt", "totp_secret", "key_secret", "token"]
    )
    def test_sensitive_keys_redacted(self, key):
        result = security.redact({key: "s3cret"})
        assert result[key] == "[REDACTED]"

    def test_redaction_recurses(self):
        result = security.redact({"outer": {"totp_secret": "s"}, "list": [{"key_hash": "k"}]})
        assert result["outer"]["totp_secret"] == "[REDACTED]"
        assert result["list"][0]["key_hash"] == "[REDACTED]"

    def test_non_sensitive_values_survive(self):
        result = security.redact({"username": "alice", "count": 3})
        assert result == {"username": "alice", "count": 3}

    def test_long_strings_truncated(self):
        result = security.redact({"note": "x" * 1000})
        assert len(result["note"]) == 512

    def test_extra_keys_honoured(self):
        result = security.redact({"custom": "v"}, extra_keys=["custom"])
        assert result["custom"] == "[REDACTED]"

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("203.0.113.7", "203.0.113.7"),
            ("  10.0.0.1  ", "10.0.0.1"),
            ("2001:db8::1", "2001:db8::1"),
            ("203.0.113.7, 10.0.0.1", "203.0.113.7"),
            ("not-an-ip", None),
            ("999.999.999.999", None),
            ("", None),
            (None, None),
            (123, None),
        ],
    )
    def test_safe_ip_address(self, raw, expected):
        assert security.safe_ip_address(raw) == expected

    def test_fingerprint_is_stable_and_short(self):
        value = "some-identifier"
        fingerprint = security.fingerprint(value)
        assert fingerprint == security.fingerprint(value)
        assert len(fingerprint) == 8
        assert value not in fingerprint

    def test_fingerprint_handles_empty(self):
        assert security.fingerprint(None) is None
        assert security.fingerprint("") is None
