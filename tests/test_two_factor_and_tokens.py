"""Tests for the 2FA and token lifetimes.

Two behaviours are pinned here because both were wrong in 0.1.x and neither
was covered by a test: email 2FA emailed a 30-second rotating TOTP while the
template promised five minutes, and the confirmation token's stored deadline
was a hard-coded day no matter what lifetime the token was minted with.
"""

from datetime import timedelta

import pytest

from surrealengine_auth import security
from surrealengine_auth.models import User
from surrealengine_auth.service import SurrealEngineAuth

PASSWORD = "correct horse battery staple"


@pytest.fixture
def email_user(sync_connection):
    user, ok = SurrealEngineAuth.register_user(
        "emma", "emma@example.com", PASSWORD
    )
    assert ok
    user.setup_two_factor("email")
    return user


@pytest.fixture
def totp_user(sync_connection):
    user, ok = SurrealEngineAuth.register_user(
        "tina", "tina@example.com", PASSWORD
    )
    assert ok
    user.setup_two_factor("authenticator")
    return user


class TestEmailTwoFactorCodes:
    def test_default_window_is_five_minutes(self):
        assert User.email_code_expires_in == 300

    def test_code_is_stored_only_as_a_digest(self, email_user):
        code = email_user.issue_email_two_factor_code()
        email_user.save_sync()
        assert len(code) == 6 and code.isdigit()
        assert email_user.tf_email_code_hash
        assert code not in email_user.tf_email_code_hash
        assert "tf_email_code_hash" not in email_user.to_dict()

    def test_code_verifies(self, email_user):
        code = email_user.issue_email_two_factor_code()
        email_user.save_sync()
        assert email_user.verify_two_factor(code) is True

    def test_code_is_single_use(self, email_user):
        code = email_user.issue_email_two_factor_code()
        email_user.save_sync()
        assert email_user.verify_two_factor(code) is True
        assert email_user.verify_two_factor(code) is False

    def test_wrong_code_is_rejected(self, email_user):
        code = email_user.issue_email_two_factor_code()
        email_user.save_sync()
        wrong = "000000" if code != "000000" else "111111"
        assert email_user.verify_two_factor(wrong) is False

    def test_expired_code_is_rejected(self, email_user):
        code = email_user.issue_email_two_factor_code()
        # Backdate the window rather than sleeping through it.
        email_user.tf_email_code_expires_at = (
            email_user.tf_email_code_expires_at - timedelta(seconds=301)
        )
        email_user.save_sync()
        assert email_user.verify_two_factor(code) is False

    def test_lifetime_is_configurable(self, email_user):
        code = email_user.issue_email_two_factor_code(expires_in=600)
        email_user.save_sync()
        window = email_user.tf_email_code_expires_at - email_user.updated_at
        assert 590 <= window.total_seconds() <= 610
        assert email_user.verify_two_factor(code) is True

    def test_issuing_a_new_code_invalidates_the_old_one(self, email_user):
        first = email_user.issue_email_two_factor_code()
        second = email_user.issue_email_two_factor_code()
        email_user.save_sync()
        assert first != second
        assert email_user.verify_two_factor(first) is False
        assert email_user.verify_two_factor(second) is True

    def test_guesses_are_bounded(self, email_user):
        """A six-digit code needs a bound; a five-minute window alone is not
        one."""
        code = email_user.issue_email_two_factor_code()
        email_user.save_sync()
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(User.email_code_max_attempts):
            assert email_user.verify_two_factor(wrong) is False
        # The code has been burned by the failed attempts, not merely delayed.
        assert email_user.verify_two_factor(code) is False

    def test_no_totp_secret_is_created_for_email(self, email_user):
        assert email_user.totp_secret is None
        assert email_user.generate_two_factor_code() is None

    def test_recovery_code_does_not_work_as_an_emailed_code(self, email_user):
        """Otherwise a one-time emailed code becomes a repeatable one."""
        recovery = email_user.setup_two_factor("email")["recovery_codes"][0]
        email_user.issue_email_two_factor_code()
        email_user.save_sync()
        # Consumed as a recovery code, but it must not satisfy the code field.
        assert email_user.verify_two_factor(recovery) is True
        email_user.issue_email_two_factor_code()
        email_user.save_sync()
        assert email_user.verify_two_factor(recovery) is False

    def test_email_codes_are_domain_separated(self):
        assert security.hash_email_code("123456") != security.hash_recovery_code(
            "123456"
        )

    def test_issuing_requires_the_email_method(self, totp_user):
        with pytest.raises(ValueError):
            totp_user.issue_email_two_factor_code()

    def test_disabling_two_factor_clears_outstanding_codes(self, email_user):
        code = email_user.issue_email_two_factor_code()
        email_user.disable_two_factor()
        assert email_user.tf_email_code_hash is None
        assert email_user.verify_two_factor(code) is False


class TestAuthenticatorUnchanged:
    def test_totp_still_verifies(self, totp_user):
        code = totp_user.generate_two_factor_code()
        assert totp_user.verify_two_factor(code) is True

    def test_totp_replay_is_blocked(self, totp_user):
        code = totp_user.generate_two_factor_code()
        assert totp_user.verify_two_factor(code) is True
        assert totp_user.verify_two_factor(code) is False

    def test_setup_returns_a_secret_and_qrcode(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "quinn", "quinn@example.com", PASSWORD
        )
        setup = user.setup_two_factor("authenticator")
        assert setup["secret"] == user.totp_secret
        assert setup["qrcode"].startswith("data:image/svg+xml")
        assert len(setup["recovery_codes"]) == len(user.tf_recovery_codes)


class TestConfirmationTokenExpiry:
    def test_default_is_a_day(self):
        assert User.confirmation_token_expires_in == 86400

    def test_stored_expiry_matches_the_issued_lifetime(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "wendy", "wendy@example.com", PASSWORD
        )
        user.generate_confirmation_token(expires_in=600)
        remaining = user.confirmation_token_expires_at - user.updated_at
        assert 590 <= remaining.total_seconds() <= 610

    def test_a_short_lived_token_expires(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "xena", "xena@example.com", PASSWORD
        )
        token = user.generate_confirmation_token(expires_in=600)
        user.confirmation_token_expires_at = (
            user.confirmation_token_expires_at - timedelta(seconds=601)
        )
        user.save_sync()
        assert User.verify_confirmation_token(token) is None

    def test_lifetime_is_configurable_per_call(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "yara", "yara@example.com", PASSWORD
        )
        user.generate_confirmation_token(expires_in=120)
        remaining = user.confirmation_token_expires_at - user.updated_at
        assert 110 <= remaining.total_seconds() <= 130

    def test_valid_token_still_confirms(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "zoe", "zoe@example.com", PASSWORD
        )
        token = user.generate_confirmation_token()
        confirmed = User.verify_confirmation_token(token)
        assert confirmed is not None
        assert confirmed.confirmed_at is not None

    def test_non_positive_expiry_is_rejected(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "aria", "aria@example.com", PASSWORD
        )
        with pytest.raises(ValueError):
            user.generate_confirmation_token(expires_in=0)


class TestLoginTokenExpiry:
    def test_default_is_an_hour(self):
        assert User.login_token_expires_in == 3600

    def test_stored_expiry_matches_the_issued_lifetime(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "nina", "nina@example.com", PASSWORD
        )
        user.generate_login_token(120)
        remaining = user.login_token_expires_at - user.updated_at
        assert 110 <= remaining.total_seconds() <= 130

    def test_expired_login_token_is_refused(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "omar", "omar@example.com", PASSWORD
        )
        token = user.generate_login_token(120)
        user.login_token_expires_at = user.login_token_expires_at - timedelta(
            seconds=121
        )
        user.save_sync()
        assert User.verify_login_token(token) is None


class TestTwoFactorTemplate:
    """The email must state the lifetime the code was actually issued with."""

    def _expiry_line(self, expires_in):
        from surrealengine_auth import SurrealEngineAuth as Svc
        from surrealengine_auth.email_service import _as_minutes

        service = Svc.get_email_service()
        rendered = service._render(
            "two_factor",
            {
                "user": type("U", (), {"username": "emma"})(),
                "code": "482913",
                "expires_in": expires_in,
                "expires_minutes": _as_minutes(expires_in),
            },
        )["text"]
        return next(
            line.strip() for line in rendered.splitlines() if "expire" in line.lower()
        )

    @pytest.mark.parametrize(
        "expires_in,expected",
        [
            (300, "This code will expire in 5 minutes."),
            (120, "This code will expire in 2 minutes."),
            (45, "This code will expire in 1 minute."),
        ],
    )
    def test_states_the_real_window(self, expires_in, expected):
        assert self._expiry_line(expires_in) == expected

    def test_does_not_promise_a_window_when_unknown(self):
        assert self._expiry_line(None) == "This code expires shortly."
