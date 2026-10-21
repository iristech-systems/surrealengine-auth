"""Tests for the async authentication path.

The async surface is not a thin wrapper: 0.1.x shared state between the sync
and async implementations in ways that only failed once a real async
connection was in play, so these tests run against an async-only connection
with no sync connection registered at all.
"""

import pytest

from surrealengine_auth.models import SecurityEvent
from surrealengine_auth.service import (
    AuthenticationError,
    LockoutError,
    SurrealEngineAuth,
)

pytestmark = pytest.mark.asyncio

PASSWORD = "correct horse battery staple"


class TestRegistration:
    async def test_registers_a_user(self, async_connection):
        user, created = await SurrealEngineAuth.register_user_async(
            "bob", "bob@example.com", PASSWORD
        )
        assert created is True
        assert user.username == "bob"
        assert user.password_hash.startswith("$argon2id$")
        assert user.verify_password(PASSWORD)

    async def test_duplicate_username_returns_none(self, async_connection):
        await SurrealEngineAuth.register_user_async("dave", "dave@example.com", PASSWORD)
        second, created = await SurrealEngineAuth.register_user_async(
            "dave", "other@example.com", PASSWORD
        )
        assert created is False
        assert second is None

    async def test_duplicate_email_races_are_caught(self, async_connection):
        """A unique index, not the pre-check, is what makes this safe."""
        await SurrealEngineAuth.register_user_async("first", "race@example.com", PASSWORD)
        second, created = await SurrealEngineAuth.register_user_async(
            "second", "race@example.com", PASSWORD
        )
        assert created is False
        assert second is None


class TestAuthentication:
    async def test_authenticates_by_username(self, async_user):
        user = await SurrealEngineAuth.authenticate_async("alice", PASSWORD)
        assert user.username == "alice"

    async def test_authenticates_by_email(self, async_user):
        user = await SurrealEngineAuth.authenticate_async("alice@example.com", PASSWORD)
        assert user.username == "alice"

    async def test_rejects_a_wrong_password(self, async_user):
        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.authenticate_async("alice", "wrong")

    async def test_rejects_an_unknown_user(self, async_connection):
        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.authenticate_async("nobody", PASSWORD)

    async def test_rejects_a_deactivated_user(self, async_user):
        async_user.is_active = False
        await async_user.save()
        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.authenticate_async("alice", PASSWORD)

    async def test_records_last_login(self, async_user):
        assert async_user.last_login is None
        await SurrealEngineAuth.authenticate_async("alice", PASSWORD)
        fresh = await SurrealEngineAuth.get_user_by_id_async(str(async_user.id))
        assert fresh.last_login is not None


class TestLockout:
    async def test_locks_out_after_repeated_failures(self, async_user):
        SurrealEngineAuth.max_attempts = 3
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                await SurrealEngineAuth.authenticate_async("alice", "wrong")

        with pytest.raises(LockoutError):
            await SurrealEngineAuth.authenticate_async("alice", PASSWORD)

    async def test_success_clears_the_counter(self, async_user):
        SurrealEngineAuth.max_attempts = 3
        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.authenticate_async("alice", "wrong")
        assert await SurrealEngineAuth.authenticate_async("alice", PASSWORD)

        for _ in range(2):
            with pytest.raises(AuthenticationError):
                await SurrealEngineAuth.authenticate_async("alice", "wrong")
        # The counter reset, so this must not be a lockout.
        assert await SurrealEngineAuth.authenticate_async("alice", PASSWORD)

    async def test_lockout_covers_unknown_users(self, async_user):
        SurrealEngineAuth.max_attempts = 2
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                await SurrealEngineAuth.authenticate_async("ghost", "anything")
        with pytest.raises(LockoutError):
            await SurrealEngineAuth.authenticate_async("ghost", "anything")

    async def test_lockout_can_be_disabled(self, async_user):
        SurrealEngineAuth.max_attempts = 0
        for _ in range(10):
            with pytest.raises(AuthenticationError):
                await SurrealEngineAuth.authenticate_async("alice", "wrong")
        assert await SurrealEngineAuth.authenticate_async("alice", PASSWORD)

    async def test_lockout_is_recorded(self, async_user):
        SurrealEngineAuth.max_attempts = 1
        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.authenticate_async("alice", "wrong")
        with pytest.raises(LockoutError):
            await SurrealEngineAuth.authenticate_async("alice", PASSWORD)

        events = await SecurityEvent.objects.filter(
            event_type="account_locked"
        ).all()
        assert len(events) == 1


class TestPasswordUpgrade:
    async def test_legacy_pbkdf2_is_upgraded_on_login(self, async_connection):
        """0.1.x stored PBKDF2; a successful login is the one moment the
        plaintext exists, so that is where the upgrade belongs."""
        from surrealengine_auth import security

        user, _ = await SurrealEngineAuth.register_user_async(
            "legacy", "legacy@example.com", PASSWORD
        )
        # The 0.1.x format is a bare hex digest in ``password_hash`` plus a
        # hex salt in ``salt``; verification needs both.
        user.password_hash = security.hash_password(
            PASSWORD, algorithm="pbkdf2", salt="0011223344556677"
        )
        user.salt = "0011223344556677"
        await user.save()
        assert not user.password_hash.startswith("$")

        authenticated = await SurrealEngineAuth.authenticate_async("legacy", PASSWORD)
        assert authenticated.password_hash.startswith("$argon2id$")
        # The rewritten hash is what got persisted, not just what is in memory.
        fresh = await SurrealEngineAuth.get_user_by_id_async(str(user.id))
        assert fresh.password_hash.startswith("$argon2id$")
        assert fresh.verify_password(PASSWORD)

    async def test_a_legacy_user_still_authenticates_with_the_old_password(
        self, async_connection
    ):
        from surrealengine_auth import security

        user, _ = await SurrealEngineAuth.register_user_async(
            "legacy2", "legacy2@example.com", PASSWORD
        )
        user.password_hash = security.hash_password(
            PASSWORD, algorithm="pbkdf2", salt="8899aabbccddeeff"
        )
        user.salt = "8899aabbccddeeff"
        await user.save()

        authenticated = await SurrealEngineAuth.authenticate_async("legacy2", PASSWORD)
        assert authenticated.username == "legacy2"


class TestAsyncEmailTwoFactor:
    """The async email-2FA path, on a connection with no sync counterpart.

    Every audit write in this path used to go through the synchronous
    ``SecurityEvent.log_event``. On an async-only application the default
    connection is async, so those writes either grabbed a sync connection that
    was never configured or blocked the event loop.
    """

    @staticmethod
    def _stub_email_service(accepts: bool = True):
        class Stub:
            def __init__(self):
                self.sent = []

            async def send_two_factor_code(self, user, code, expires_in=None):
                self.sent.append((user.email, code, expires_in))
                return accepts

            def send_two_factor_code_sync(self, user, code, expires_in=None):
                self.sent.append((user.email, code, expires_in))
                return accepts

        return Stub()

    @pytest.fixture
    def email_stub(self):
        """Install a stub email service and put the real one back after."""
        original = SurrealEngineAuth._email_service
        stub = self._stub_email_service()
        SurrealEngineAuth._email_service = stub
        yield stub
        SurrealEngineAuth._email_service = original

    async def _enable_email_2fa(self, user):
        setup = await user.setup_two_factor_async("email")
        return setup

    async def test_sending_writes_the_code_and_the_audit_event(
        self, async_user, email_stub
    ):
        from surrealengine_auth.models import SecurityEvent

        await self._enable_email_2fa(async_user)

        assert await SurrealEngineAuth.send_two_factor_code_async(async_user) is True

        events = await SecurityEvent.objects.filter(
            event_type="two_factor_code_sent", user_id=async_user.id
        ).all()
        assert len(events) == 1

    async def test_the_code_is_persisted_before_the_send(self, async_user, email_stub):
        await self._enable_email_2fa(async_user)

        assert await SurrealEngineAuth.send_two_factor_code_async(async_user) is True
        assert email_stub.sent, "the code was never handed to the mailer"
        assert email_stub.sent[0][2] == async_user.email_code_expires_in

        stored = await SurrealEngineAuth.get_user_by_username_async("alice")
        assert stored.tf_email_code_hash
        assert stored.tf_email_code_expires_at

    async def test_a_refused_send_is_audited(self, async_user, email_stub):
        from surrealengine_auth.models import SecurityEvent

        SurrealEngineAuth._email_service = self._stub_email_service(accepts=False)
        await self._enable_email_2fa(async_user)

        assert await SurrealEngineAuth.send_two_factor_code_async(async_user) is False

        events = await SecurityEvent.objects.filter(
            event_type="two_factor_code_send_failed", user_id=async_user.id
        ).all()
        assert len(events) == 1

    async def test_email_2fa_not_configured_is_audited(self, async_user, email_stub):
        from surrealengine_auth.models import SecurityEvent

        # TOTP enrolled, not email.
        await async_user.setup_two_factor_async("authenticator")

        assert await SurrealEngineAuth.send_two_factor_code_async(async_user) is False

        events = await SecurityEvent.objects.filter(
            event_type="two_factor_code_send_failed", user_id=async_user.id
        ).all()
        assert events[0].details["reason"] == "Email 2FA not configured"
