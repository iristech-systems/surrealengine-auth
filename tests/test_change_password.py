"""Tests for changing a password.

0.1.x had no service-level way to change a password, so callers used
``user.set_password(...)`` directly, which left every API key and session
the old password had opened still usable. These tests pin the service
behaviour: the new password works, the old one does not, and what the old
password unlocked is revoked.
"""

import pytest

from surrealengine_auth import SurrealEngineAuth
from surrealengine_auth.models import SecurityEvent, User
from surrealengine_auth.service import AuthenticationError

OLD_PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a whole new battery staple"


class TestChangePassword:
    def test_the_new_password_authenticates(self, user):
        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        authenticated = SurrealEngineAuth.authenticate("alice", NEW_PASSWORD)
        assert authenticated.id == user.id

    def test_the_old_password_stops_working(self, user):
        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", OLD_PASSWORD)

    def test_the_hash_is_argon2id_not_the_legacy_digest(self, user):
        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        assert user.password_hash.startswith("$argon2id$")
        assert user.salt is None

    def test_the_wrong_current_password_is_refused(self, user):
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.change_password(
                user, NEW_PASSWORD, current_password="not the password"
            )

        # The refusal must not have changed the stored credential.
        assert SurrealEngineAuth.authenticate("alice", OLD_PASSWORD)

    def test_the_right_current_password_is_accepted(self, user):
        SurrealEngineAuth.change_password(
            user, NEW_PASSWORD, current_password=OLD_PASSWORD
        )

        assert SurrealEngineAuth.authenticate("alice", NEW_PASSWORD)

    def test_api_keys_are_revoked(self, user):
        created = SurrealEngineAuth.create_api_key(user, "stale key")
        assert created["api_key"]

        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate_with_api_key(created["api_key"])

    def test_the_revocation_is_audited(self, user):
        created = SurrealEngineAuth.create_api_key(user, "stale key")

        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        events = SecurityEvent.objects.filter_sync(
            event_type="password_changed", user_id=user.id
        ).all_sync()
        assert len(events) == 1
        assert created["key"]["key_id"] in events[0].details["revoked_api_keys"]

        revocations = SecurityEvent.objects.filter_sync(
            event_type="api_key_revoked", user_id=user.id
        ).all_sync()
        assert any(
            event.details.get("reason") == "Password changed"
            for event in revocations
        )

    def test_an_outstanding_passwordless_token_is_cleared(self, user):
        token = user.generate_login_token()
        assert token

        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        assert user.login_token is None
        assert user.login_token_expires_at is None
        # The token must no longer redeem for a session.
        assert User.verify_login_token(token) is None

    def test_an_outstanding_email_code_is_cleared(self, user):
        user.tf_primary_method = "email"
        user.issue_email_two_factor_code()
        assert user.tf_email_code_hash

        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        assert user.tf_email_code_hash is None
        assert user.tf_email_code_expires_at is None
        assert user.tf_email_code_attempts == 0

    def test_the_lockout_counter_is_cleared(self, user):
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                SurrealEngineAuth.authenticate("alice", "wrong")
        # authenticate() re-fetches the user, so the counter is bumped on a
        # fresh instance; the stored value is the one that matters.
        assert SurrealEngineAuth.get_user_by_username("alice").failed_attempts > 0

        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        reloaded = SurrealEngineAuth.get_user_by_username("alice")
        assert reloaded.failed_attempts == 0
        assert reloaded.last_failed_at is None

    def test_a_legacy_user_is_upgraded(self, sync_connection):
        from surrealengine_auth import security

        legacy_hash = security.hash_password(
            OLD_PASSWORD, algorithm="pbkdf2", salt="a1b2c3d4"
        )
        legacy = SurrealEngineAuth._user_class(
            username="legacy",
            email="legacy@example.com",
            password_hash=legacy_hash,
            salt="a1b2c3d4",
        )
        legacy.save_sync()

        SurrealEngineAuth.change_password(legacy, NEW_PASSWORD)

        assert legacy.password_hash.startswith("$argon2id$")
        assert SurrealEngineAuth.authenticate("legacy", NEW_PASSWORD)

    def test_an_empty_password_is_refused(self, user):
        with pytest.raises(ValueError):
            SurrealEngineAuth.change_password(user, "")

        assert SurrealEngineAuth.authenticate("alice", OLD_PASSWORD)

    def test_the_change_is_persisted(self, user):
        SurrealEngineAuth.change_password(user, NEW_PASSWORD)

        reloaded = SurrealEngineAuth.get_user_by_username("alice")
        assert reloaded.verify_password(NEW_PASSWORD)
        assert not reloaded.verify_password(OLD_PASSWORD)


class TestSetPassword:
    def test_it_hashes_without_saving(self, user):
        user.set_password(NEW_PASSWORD)

        assert user.password_hash.startswith("$argon2id$")
        assert user.verify_password(NEW_PASSWORD)
        # Nothing has been written yet, so the stored credential is unchanged.
        reloaded = SurrealEngineAuth.get_user_by_username("alice")
        assert reloaded.verify_password(OLD_PASSWORD)

    def test_a_following_save_persists_it(self, user):
        user.set_password(NEW_PASSWORD)
        user.save_sync()

        reloaded = SurrealEngineAuth.get_user_by_username("alice")
        assert reloaded.verify_password(NEW_PASSWORD)


class TestChangePasswordAsync:
    @pytest.mark.asyncio
    async def test_the_new_password_authenticates(self, async_user):
        await SurrealEngineAuth.change_password_async(async_user, NEW_PASSWORD)

        authenticated = await SurrealEngineAuth.authenticate_async(
            "alice", NEW_PASSWORD
        )
        assert authenticated.id == async_user.id

    @pytest.mark.asyncio
    async def test_the_old_password_stops_working(self, async_user):
        await SurrealEngineAuth.change_password_async(async_user, NEW_PASSWORD)

        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.authenticate_async("alice", OLD_PASSWORD)

    @pytest.mark.asyncio
    async def test_the_wrong_current_password_is_refused(self, async_user):
        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.change_password_async(
                async_user, NEW_PASSWORD, current_password="not the password"
            )

    @pytest.mark.asyncio
    async def test_api_keys_are_revoked(self, async_user):
        created = await SurrealEngineAuth.create_api_key_async(
            async_user, "stale key"
        )

        await SurrealEngineAuth.change_password_async(async_user, NEW_PASSWORD)

        with pytest.raises(AuthenticationError):
            await SurrealEngineAuth.authenticate_with_api_key_async(
                created["api_key"]
            )

    @pytest.mark.asyncio
    async def test_the_change_is_audited(self, async_user):
        await SurrealEngineAuth.change_password_async(async_user, NEW_PASSWORD)

        events = await SecurityEvent.objects.filter(
            event_type="password_changed", user_id=async_user.id
        ).all()
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_the_change_is_persisted(self, async_user):
        await SurrealEngineAuth.change_password_async(async_user, NEW_PASSWORD)

        reloaded = await SurrealEngineAuth.get_user_by_username_async("alice")
        assert reloaded.verify_password(NEW_PASSWORD)
