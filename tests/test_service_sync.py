"""Tests for registration, password authentication, and lockout (sync)."""

import hashlib

import pytest
from surrealengine.context import get_active_connection

from surrealengine_auth import security
from surrealengine_auth.models import APIKey, User, UserBuiltin
from surrealengine_auth.service import (
    AuthenticationError,
    LockoutError,
    PermissionDenied,
    SurrealEngineAuth,
)

PASSWORD = "correct horse battery staple"


class TestRegistration:
    def test_registers_a_user(self, sync_connection):
        user, created = SurrealEngineAuth.register_user(
            "bob", "bob@example.com", PASSWORD
        )
        assert created is True
        assert user is not None
        assert user.username == "bob"
        assert user.is_active is True
        assert user.is_admin is False

    def test_password_is_not_stored_in_the_clear(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user("carl", "carl@example.com", PASSWORD)
        assert PASSWORD not in user.password_hash
        assert user.password_hash.startswith("$argon2id$")
        assert user.verify_password(PASSWORD)
        assert not user.verify_password("wrong")

    def test_duplicate_username_does_not_leak_the_existing_account(
        self, sync_connection
    ):
        first, _ = SurrealEngineAuth.register_user("dave", "dave@example.com", PASSWORD)
        second, created = SurrealEngineAuth.register_user("dave", "other@example.com", PASSWORD)

        assert created is False
        # 0.1.x returned the existing User here, handing the caller another
        # account's password_hash, salt, totp_secret and login_token.
        assert second is None
        assert first.password_hash != getattr(second, "password_hash", None)

    def test_duplicate_email_does_not_leak_the_existing_account(self, sync_connection):
        SurrealEngineAuth.register_user("erin", "erin@example.com", PASSWORD)
        second, created = SurrealEngineAuth.register_user("erin2", "erin@example.com", PASSWORD)
        assert created is False
        assert second is None

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"username": "", "email": "x@example.com", "password": PASSWORD},
            {"username": "x", "email": "", "password": PASSWORD},
            {"username": "x", "email": "x@example.com", "password": ""},
            {"username": None, "email": "x@example.com", "password": PASSWORD},
        ],
    )
    def test_missing_fields_rejected(self, sync_connection, kwargs):
        with pytest.raises(ValueError):
            SurrealEngineAuth.register_user(**kwargs)

    def test_admin_flag_is_set_when_requested(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "root", "root@example.com", PASSWORD, is_admin=True
        )
        assert user.is_admin is True

    def test_metadata_is_stored(self, sync_connection):
        user, _ = SurrealEngineAuth.register_user(
            "meta", "meta@example.com", PASSWORD, metadata={"team": "core"}
        )
        assert user.metadata["team"] == "core"

    def test_registration_is_recorded_in_the_audit_log(self, sync_connection):
        from surrealengine_auth.models import SecurityEvent

        user, _ = SurrealEngineAuth.register_user("aud", "aud@example.com", PASSWORD)
        events = SecurityEvent.objects.filter_sync(
            event_type="user_registered", user_id=str(user.id)
        ).all_sync()
        assert len(events) == 1


class TestPasswordAuthentication:
    def test_authenticates_by_username(self, user):
        assert SurrealEngineAuth.authenticate("alice", PASSWORD) is not None

    def test_authenticates_by_email(self, user):
        assert SurrealEngineAuth.authenticate("alice@example.com", PASSWORD) is not None

    def test_wrong_password_raises(self, user):
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", "wrong")

    def test_unknown_user_raises_the_same_error(self, user):
        # Indistinguishable from a wrong password so accounts cannot be
        # enumerated from the exception type.
        with pytest.raises(AuthenticationError) as unknown:
            SurrealEngineAuth.authenticate("nobody", PASSWORD)
        with pytest.raises(AuthenticationError) as wrong_password:
            SurrealEngineAuth.authenticate("alice", "wrong")
        assert str(unknown.value) == str(wrong_password.value)

    def test_inactive_user_cannot_authenticate(self, user):
        SurrealEngineAuth.deactivate_user(user)
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", PASSWORD)

    def test_successful_login_updates_last_login(self, user):
        assert user.last_login is None
        authenticated = SurrealEngineAuth.authenticate("alice", PASSWORD)
        assert authenticated.last_login is not None

    def test_empty_password_is_rejected(self, user):
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", "")

    def test_login_upgrades_a_legacy_pbkdf2_hash(self, sync_connection):
        """A 0.1.x hash must verify, then be re-hashed to Argon2id."""
        salt = "b" * 32
        legacy = hashlib.pbkdf2_hmac(
            "sha256", PASSWORD.encode(), salt.encode(), 100_000
        ).hex()

        user = User.create_user(
            username="legacy",
            email="legacy@example.com",
            password=PASSWORD,
        )
        # Overwrite with a 0.1.x-style record.
        user.password_hash = legacy
        user.salt = salt
        user.save_sync()
        assert user.password_needs_rehash()

        authenticated = SurrealEngineAuth.authenticate("legacy", PASSWORD)
        assert authenticated.password_hash.startswith("$argon2id$")
        assert authenticated.salt is None
        assert authenticated.verify_password(PASSWORD)

    def test_legacy_user_with_wrong_password_is_still_refused(self, sync_connection):
        salt = "c" * 32
        legacy = hashlib.pbkdf2_hmac(
            "sha256", PASSWORD.encode(), salt.encode(), 100_000
        ).hex()
        user = User.create_user(
            username="legacy2", email="legacy2@example.com", password=PASSWORD
        )
        user.password_hash = legacy
        user.salt = salt
        user.save_sync()

        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("legacy2", "wrong")


class TestLockout:
    def test_locks_out_after_repeated_failures(self, user):
        SurrealEngineAuth.max_attempts = 3
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                SurrealEngineAuth.authenticate("alice", "wrong")

        with pytest.raises(LockoutError):
            SurrealEngineAuth.authenticate("alice", PASSWORD)

    def test_correct_password_also_blocked_while_locked_out(self, user):
        SurrealEngineAuth.max_attempts = 1
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", "wrong")
        with pytest.raises(LockoutError):
            SurrealEngineAuth.authenticate("alice", PASSWORD)

    def test_success_clears_the_counter(self, user):
        SurrealEngineAuth.max_attempts = 3
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", "wrong")
        assert SurrealEngineAuth.authenticate("alice", PASSWORD)

        # Two more failures should not lock, since the counter reset.
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                SurrealEngineAuth.authenticate("alice", "wrong")
        assert SurrealEngineAuth.authenticate("alice", PASSWORD)

    def test_lockout_can_be_disabled(self, user):
        SurrealEngineAuth.max_attempts = 0
        for _ in range(10):
            with pytest.raises(AuthenticationError):
                SurrealEngineAuth.authenticate("alice", "wrong")
        assert SurrealEngineAuth.authenticate("alice", PASSWORD)

    def test_lockout_also_covers_unknown_users(self, user):
        """A nonexistent identifier must not be a free oracle."""
        SurrealEngineAuth.max_attempts = 2
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                SurrealEngineAuth.authenticate("ghost", "anything")
        with pytest.raises(LockoutError):
            SurrealEngineAuth.authenticate("ghost", "anything")

    def test_lockout_is_recorded(self, user):
        from surrealengine_auth.models import SecurityEvent

        SurrealEngineAuth.max_attempts = 1
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", "wrong")
        with pytest.raises(LockoutError):
            SurrealEngineAuth.authenticate("alice", PASSWORD)

        events = SecurityEvent.objects.filter_sync(event_type="account_locked").all_sync()
        assert len(events) == 1

    def test_failure_counter_is_not_a_user_visible_field(self, user):
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", "wrong")
        # Counters are typed columns, not entries in the caller-visible dict.
        stored = SurrealEngineAuth.get_user_by_username("alice")
        assert stored.failed_attempts == 1
        assert "failed_attempts" not in stored.to_dict()
        assert "last_failed_at" not in stored.to_dict()
        assert "password_hash" not in stored.to_dict()


class TestUserLookup:
    def test_get_by_id(self, user):
        assert SurrealEngineAuth.get_user_by_id(str(user.id)).username == "alice"

    def test_get_by_username(self, user):
        assert SurrealEngineAuth.get_user_by_username("alice") is not None

    def test_get_by_email(self, user):
        assert SurrealEngineAuth.get_user_by_email("alice@example.com") is not None

    def test_missing_user_returns_none(self, sync_connection):
        assert SurrealEngineAuth.get_user_by_username("nobody") is None
        assert SurrealEngineAuth.get_user_by_email("nobody@example.com") is None
        assert SurrealEngineAuth.get_user_by_id("users:doesnotexist") is None

    def test_list_users_pagination_shape(self, sync_connection):
        for index in range(3):
            SurrealEngineAuth.register_user(
                f"list{index}", f"list{index}@example.com", PASSWORD
            )
        page = SurrealEngineAuth.list_users(page_number=1, page_size=2)
        assert page["total"] == 3
        assert page["page"] == 1
        assert page["pages"] == 2
        assert page["size"] == 2
        assert len(page["items"]) == 2


class TestUpdateUser:
    def test_updates_allowed_fields(self, user):
        updated = SurrealEngineAuth.update_user(user, email="new@example.com")
        assert updated.email == "new@example.com"

    def test_password_goes_through_the_hasher(self, user):
        SurrealEngineAuth.update_user(user, password="a-new-password")
        assert user.verify_password("a-new-password")
        assert user.password_hash.startswith("$argon2id$")

    @pytest.mark.parametrize(
        "field,value",
        [
            ("is_admin", True),
            ("password_hash", "forged-hash"),
            ("salt", "forged-salt"),
            ("totp_secret", "AAAABBBBCCCCDDDD"),
            ("tf_recovery_codes", ["attacker-controlled"]),
            ("login_token", "attacker-token"),
            ("confirmation_token_jti", "attacker-jti"),
            ("created_at", "1999-01-01"),
        ],
    )
    def test_protected_fields_are_refused(self, user, field, value):
        # 0.1.x let update_user set anything, which was a privilege
        # escalation path via is_admin and a hash-replacement path.
        with pytest.raises(PermissionDenied):
            SurrealEngineAuth.update_user(user, **{field: value})

    def test_protected_field_error_names_the_field(self, user):
        with pytest.raises(PermissionDenied, match="is_admin"):
            SurrealEngineAuth.update_user(user, is_admin=True)

    def test_password_is_not_echoed_into_the_audit_log(self, user):
        from surrealengine_auth.models import SecurityEvent

        SurrealEngineAuth.update_user(user, password="brand-new-secret")
        events = SecurityEvent.objects.filter_sync(
            event_type="user_updated", user_id=str(user.id)
        ).all_sync()
        assert "brand-new-secret" not in str(events[0].details)

    def test_audit_log_records_field_names_not_values(self, user):
        from surrealengine_auth.models import SecurityEvent

        SurrealEngineAuth.update_user(user, email="another@example.com")
        events = SecurityEvent.objects.filter_sync(
            event_type="user_updated", user_id=str(user.id)
        ).all_sync()
        assert events[0].details["updated_fields"] == ["email"]


class TestAccountState:
    def test_deactivate_revokes_all_keys(self, user):
        first = SurrealEngineAuth.create_api_key(user, name="one")["api_key"]
        second = SurrealEngineAuth.create_api_key(user, name="two")["api_key"]

        SurrealEngineAuth.deactivate_user(user)

        assert user.is_active is False
        for key in user.get_api_keys():
            assert key.is_usable() is False
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate_with_api_key(first)
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate_with_api_key(second)

    def test_activate_restores_login(self, user):
        SurrealEngineAuth.deactivate_user(user)
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("alice", PASSWORD)

        SurrealEngineAuth.activate_user(user)
        assert SurrealEngineAuth.authenticate("alice", PASSWORD)


class TestCustomUserClass:
    def test_can_swap_the_user_model(self, sync_connection):
        class CustomUser(UserBuiltin):
            class Meta:
                collection = "custom_users"

        SurrealEngineAuth.configure_user_class(CustomUser)
        assert SurrealEngineAuth._user_class is CustomUser

    def test_base_class_does_not_claim_a_concrete_collection(self):
        # Only one Document class may own a collection name, so UserBuiltin
        # must not sit on "user" -- the name 0.1.x records were written to.
        assert User._get_collection_name() == "user"
        assert UserBuiltin._get_collection_name() != "user"

    def test_api_key_owner_is_not_pinned_to_one_table(self):
        # The user class is pluggable, so the key's owner column must not be a
        # ReferenceField naming a specific collection.
        from surrealengine.fields import RecordIDField

        assert isinstance(APIKey._fields["user"], RecordIDField)

    def test_a_reference_field_would_reject_a_custom_user(
        self, sync_connection
    ):
        """Why the column is a bare record id, demonstrated rather than asserted.

        A ``ReferenceField`` names its target collection, and SurrealDB then
        refuses a record from anywhere else. The failure is on the write, after
        the key has already been minted, so the caller gets an exception
        instead of a key.
        """
        from surrealengine.fields import ReferenceField

        class CustomUser(UserBuiltin):
            class Meta:
                collection = "refcheck_users"

        SurrealEngineAuth.configure_user_class(CustomUser)
        user = CustomUser(username="bob", email="bob@example.com")
        user.password_hash = security.hash_password("a password")
        user.salt = None
        user.save_sync()

        # Rebuild the table so the column really is constrained: swapping the
        # ORM field alone leaves the existing schema in place.
        connection = get_active_connection(async_mode=False)
        connection.client.query("REMOVE TABLE api_keys")
        original = APIKey._fields["user"]
        APIKey._fields["user"] = ReferenceField(document_type=User)
        try:
            SurrealEngineAuth.setup_database()
            assert "record<user>" in APIKey._get_field_type_for_surreal(
                APIKey._fields["user"]
            )
            with pytest.raises(Exception):
                user.create_api_key("pinned", expires_in_days=1)
            assert APIKey.objects.all_sync() == []
        finally:
            APIKey._fields["user"] = original
            connection.client.query("REMOVE TABLE api_keys")
            SurrealEngineAuth.setup_database()

        # And the record id actually works for the same user.
        created = user.create_api_key("unpinned", expires_in_days=1)
        assert (
            SurrealEngineAuth.authenticate_with_api_key(created["api_key"]).username
            == "bob"
        )

    def test_audit_events_are_findable_by_owner(self, sync_connection, user):
        """Why ``user_id`` is a record link, demonstrated rather than asserted.

        With a string column the event writes fine and then cannot be found:
        the ORM serialises a record-shaped value into a record literal when it
        builds the filter, so a record is compared against a stored string and
        nothing matches. The event looks written, which is worse than an
        obvious failure.
        """
        from surrealengine.fields import StringField

        from surrealengine_auth.models import SecurityEvent

        SecurityEvent.log_event(event_type="user_updated", user_id=user.id)
        by_record = SecurityEvent.objects.filter_sync(
            event_type="user_updated", user_id=user.id
        ).all_sync()
        by_string = SecurityEvent.objects.filter_sync(
            event_type="user_updated", user_id=str(user.id)
        ).all_sync()
        assert len(by_record) == 1
        assert len(by_string) == 1

        # Rebuild the table with a string column to show what the old schema
        # did, then restore. Swapping the field alone is not enough: the table
        # already constrains the column to a record.
        connection = get_active_connection(async_mode=False)
        connection.client.query("REMOVE TABLE security_event")
        original = SecurityEvent._fields["user_id"]
        SecurityEvent._fields["user_id"] = StringField()
        try:
            SurrealEngineAuth.setup_database()
            SecurityEvent.log_event(event_type="user_activated", user_id=user.id)
            stored = SecurityEvent.objects.filter_sync(
                event_type="user_activated"
            ).all_sync()
            assert stored, "the event should exist"
            assert isinstance(stored[0].user_id, str), "stored as a plain string"
            for label, value in (("RecordID", user.id), ("str", str(user.id))):
                assert (
                    SecurityEvent.objects.filter_sync(
                        event_type="user_activated", user_id=value
                    ).all_sync()
                    == []
                ), f"unfindable when filtering by {label}"
        finally:
            SecurityEvent._fields["user_id"] = original
            connection.client.query("REMOVE TABLE security_event")
            SurrealEngineAuth.setup_database()

    def test_rejects_a_non_user_class(self, sync_connection):
        with pytest.raises(TypeError):
            SurrealEngineAuth.configure_user_class(dict)

        class Unrelated:
            pass

        with pytest.raises(TypeError):
            SurrealEngineAuth.configure_user_class(Unrelated)
