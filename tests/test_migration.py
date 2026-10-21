"""Upgrade path from a 0.1.x database.

The requirement is narrow and specific: nobody is using the API-key format
change, but people's existing passwords must keep working. These tests build a
0.1.x-shaped table and run the current model against it, so the guarantee is
checked rather than assumed.
"""

import hashlib
import secrets

import pytest

from surrealengine_auth import security
from surrealengine_auth.models import User, UserBuiltin
from surrealengine_auth.service import (
    AuthenticationError,
    SurrealEngineAuth,
)

PASSWORD = "correct horse battery staple"

#: The 0.1.x ``user`` table, field for field. Every field added since is
#: absent, which is the point: an old record must load without them.
LEGACY_USER_SCHEMA = """
DEFINE TABLE user SCHEMALESS;
DEFINE FIELD username ON user TYPE option<string>;
DEFINE FIELD email ON user TYPE option<string>;
DEFINE FIELD password_hash ON user TYPE option<string>;
DEFINE FIELD salt ON user TYPE option<string>;
DEFINE FIELD is_active ON user TYPE option<bool>;
DEFINE FIELD is_admin ON user TYPE option<bool>;
DEFINE FIELD confirmed_at ON user TYPE option<datetime>;
DEFINE FIELD totp_secret ON user TYPE option<string>;
DEFINE FIELD tf_primary_method ON user TYPE option<string>;
DEFINE FIELD tf_recovery_codes ON user TYPE option<array<string>>;
DEFINE FIELD login_token ON user TYPE option<string>;
DEFINE FIELD login_token_expires_at ON user TYPE option<datetime>;
DEFINE FIELD created_at ON user TYPE option<datetime>;
DEFINE FIELD updated_at ON user TYPE option<datetime>;
DEFINE FIELD last_login ON user TYPE option<datetime>;
DEFINE FIELD metadata ON user TYPE option<object>;
DEFINE INDEX legacy_username ON user FIELDS username UNIQUE;
DEFINE INDEX legacy_email ON user FIELDS email UNIQUE;
"""


def legacy_hash(password: str, salt: str) -> str:
    """The 0.1.x hashing scheme, verbatim."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()


@pytest.fixture
def legacy_db():
    """A database containing one user written the 0.1.x way.

    Uses its own connection rather than ``sync_connection``: that fixture
    builds the *current* strict schema, and applying the old table definition
    on top of it would fail. The point of this fixture is to start from a
    database the current code has never touched.
    """
    from surrealengine import create_connection

    connection = create_connection(
        "mem://", "auth_test", "legacy_db", async_mode=False, make_default=True
    )
    connection.connect()
    for statement in LEGACY_USER_SCHEMA.strip().split(";"):
        statement = statement.strip()
        if statement:
            connection.query(statement)

    salt = secrets.token_hex(16)
    connection.query(
        "CREATE user SET username = 'legacy', email = 'legacy@example.com', "
        f"password_hash = '{legacy_hash(PASSWORD, salt)}', salt = '{salt}', "
        "is_active = true, is_admin = false"
    )
    yield connection
    connection.disconnect()


class TestLegacyPasswordsKeepWorking:
    def test_an_old_record_loads(self, legacy_db):
        user = SurrealEngineAuth.get_user_by_username("legacy")
        assert user is not None
        assert user.email == "legacy@example.com"
        assert user.is_active is True

    def test_an_old_password_authenticates(self, legacy_db):
        assert SurrealEngineAuth.authenticate("legacy", PASSWORD).username == "legacy"

    def test_the_hash_is_upgraded_in_place(self, legacy_db):
        user = SurrealEngineAuth.authenticate("legacy", PASSWORD)
        assert user.password_hash.startswith("$argon2id$")

        # Persisted, not just held in memory, and the old column is now vestigial.
        stored = SurrealEngineAuth.get_user_by_username("legacy")
        assert stored.password_hash.startswith("$argon2id$")
        assert stored.verify_password(PASSWORD)

    def test_a_wrong_password_is_still_rejected(self, legacy_db):
        with pytest.raises(AuthenticationError):
            SurrealEngineAuth.authenticate("legacy", "not the password")

    def test_upgrade_happens_once_not_every_login(self, legacy_db):
        SurrealEngineAuth.authenticate("legacy", PASSWORD)
        first = SurrealEngineAuth.get_user_by_username("legacy").password_hash
        SurrealEngineAuth.authenticate("legacy", PASSWORD)
        second = SurrealEngineAuth.get_user_by_username("legacy").password_hash
        # Argon2 salts per hash, so an unchanged hash means no needless rewrite.
        assert first == second

    def test_a_legacy_user_with_no_metadata_still_enrols_in_two_factor(self, legacy_db):
        user = SurrealEngineAuth.get_user_by_username("legacy")
        setup = user.setup_two_factor("authenticator")
        assert setup["secret"]
        assert user.verify_two_factor(user.generate_two_factor_code()) is True

    def test_a_legacy_user_can_hold_an_api_key(self, legacy_db):
        user = SurrealEngineAuth.get_user_by_username("legacy")
        created = user.create_api_key("legacy key", expires_in_days=30)
        assert created["key"]["key_id"]
        assert "key_hash" not in created["key"]
        assert SurrealEngineAuth.authenticate_with_api_key(
            created["api_key"]
        ).username == "legacy"

    def test_the_salt_column_is_still_part_of_the_model(self):
        """It is read for legacy digests, so the column must survive the upgrade."""
        assert "salt" in User._fields

    def test_the_collection_is_the_table_0_1_x_actually_wrote_to(self):
        """Guard against a rename that would strand every existing account.

        0.1.x declared ``collection = "users"`` on ``UserBuiltin`` but not on
        ``User``, and the metaclass does not inherit ``Meta``. The declared
        name was therefore unused: records went to ``user``, derived from the
        class name.
        """
        assert User.Meta.collection == "user"

    def test_the_metaclass_does_not_inherit_meta(self):
        """The reason the collection has to be spelled out here.

        If surrealengine ever starts walking the MRO for ``Meta``, a subclass
        without its own ``Meta`` would start resolving to whatever
        ``UserBuiltin`` declares. This test documents the current behaviour
        that the collection name depends on.
        """
        class Anonymous(UserBuiltin):
            pass

        assert "Meta" not in vars(Anonymous)


class TestBreakingChanges:
    def test_the_legacy_id_dot_secret_scheme_is_gone(self):
        """No shim: the attribute and helper were removed outright."""
        assert not hasattr(User, "parse_key")
        assert not hasattr(SurrealEngineAuth, "parse_api_key")

    def test_api_keys_are_bare_uuids(self):
        from surrealengine_auth.models import APIKey

        assert APIKey._fields["key_hash"] is not None
        assert "key_secret" not in APIKey._fields
        generated = security.generate_api_key()
        assert len(generated) == 36 and generated.count("-") == 4
        assert "." not in generated


class TestApiKeyDigestsAreKeyedConsistently:
    """Issuance and verification must agree on the keying secret.

    They used to disagree: creation hashed unkeyed, verification hashed with
    the app secret. Every key therefore stopped working the moment an app
    secret was configured, and the only test covering it asserted a failure,
    so it passed either way.
    """

    def test_a_key_verifies_when_an_app_secret_is_configured(self, user):
        created = user.create_api_key("keyed")["api_key"]
        assert SurrealEngineAuth.authenticate_with_api_key(created).username == "alice"

    def test_the_stored_digest_is_keyed(self, user):
        created = user.create_api_key("keyed")["api_key"]
        expected = security.hash_api_key(created)
        # HMAC under the configured secret, not a bare SHA-256.
        assert expected != security.hashlib.sha256(
            created.encode("utf-8")
        ).hexdigest()
        assert expected == security.hash_api_key(
            created, app_secret=SurrealEngineAuth.get_app_secret()
        )

    def test_a_key_still_verifies_without_a_secret(self, user):
        # configure_app_secret(None) falls back to the token secret, so the
        # unkeyed case has to be reached by clearing both holders.
        SurrealEngineAuth._app_secret = None
        security.AppSecretConfig.configure(None)
        created = user.create_api_key("unkeyed")["api_key"]
        assert created
        assert (
            security.hash_api_key(created)
            == security.hashlib.sha256(created.encode("utf-8")).hexdigest()
        )
        assert SurrealEngineAuth.authenticate_with_api_key(created).username == "alice"

    def test_the_wrong_secret_does_not_verify(self, user):
        created = user.create_api_key("keyed")["api_key"]
        assert (
            security.hash_api_key(created, app_secret="a-different-secret")
            != security.hash_api_key(created)
        )


class TestSetupDatabaseAgainstAnExistingDatabase:
    """``setup_database`` has to work on a database it did not create.

    Every case below is a way the previous DDL broke an upgrade. All of them
    were found by running the real thing, not by reading the code: the failure
    modes are in SurrealDB's schema handling, not in the auth package.
    """

    def test_it_is_safe_to_call_twice(self, sync_connection):
        """It claimed to be. The first version raised AlreadyExistsError."""
        SurrealEngineAuth.setup_database()
        SurrealEngineAuth.setup_database()  # must not raise

    def test_it_converges_a_legacy_schemaless_table(self, legacy_db):
        assert not _table_is_schemafull(legacy_db, "user")
        SurrealEngineAuth.setup_database()
        assert _table_is_schemafull(legacy_db, "user")

    def test_it_preserves_legacy_rows(self, legacy_db):
        SurrealEngineAuth.setup_database()
        assert legacy_db.query("SELECT * FROM user")[0]

    def test_a_legacy_user_can_still_be_upgraded(self, legacy_db):
        """The failure this guards: ``object FLEXIBLE`` is not optional.

        ``metadata`` was absent on every 0.1.x row, but the generated schema
        declared it as a required object. Writing the upgraded Argon2id hash
        then failed with "Couldn't coerce value for field 'metadata' ... found
        'NONE'", so a legacy user could authenticate and then be unable to
        save anything at all.
        """
        SurrealEngineAuth.setup_database()
        user = SurrealEngineAuth.authenticate("legacy", PASSWORD)
        assert user.password_hash.startswith("$argon2id$")

    def test_metadata_still_accepts_arbitrary_keys(self, legacy_db):
        """``option<object>`` without FLEXIBLE would reject unknown keys."""
        SurrealEngineAuth.setup_database()
        user = SurrealEngineAuth.get_user_by_username("legacy")
        user.metadata = {"plan": "pro", "seats": 12}
        user.save_sync()
        assert SurrealEngineAuth.get_user_by_username("legacy").metadata == {
            "plan": "pro",
            "seats": 12,
        }

    def test_legacy_audit_rows_do_not_block_new_ones(self, legacy_db):
        """A string-valued column being tightened to record must not wedge.

        ``security_event.user_id`` was a string in 0.1.x and is a record now.
        Redefining the column left the table rejecting every subsequent write.
        """
        from surrealengine_auth.models import SecurityEvent

        legacy_db.query("DEFINE TABLE IF NOT EXISTS security_event SCHEMALESS")
        legacy_db.query("DEFINE FIELD user_id ON security_event TYPE option<string>")
        legacy_db.query(
            "CREATE security_event SET event_type = 'login_success', user_id = 'user:legacy'"
        )

        SurrealEngineAuth.setup_database()
        user = SurrealEngineAuth.get_user_by_username("legacy")
        SecurityEvent.log_event(event_type="login_success", user_id=user.id)

        fresh = SecurityEvent.objects.filter_sync(user_id=user.id).all_sync()
        assert fresh, "the new audit row was not written"

    def test_the_legacy_audit_row_is_left_alone(self, legacy_db):
        from surrealengine_auth.models import SecurityEvent

        legacy_db.query("DEFINE TABLE IF NOT EXISTS security_event SCHEMALESS")
        legacy_db.query("DEFINE FIELD user_id ON security_event TYPE option<string>")
        legacy_db.query(
            "CREATE security_event SET event_type = 'login_success', user_id = 'user:legacy'"
        )
        SurrealEngineAuth.setup_database()
        assert len(SecurityEvent.objects.all_sync()) == 1


def _table_is_schemafull(connection, table: str) -> bool:
    """True when ``table`` rejects undefined fields."""
    try:
        connection.query(f"CREATE {table} SET __probe__ = 1")
    except Exception:
        return True
    connection.query(f"DELETE {table} WHERE __probe__ = 1")
    return False
