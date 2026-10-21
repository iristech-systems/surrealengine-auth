"""
High-level authentication service.

Every public method is a thin, uniform wrapper: validate input, delegate to
the model, record exactly one :class:`SecurityEvent`. Each method raises
:class:`AuthenticationError` or :class:`PermissionDenied` on refusal and
returns the authenticated principal on success, so callers do not have to
distinguish "no such user" from "wrong password".

Compatibility notes for 0.1.x
------------------------------
* The sync method names and their ``_async`` twins are unchanged.
* ``register_user`` and ``authenticate`` still return ``(user, created)`` and
  ``user``. What changed is what a *failed* call returns: a refused
  registration yields ``(None, False)`` instead of leaking the existing
  ``User`` object (which carried ``password_hash``, ``salt``, ``totp_secret``
  and ``login_token``), and a failed login raises rather than returning None.
* ``authenticate_with_api_key`` takes the bare UUID4 key, and
  ``APIKey.formatted_key`` / ``APIKey.parse_key`` are gone because the
  ``"id.secret"`` scheme is no longer accepted or produced.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Type

from surrealengine.context import get_active_connection
from surrealengine.exceptions import DoesNotExist

from . import security
from .email_service import EmailService
from .logger import get_logger
from .models import APIKey, SecurityEvent, TOTPManager, User, UserBuiltin

__all__ = [
    "SurrealEngineAuth",
    "AuthenticationError",
    "PermissionDenied",
    "LockoutError",
]


class AuthenticationError(Exception):
    """Credentials are not valid.

    Deliberately does not distinguish between an unknown user, a wrong
    password, and an inactive account.
    """


class PermissionDenied(Exception):
    """The caller is authenticated but not allowed to do this."""


class LockoutError(AuthenticationError):
    """Too many failed attempts for this identifier."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _Unset:
    """Sentinel distinguishing "not loaded" from "looked up, absent"."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unset>"


_UNSET: Any = _Unset()


def _as_utc(value: Any) -> datetime:
    """Coerce a stored timestamp into a timezone-aware UTC datetime.

    ``DateTimeField`` returns a ``PreciseDatetime`` and records written by
    other tools may be naive. Subtracting either from an aware ``now()``
    raises, which would turn a lockout check into an unhandled error.
    """
    if not isinstance(value, datetime):
        raise TypeError(f"Expected a datetime, got {type(value)!r}")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _clear_outstanding_tokens(user: UserBuiltin) -> None:
    """Invalidate the session and 2FA material a password change should end.

    A passwordless login token and an emailed 2FA code are both short-lived
    grants that were issued to whoever knew the old password's address.
    Rotating the password should not leave them usable, so they are cleared
    here. The caller saves the user afterwards.
    """
    user.login_token = None
    user.login_token_expires_at = None
    user.confirmation_token_jti = None
    user.confirmation_token_expires_at = None
    user.tf_email_code_hash = None
    user.tf_email_code_expires_at = None
    user.tf_email_code_attempts = 0


def _optional_object_types(sql: str) -> str:
    """Wrap a bare ``object`` type in ``option<>`` so absent values are legal.

    surrealengine skips the ``option<>`` wrapper for object fields, on the
    assumption that ``object FLEXIBLE`` already implies optional. It does not:
    a row written before the field existed has no value for it, and updating
    that row then fails with ``Couldn't coerce value for field 'metadata' ...
    Expected 'object' but found 'NONE'``. That is exactly the row we are trying
    to migrate -- the one whose password hash is being upgraded to Argon2id.

    ``FLEXIBLE`` has to stay outside the wrapper (``option<object> FLEXIBLE``);
    ``option<object FLEXIBLE>`` is a parse error. Note ``option<object>``
    without ``FLEXIBLE`` is not a substitute: it rejects unknown keys, which
    would break every user storing their own data in ``metadata``.
    """
    match = re.search(r"TYPE\s+(option<)?object(\s+FLEXIBLE)?\b", sql)
    if match is None or "option<object" in sql:
        return sql
    if match.group(2):
        return sql[: match.start()] + "TYPE option<object> FLEXIBLE" + sql[match.end() :]
    return sql[: match.start()] + "TYPE option<object>" + sql[match.end() :]


def _field_defs_for(model: Type) -> List[str]:
    """Return the ``DEFINE FIELD`` statements for ``model``, as OVERWRITE.

    surrealengine's own DDL is not reusable here: ``DEFINE TABLE`` lacks
    ``IF NOT EXISTS`` (so a second call raises) and a plain ``DEFINE FIELD``
    errors when the field already exists. ``OVERWRITE`` is the form that is
    safe to re-run -- it redefines the field in place, leaves existing rows
    untouched, and is what lets a 0.1.x column take on a new type.
    """
    from surrealengine.table import Table

    statements: List[str] = []
    collection = model._get_collection_name()
    for field in model._build_fielddefs(True):
        for raw in Table._build_field_sql_recursive(collection, field):
            # "DEFINE FIELD x ON t ..." -> "DEFINE FIELD OVERWRITE x ON t ..."
            sql = raw.replace("DEFINE FIELD ", "DEFINE FIELD OVERWRITE ", 1)
            statements.append(
                _optional_object_types(sql) if not field.required else sql
            )
    return statements


def _converge_table_sync(model: Type) -> None:
    """Bring ``model``'s table in line with the model, without losing rows.

    ``OVERWRITE`` on the table converts a 0.1.x ``SCHEMALESS`` table to
    ``SCHEMAFULL`` (``IF NOT EXISTS`` would leave it schemaless, and the field
    definitions below need a schemafull table) and keeps the rows. The fields
    are then defined with ``OVERWRITE`` as well: a plain ``DEFINE FIELD``
    errors on a field that already exists, and redefining a column without
    ``OVERWRITE`` leaves the table rejecting writes once it holds a value of
    the old type.
    """
    connection = get_active_connection(async_mode=False)
    name = model._get_collection_name()
    connection.client.query(f"DEFINE TABLE OVERWRITE {name} SCHEMAFULL")
    for sql in _field_defs_for(model):
        connection.client.query(sql)


async def _converge_table_async(model: Type) -> None:
    """Async counterpart of :func:`_converge_table_sync`."""
    connection = get_active_connection(async_mode=True)
    name = model._get_collection_name()
    await connection.client.query(f"DEFINE TABLE OVERWRITE {name} SCHEMAFULL")
    for sql in _field_defs_for(model):
        await connection.client.query(sql)


class SurrealEngineAuth:
    """Authentication and authorization facade.

    Configure once at startup, then call from anywhere::

        SurrealEngineAuth.configure_token_secret(os.environ["AUTH_SECRET"])
        user = SurrealEngineAuth.authenticate("alice", "hunter2")
    """

    _email_service: Optional[EmailService] = None
    _user_class: Type[UserBuiltin] = User
    _app_secret: Optional[str] = None

    #: Failed attempts allowed per identifier before the account locks.
    max_attempts: int = 5
    #: How long a lockout lasts, in seconds.
    lockout_seconds: int = 900
    #: Window in which failed attempts are counted, in seconds.
    attempt_window_seconds: int = 900

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #

    @classmethod
    def get_email_service(cls) -> EmailService:
        """Return the email service, building it from the environment once."""
        if cls._email_service is None:
            cls._email_service = EmailService(
                smtp_host=os.environ.get("SMTP_HOST", "localhost"),
                smtp_port=int(os.environ.get("SMTP_PORT", "25")),
                smtp_username=os.environ.get("SMTP_USERNAME"),
                smtp_password=os.environ.get("SMTP_PASSWORD"),
                use_tls=os.environ.get("SMTP_USE_TLS", "False").lower() == "true",
                use_ssl=os.environ.get("SMTP_USE_SSL", "False").lower() == "true",
                default_sender=os.environ.get(
                    "SMTP_SENDER", "noreply@example.com"
                ),
            )
        return cls._email_service

    @classmethod
    def configure_email_service(cls, **kwargs: Any) -> None:
        """Replace the email service with one built from ``kwargs``."""
        cls._email_service = EmailService(**kwargs)

    @classmethod
    def configure_user_class(cls, user_class: Type[UserBuiltin]) -> None:
        """Use ``user_class`` instead of the bundled :class:`User`."""
        if not isinstance(user_class, type) or not issubclass(user_class, UserBuiltin):
            raise TypeError("user_class must be a subclass of UserBuiltin")
        cls._user_class = user_class

    @classmethod
    def configure_token_secret(
        cls, secret: Optional[str] = None, *, issuer: Optional[str] = None
    ) -> str:
        """Set the secret used to sign confirmation and login tokens.

        Pass a value with at least 32 bytes of entropy. When omitted,
        ``SURREALENGINE_AUTH_SECRET`` is read from the environment. If neither
        is available a secret is generated for this process and a warning is
        logged, which invalidates outstanding tokens on restart.
        """
        resolved = secret or os.environ.get("SURREALENGINE_AUTH_SECRET")
        if not resolved:
            resolved = security.TokenConfig.generate_secret()
            get_logger().warning(
                "No SURREALENGINE_AUTH_SECRET configured; generated an "
                "ephemeral signing secret. Tokens will not survive a restart."
            )
        cls.configure_app_secret(resolved)
        security.TokenConfig.configure(resolved, issuer=issuer)
        return resolved

    @classmethod
    def configure_app_secret(cls, secret: Optional[str] = None) -> str:
        """Set the secret used to key API key digests.

        Shares the token secret when you have nothing specific in mind. An
        application secret makes stored key digests unusable to an attacker
        who obtains the ``api_keys`` table but not the secret.
        """
        resolved = secret or os.environ.get("SURREALENGINE_AUTH_SECRET")
        if not resolved:
            resolved = (
                security.TokenConfig.secret or security.TokenConfig.generate_secret()
            )
        cls._app_secret = resolved
        # Keyed digests are written and compared in different layers; both read
        # the secret from here so they cannot disagree.
        security.AppSecretConfig.configure(resolved)
        return resolved

    @classmethod
    def get_app_secret(cls) -> Optional[str]:
        """Return the secret currently used to key API key digests."""
        return cls._app_secret

    @classmethod
    def setup_database(cls) -> None:
        """Create or converge the auth tables and indexes (sync).

        Safe to call repeatedly, and safe to call against a database that a
        0.1.x release already created. Run once at application startup.

        ``Model.create_table`` cannot be used for this: its ``DEFINE TABLE``
        has no ``IF NOT EXISTS`` and its ``DEFINE FIELD`` statements error on
        a field that already exists. Calling it twice raised
        ``AlreadyExistsError``, and calling it against a real 0.1.x database
        raised on the first call -- so the tables could only ever be created by
        an application that had never run the previous version.
        """
        for model in (cls._user_class, APIKey, SecurityEvent):
            _converge_table_sync(model)
            model.create_indexes_sync()

    @classmethod
    async def setup_database_async(cls) -> None:
        """Create or converge the auth tables and indexes (async).

        Async counterpart of :meth:`setup_database`, with the same guarantees.
        """
        for model in (cls._user_class, APIKey, SecurityEvent):
            await _converge_table_async(model)
            await model.create_indexes()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @classmethod
    def _lockout_key(cls, identifier: str) -> str:
        """Key for lockout bookkeeping.

        Derived from the identifier so the raw value is not stored in an
        audit record.
        """
        return security.fingerprint(identifier, length=16)

    @classmethod
    def _attempts_key(cls, identifier: str) -> str:
        return f"auth_attempts_{cls._lockout_key(identifier)}"

    @classmethod
    def _lockout_active(cls, count: int, last: Optional[datetime]) -> bool:
        """True when ``(count, last)`` should block further attempts.

        Blocking needs both a saturated counter and a window that has not yet
        elapsed. A missing timestamp with a saturated counter blocks, so a
        record written by an older version cannot be used to slip through.
        """
        if count < cls.max_attempts:
            return False
        if last is None:
            return True
        return (_utcnow() - _as_utc(last)).total_seconds() < cls.lockout_seconds

    @classmethod
    def _bump_memory(cls, identifier: str) -> int:
        key = cls._attempts_key(identifier)
        count, _ = _MEMORY_ATTEMPTS.get(key, (0, None))
        count += 1
        _MEMORY_ATTEMPTS[key] = (count, _utcnow())
        return count

    @classmethod
    def _bump_attempts(
        cls, identifier: str, user: Any = _UNSET
    ) -> int:
        """Increment and return the failure count for ``identifier``.

        The counter lives on the user record when one exists; otherwise it goes
        to a process-local dict, since an unknown identifier has nowhere to put
        it. Callers that already loaded the user should pass it in rather than
        paying for a second lookup.
        """
        target = cls._find_user_sync(identifier) if user is _UNSET else user
        if target is None:
            return cls._bump_memory(identifier)
        count = int(target.failed_attempts or 0) + 1
        target.failed_attempts = count
        target.last_failed_at = _utcnow()
        target.save_sync()
        return count

    @classmethod
    async def _bump_attempts_async(
        cls, identifier: str, user: Any = _UNSET
    ) -> int:
        """Async :meth:`_bump_attempts`."""
        target = cls._find_user_sync(identifier) if user is _UNSET else user
        if target is None and user is _UNSET:
            target = await cls._find_user_async(identifier)
        if target is None:
            return cls._bump_memory(identifier)
        count = int(target.failed_attempts or 0) + 1
        target.failed_attempts = count
        target.last_failed_at = _utcnow()
        await target.save()
        return count

    @classmethod
    def _clear_attempts(cls, identifier: str, user: Any = _UNSET) -> None:
        """Reset the failure counter for ``identifier``.

        ``user`` should be the instance the caller is about to save. Clearing
        via a second lookup would be undone: the caller's stale instance would
        still hold the old counter and overwrite it on the next save.
        """
        target = cls._find_user_sync(identifier) if user is _UNSET else user
        if target is not None:
            target.failed_attempts = 0
            target.last_failed_at = None
            if user is _UNSET:
                target.save_sync()
        _MEMORY_ATTEMPTS.pop(cls._attempts_key(identifier), None)

    @classmethod
    async def _clear_attempts_async(
        cls, identifier: str, user: Any = _UNSET
    ) -> None:
        """Async :meth:`_clear_attempts`."""
        target = cls._find_user_sync(identifier) if user is _UNSET else user
        if target is not None:
            target.failed_attempts = 0
            target.last_failed_at = None
            if user is _UNSET:
                await target.save()
        _MEMORY_ATTEMPTS.pop(cls._attempts_key(identifier), None)

    @classmethod
    def _is_locked_out(cls, identifier: str, user: Any = _UNSET) -> bool:
        if cls.max_attempts <= 0:
            return False
        target = cls._find_user_sync(identifier) if user is _UNSET else user
        if target is not None:
            return cls._lockout_active(
                int(target.failed_attempts or 0), target.last_failed_at
            )
        count, last = _MEMORY_ATTEMPTS.get(cls._attempts_key(identifier), (0, None))
        return cls._lockout_active(count, last)

    @classmethod
    async def _is_locked_out_async(
        cls, identifier: str, user: Any = _UNSET
    ) -> bool:
        """Async :meth:`_is_locked_out`."""
        if cls.max_attempts <= 0:
            return False
        target = cls._find_user_sync(identifier) if user is _UNSET else user
        if target is None and user is _UNSET:
            target = await cls._find_user_async(identifier)
        if target is not None:
            return cls._lockout_active(
                int(target.failed_attempts or 0), target.last_failed_at
            )
        count, last = _MEMORY_ATTEMPTS.get(cls._attempts_key(identifier), (0, None))
        return cls._lockout_active(count, last)

    @classmethod
    def _find_user_sync(cls, identifier: str) -> Optional[UserBuiltin]:
        """Look up a user by username or email (sync)."""
        if not identifier or not isinstance(identifier, str):
            return None
        user = cls._user_class.objects.filter_sync(username=identifier).first_sync()
        if user is None:
            user = cls._user_class.objects.filter_sync(email=identifier).first_sync()
        return user

    @classmethod
    async def _find_user_async(cls, identifier: str) -> Optional[UserBuiltin]:
        """Look up a user by username or email (async)."""
        if not identifier or not isinstance(identifier, str):
            return None
        user = await cls._user_class.objects.filter(username=identifier).first()
        if user is None:
            user = await cls._user_class.objects.filter(email=identifier).first()
        return user

    @classmethod
    def _check_credentials(
        cls, user: Optional[UserBuiltin], password: str
    ) -> UserBuiltin:
        """Validate credentials for an already-loaded ``user``.

        A missing user still pays for an Argon2 verification so the response
        time does not reveal whether the account exists.
        """
        if user is None:
            security.dummy_verify()
            raise AuthenticationError("Invalid credentials")
        if not user.verify_password(password):
            raise AuthenticationError("Invalid credentials")
        if not user.is_active:
            raise AuthenticationError("Invalid credentials")
        return user

    @classmethod
    async def _check_credentials_async(
        cls, user: Optional[UserBuiltin], password: str
    ) -> UserBuiltin:
        return cls._check_credentials(user, password)

    # ------------------------------------------------------------------ #
    # Registration
    # ------------------------------------------------------------------ #

    @classmethod
    def _validate_registration(
        cls, username: str, email: str, password: str
    ) -> None:
        if not username or not isinstance(username, str):
            raise ValueError("username is required")
        if not email or not isinstance(email, str):
            raise ValueError("email is required")
        if not password or not isinstance(password, str):
            raise ValueError("password is required")

    @classmethod
    def register_user(
        cls,
        username: str,
        email: str,
        password: str,
        is_admin: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "tuple":
        """Register a user (sync).

        Returns:
            ``(user, True)`` on success, or ``(None, False)`` when the
            username or email is already taken. The conflicting account is
            never returned; 0.1.x did, which handed the caller another
            user's password hash, salt, TOTP secret, and login token.
        """
        cls._validate_registration(username, email, password)

        existing = cls._user_class.objects.filter_sync(username=username).first_sync()
        if existing is None:
            existing = cls._user_class.objects.filter_sync(email=email).first_sync()
        if existing is not None:
            SecurityEvent.log_event(
                event_type="user_registered",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "username or email already registered"},
            )
            return None, False

        try:
            user = cls._user_class.create_user(
                username=username,
                email=email,
                password=password,
                is_admin=is_admin,
                metadata=metadata,
            )
        except Exception as exc:
            # A concurrent registration can slip between the check above and
            # the write. The unique index is the real guard, so translate the
            # driver's constraint error into the same (None, False) result.
            if _is_unique_violation(exc):
                return None, False
            raise

        SecurityEvent.log_event(
            event_type="user_registered",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email},
        )
        return user, True

    @classmethod
    async def register_user_async(
        cls,
        username: str,
        email: str,
        password: str,
        is_admin: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "tuple":
        """Register a user (async). See :meth:`register_user`."""
        cls._validate_registration(username, email, password)

        existing = await cls._user_class.objects.filter(username=username).first()
        if existing is None:
            existing = await cls._user_class.objects.filter(email=email).first()
        if existing is not None:
            await SecurityEvent.log_event_async(
                event_type="user_registered",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "username or email already registered"},
            )
            return None, False

        try:
            user = await cls._user_class.create_user_async(
                username=username,
                email=email,
                password=password,
                is_admin=is_admin,
                metadata=metadata,
            )
        except Exception as exc:
            if _is_unique_violation(exc):
                return None, False
            raise

        await SecurityEvent.log_event_async(
            event_type="user_registered",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email},
        )
        return user, True

    # ------------------------------------------------------------------ #
    # Password authentication
    # ------------------------------------------------------------------ #

    @classmethod
    def authenticate(
        cls,
        username_or_email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Authenticate with a username or email and password (sync).

        Raises:
            LockoutError: too many recent failures for this identifier.
            AuthenticationError: invalid credentials.
        """
        # One lookup serves both the lockout check and the credential check.
        user = cls._find_user_sync(username_or_email)
        if cls._is_locked_out(username_or_email, user):
            SecurityEvent.log_event(
                event_type="account_locked",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"identifier_fp": cls._lockout_key(username_or_email)},
            )
            raise LockoutError("Too many failed attempts; try again later")

        try:
            authenticated = cls._check_credentials(user, password or "")
        except AuthenticationError:
            cls._bump_attempts(username_or_email, user)
            SecurityEvent.log_event(
                event_type="user_unauthenticated",
                user_id=user.id if user else None,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "identifier_fp": cls._lockout_key(username_or_email),
                    "reason": "Invalid credentials",
                },
            )
            raise

        # Opportunistically re-hash a legacy PBKDF2 hash on a successful
        # login, the only moment the plaintext password is available.
        if user is not None and user.upgrade_password_hash_with(password or ""):
            user.save_sync()

        cls._clear_attempts(username_or_email, authenticated)
        authenticated.last_login = _utcnow()
        authenticated.save_sync()

        SecurityEvent.log_event(
            event_type="user_authenticated",
            user_id=authenticated.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": authenticated.username},
        )
        return authenticated

    @classmethod
    async def authenticate_async(
        cls,
        username_or_email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Authenticate with a username or email and password (async)."""
        # One lookup serves both the lockout check and the credential check.
        user = await cls._find_user_async(username_or_email)
        if await cls._is_locked_out_async(username_or_email, user):
            await SecurityEvent.log_event_async(
                event_type="account_locked",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"identifier_fp": cls._lockout_key(username_or_email)},
            )
            raise LockoutError("Too many failed attempts; try again later")

        try:
            authenticated = await cls._check_credentials_async(user, password or "")
        except AuthenticationError:
            await cls._bump_attempts_async(username_or_email, user)
            await SecurityEvent.log_event_async(
                event_type="user_unauthenticated",
                user_id=user.id if user else None,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "identifier_fp": cls._lockout_key(username_or_email),
                    "reason": "Invalid credentials",
                },
            )
            raise

        if user is not None and user.upgrade_password_hash_with(password or ""):
            await user.save()

        await cls._clear_attempts_async(username_or_email, authenticated)
        authenticated.last_login = _utcnow()
        await authenticated.save()

        await SecurityEvent.log_event_async(
            event_type="user_authenticated",
            user_id=authenticated.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": authenticated.username},
        )
        return authenticated

    # ------------------------------------------------------------------ #
    # API key authentication
    # ------------------------------------------------------------------ #

    @classmethod
    def authenticate_with_api_key(
        cls,
        api_key: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Authenticate with an API key (sync).

        Args:
            api_key: The bare UUID4 key as returned at creation time.

        Raises:
            AuthenticationError: unknown, revoked, or expired key.
        """
        key = APIKey.verify_key(api_key, app_secret=cls.get_app_secret())
        if key is None:
            SecurityEvent.log_event(
                event_type="api_key_authentication_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "key_fp": security.fingerprint(api_key),
                    "reason": "Unknown, revoked, or expired API key",
                },
            )
            raise AuthenticationError("Invalid API key")

        user = cls._user_class.objects.get_sync(id=key.user, allow_none=True)
        if user is None or not user.is_active:
            SecurityEvent.log_event(
                event_type="api_key_authentication_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "key_fp": security.fingerprint(api_key),
                    "reason": "Key owner missing or inactive",
                },
            )
            raise AuthenticationError("Invalid API key")

        SecurityEvent.log_event(
            event_type="api_key_authentication_succeeded",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "api_key_id": key.key_id},
        )
        return user

    @classmethod
    async def authenticate_with_api_key_async(
        cls,
        api_key: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Authenticate with an API key (async). See the sync variant."""
        key = await APIKey.verify_key_async(
            api_key, app_secret=cls.get_app_secret()
        )
        if key is None:
            await SecurityEvent.log_event_async(
                event_type="api_key_authentication_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "key_fp": security.fingerprint(api_key),
                    "reason": "Unknown, revoked, or expired API key",
                },
            )
            raise AuthenticationError("Invalid API key")

        user = await cls._user_class.objects.get(id=key.user, allow_none=True)
        if user is None or not user.is_active:
            await SecurityEvent.log_event_async(
                event_type="api_key_authentication_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "key_fp": security.fingerprint(api_key),
                    "reason": "Key owner missing or inactive",
                },
            )
            raise AuthenticationError("Invalid API key")

        await SecurityEvent.log_event_async(
            event_type="api_key_authentication_succeeded",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "api_key_id": key.key_id},
        )
        return user

    # ------------------------------------------------------------------ #
    # API key management
    # ------------------------------------------------------------------ #

    @classmethod
    def create_api_key(
        cls,
        user: UserBuiltin,
        name: str,
        expires_in_days: int = 365,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create an API key for ``user`` (sync).

        The returned dict has a ``key`` (public fields) and ``api_key``
        (plaintext, shown once).
        """
        result = user.create_api_key(
            name=name,
            expires_in_days=expires_in_days,
            scopes=scopes,
            metadata=metadata,
        )
        SecurityEvent.log_event(
            event_type="api_key_created",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "api_key_id": result["key"]["key_id"],
                "api_key_name": name,
            },
        )
        return result

    @classmethod
    async def create_api_key_async(
        cls,
        user: UserBuiltin,
        name: str,
        expires_in_days: int = 365,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create an API key for ``user`` (async)."""
        result = await user.create_api_key_async(
            name=name,
            expires_in_days=expires_in_days,
            scopes=scopes,
            metadata=metadata,
        )
        await SecurityEvent.log_event_async(
            event_type="api_key_created",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "api_key_id": result["key"]["key_id"],
                "api_key_name": name,
            },
        )
        return result

    @classmethod
    def revoke_api_key(
        cls,
        user: UserBuiltin,
        key_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Revoke one of ``user``'s keys (sync)."""
        result = user.revoke_api_key(key_id)
        if result:
            SecurityEvent.log_event(
                event_type="api_key_revoked",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username, "api_key_id": key_id},
            )
        return result

    @classmethod
    async def revoke_api_key_async(
        cls,
        user: UserBuiltin,
        key_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Revoke one of ``user``'s keys (async)."""
        result = await user.revoke_api_key_async(key_id)
        if result:
            await SecurityEvent.log_event_async(
                event_type="api_key_revoked",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username, "api_key_id": key_id},
            )
        return result

    @classmethod
    def refresh_api_key(
        cls,
        api_key: APIKey,
        expires_in_days: int = 365,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> APIKey:
        """Extend a key's expiry (sync)."""
        old_expires_at = api_key.expires_at
        api_key.refresh(expires_in_days)
        SecurityEvent.log_event(
            event_type="api_key_refreshed",
            user_id=api_key.user,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "api_key_id": api_key.key_id,
                "old_expires_at": old_expires_at.isoformat() if old_expires_at else None,
                "new_expires_at": api_key.expires_at.isoformat()
                if api_key.expires_at
                else None,
            },
        )
        return api_key

    @classmethod
    async def refresh_api_key_async(
        cls,
        api_key: APIKey,
        expires_in_days: int = 365,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> APIKey:
        """Extend a key's expiry (async)."""
        old_expires_at = api_key.expires_at
        await api_key.refresh_async(expires_in_days)
        await SecurityEvent.log_event_async(
            event_type="api_key_refreshed",
            user_id=api_key.user,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "api_key_id": api_key.key_id,
                "old_expires_at": old_expires_at.isoformat() if old_expires_at else None,
                "new_expires_at": api_key.expires_at.isoformat()
                if api_key.expires_at
                else None,
            },
        )
        return api_key

    @staticmethod
    def get_api_key(
        key_id: str, dereference: bool = True
    ) -> Optional[APIKey]:
        """Fetch a key by its public ``key_id`` (sync)."""
        return APIKey.objects.get_sync(
            key_id=key_id, dereference=dereference, allow_none=True
        )

    @staticmethod
    async def get_api_key_async(
        key_id: str, dereference: bool = True
    ) -> Optional[APIKey]:
        """Fetch a key by its public ``key_id`` (async)."""
        return await APIKey.objects.get(
            key_id=key_id, dereference=dereference, allow_none=True
        )

    @staticmethod
    def list_api_keys(user: UserBuiltin) -> List[APIKey]:
        """All of ``user``'s keys (sync)."""
        return user.get_api_keys()

    @staticmethod
    async def list_api_keys_async(user: UserBuiltin) -> List[APIKey]:
        """All of ``user``'s keys (async)."""
        return await user.get_api_keys_async()

    @staticmethod
    def list_active_api_keys(user: UserBuiltin) -> List[APIKey]:
        """Keys of ``user`` that still authenticate (sync)."""
        return user.get_active_api_keys()

    @staticmethod
    async def list_active_api_keys_async(user: UserBuiltin) -> List[APIKey]:
        """Keys of ``user`` that still authenticate (async)."""
        return await user.get_active_api_keys_async()

    # ------------------------------------------------------------------ #
    # User lookup and management
    # ------------------------------------------------------------------ #

    @classmethod
    def get_user_by_id(cls, user_id: str) -> Optional[UserBuiltin]:
        """Fetch a user by record id (sync)."""
        return cls._user_class.objects.get_sync(id=user_id, allow_none=True)

    @classmethod
    async def get_user_by_id_async(cls, user_id: str) -> Optional[UserBuiltin]:
        """Fetch a user by record id (async)."""
        return await cls._user_class.objects.get(id=user_id, allow_none=True)

    @classmethod
    def get_user_by_username(cls, username: str) -> Optional[UserBuiltin]:
        """Fetch a user by username (sync)."""
        return cls._user_class.objects.get_sync(
            username=username, allow_none=True
        )

    @classmethod
    async def get_user_by_username_async(cls, username: str) -> Optional[UserBuiltin]:
        """Fetch a user by username (async)."""
        return await cls._user_class.objects.get(username=username, allow_none=True)

    @classmethod
    def get_user_by_email(cls, email: str) -> Optional[UserBuiltin]:
        """Fetch a user by email (sync)."""
        return cls._user_class.objects.get_sync(email=email, allow_none=True)

    @classmethod
    async def get_user_by_email_async(cls, email: str) -> Optional[UserBuiltin]:
        """Fetch a user by email (async)."""
        return await cls._user_class.objects.get(email=email, allow_none=True)

    @classmethod
    def _count_users_sync(cls) -> int:
        """Total number of user records (sync).

        ``QuerySet.count_sync()`` is not usable here: it runs
        ``SELECT count() FROM users`` without ``GROUP ALL``, which returns one
        row per record, and surrealengine reads only the first — so three
        users counted as one. ``GROUP ALL`` collapses to a single row.
        """
        connection = get_active_connection(async_mode=False)
        table = cls._user_class._get_collection_name()
        rows = connection.query(f"SELECT count() FROM {table} GROUP ALL")
        if not rows or not rows[0]:
            return 0
        row = rows[0][0] if isinstance(rows[0], list) else rows[0]
        if not isinstance(row, dict):
            return 0
        for value in row.values():
            if isinstance(value, (int, float)):
                return int(value)
        return 0

    @classmethod
    async def _count_users_async(cls) -> int:
        """Total number of user records (async). See :meth:`_count_users_sync`."""
        connection = get_active_connection(async_mode=True)
        table = cls._user_class._get_collection_name()
        rows = await connection.query(f"SELECT count() FROM {table} GROUP ALL")
        if not rows or not rows[0]:
            return 0
        row = rows[0][0] if isinstance(rows[0], list) else rows[0]
        if not isinstance(row, dict):
            return 0
        for value in row.values():
            if isinstance(value, (int, float)):
                return int(value)
        return 0

    @classmethod
    def list_users(
        cls, page_number: int = 1, page_size: int = 100
    ) -> Dict[str, Any]:
        """Paginated user list (sync).

        The ``size`` key is retained for 0.1.x callers.
        """
        result = cls._user_class.objects.filter_sync().paginate_sync(
            page_number, page_size
        )
        total = cls._count_users_sync()
        per_page = result.per_page
        return {
            "items": result.items,
            "total": total,
            "page": result.page,
            "size": per_page,
            "per_page": per_page,
            "pages": max(1, -(-total // per_page)) if per_page else 0,
        }

    @classmethod
    async def list_users_async(
        cls, page_number: int = 1, page_size: int = 100
    ) -> Dict[str, Any]:
        """Paginated user list (async)."""
        result = await cls._user_class.objects.filter().paginate(
            page_number, page_size
        )
        total = await cls._count_users_async()
        per_page = result.per_page
        return {
            "items": result.items,
            "total": total,
            "page": result.page,
            "size": per_page,
            "per_page": per_page,
            "pages": max(1, -(-total // per_page)) if per_page else 0,
        }

    #: Fields that :meth:`update_user` refuses to set. Each one either grants
    #: privilege or is a credential; setting them from request data is how
    #: 0.1.x allowed privilege escalation and hash replacement.
    PROTECTED_FIELDS = frozenset(
        {
            "id",
            "password_hash",
            "salt",
            "totp_secret",
            "tf_recovery_codes",
            "tf_last_totp_step",
            "login_token",
            "login_token_expires_at",
            "confirmation_token_jti",
            "confirmation_token_expires_at",
            "failed_attempts",
            "last_failed_at",
            "is_admin",
            "created_at",
        }
    )

    @classmethod
    def update_user(
        cls,
        user: UserBuiltin,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs: Any,
    ) -> UserBuiltin:
        """Update user attributes (sync).

        ``password`` is handled through :meth:`UserBuiltin.update_password`.
        Attributes in :attr:`PROTECTED_FIELDS` are rejected with
        :class:`PermissionDenied`; use the dedicated methods for those.
        """
        cls._reject_protected(kwargs)

        password = kwargs.pop("password", None)
        if password is not None:
            user.update_password(password)

        updated_fields: List[str] = []
        for key, value in kwargs.items():
            if key not in ("ip_address", "user_agent") and hasattr(user, key):
                setattr(user, key, value)
                updated_fields.append(key)

        if password is not None:
            updated_fields.append("password")
        user.updated_at = _utcnow()
        user.save_sync()

        SecurityEvent.log_event(
            event_type="user_updated",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                # Field names only: the previous implementation logged values.
                "updated_fields": updated_fields,
            },
        )
        if password is not None:
            SecurityEvent.log_event(
                event_type="password_changed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username},
            )
        return user

    @classmethod
    async def update_user_async(
        cls,
        user: UserBuiltin,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs: Any,
    ) -> UserBuiltin:
        """Update user attributes (async). See :meth:`update_user`."""
        cls._reject_protected(kwargs)

        password = kwargs.pop("password", None)
        if password is not None:
            await user.update_password_async(password)

        updated_fields: List[str] = []
        for key, value in kwargs.items():
            if key not in ("ip_address", "user_agent") and hasattr(user, key):
                setattr(user, key, value)
                updated_fields.append(key)

        if password is not None:
            updated_fields.append("password")
        user.updated_at = _utcnow()
        await user.save()

        await SecurityEvent.log_event_async(
            event_type="user_updated",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "updated_fields": updated_fields},
        )
        if password is not None:
            await SecurityEvent.log_event_async(
                event_type="password_changed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username},
            )
        return user

    @staticmethod
    def _reject_protected(kwargs: Dict[str, Any]) -> None:
        offending = sorted(set(kwargs) & SurrealEngineAuth.PROTECTED_FIELDS)
        if offending:
            raise PermissionDenied(
                "cannot set protected field(s): " + ", ".join(offending)
            )

    @classmethod
    def change_password(
        cls,
        user: UserBuiltin,
        new_password: str,
        current_password: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Set a new password for ``user`` and revoke what the old one had (sync).

        This is the supported way to change a password. 0.1.x had no
        service-level entry point for it, so callers reached for
        ``user.set_password(...)`` directly, which hashed the new password
        and left every session and API key the old password had opened
        alive.

        When ``current_password`` is given it is verified first, so a caller
        that has not already established the caller's identity cannot rotate
        the credential. Callers that have already authenticated the user (an
        admin, or a session holding the old password) may omit it.

        Changing the password revokes the account's API keys and its
        outstanding passwordless-login and email-2FA material. A password
        that leaks should not leave the things it unlocked usable, and a
        rotated password is the usual response to a suspected compromise.

        Raises:
            AuthenticationError: ``current_password`` was supplied and is wrong.
            ValueError: ``new_password`` is empty.
        """
        cls._verify_current_password(user, current_password)

        revoked = cls._revoke_on_password_change_sync(user, ip_address, user_agent)

        user.set_password(new_password)
        # A password change is a successful authentication; the failure
        # counter that would otherwise lock the account out is cleared.
        cls._clear_attempts(user.username, user)
        user.last_login = _utcnow()
        user.save_sync()

        SecurityEvent.log_event(
            event_type="password_changed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "revoked_api_keys": revoked,
            },
        )
        return user

    @classmethod
    async def change_password_async(
        cls,
        user: UserBuiltin,
        new_password: str,
        current_password: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Set a new password for ``user`` and revoke what the old one had.

        Async counterpart of :meth:`change_password`, with the same
        guarantees.
        """
        cls._verify_current_password(user, current_password)

        revoked = await cls._revoke_on_password_change_async(
            user, ip_address, user_agent
        )

        await user.set_password_async(new_password)
        await cls._clear_attempts_async(user.username, user)
        user.last_login = _utcnow()
        await user.save()

        await SecurityEvent.log_event_async(
            event_type="password_changed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "revoked_api_keys": revoked,
            },
        )
        return user

    @classmethod
    def _verify_current_password(
        cls, user: UserBuiltin, current_password: Optional[str]
    ) -> None:
        """Check ``current_password`` against the stored hash, if one was given."""
        if current_password is None:
            return
        if not user.verify_password(current_password):
            raise AuthenticationError("current password is incorrect")

    @classmethod
    def _revoke_on_password_change_sync(
        cls,
        user: UserBuiltin,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> List[str]:
        """Revoke API keys and outstanding tokens after a password change."""
        revoked: List[str] = []
        for key in user.get_active_api_keys():
            key.revoke()
            revoked.append(key.key_id)
            SecurityEvent.log_event(
                event_type="api_key_revoked",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "api_key_id": key.key_id,
                    "reason": "Password changed",
                },
            )
        _clear_outstanding_tokens(user)
        return revoked

    @classmethod
    async def _revoke_on_password_change_async(
        cls,
        user: UserBuiltin,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> List[str]:
        """Revoke API keys and outstanding tokens after a password change."""
        revoked: List[str] = []
        for key in await user.get_active_api_keys_async():
            await key.revoke_async()
            revoked.append(key.key_id)
            await SecurityEvent.log_event_async(
                event_type="api_key_revoked",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "api_key_id": key.key_id,
                    "reason": "Password changed",
                },
            )
        _clear_outstanding_tokens(user)
        return revoked

    @classmethod
    def deactivate_user(
        cls,
        user: UserBuiltin,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Deactivate an account and revoke all of its keys (sync).

        Keys are revoked first: 0.1.x saved the deactivation and then revoked
        keys, so a failure in between left live keys on a disabled account.
        """
        revoked: List[str] = []
        for key in user.get_active_api_keys():
            key.revoke()
            revoked.append(key.key_id)
            SecurityEvent.log_event(
                event_type="api_key_revoked",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "api_key_id": key.key_id,
                    "reason": "User account deactivated",
                },
            )

        user.is_active = False
        user.updated_at = _utcnow()
        user.save_sync()

        SecurityEvent.log_event(
            event_type="user_deactivated",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "email": user.email,
                "revoked_api_keys": revoked,
            },
        )
        return user

    @classmethod
    def activate_user(
        cls,
        user: UserBuiltin,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Reactivate an account (sync)."""
        user.is_active = True
        user.updated_at = _utcnow()
        user.save_sync()
        SecurityEvent.log_event(
            event_type="user_activated",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email},
        )
        return user

    # ------------------------------------------------------------------ #
    # Email confirmation
    # ------------------------------------------------------------------ #

    @classmethod
    def send_confirmation_email(
        cls,
        user: User,
        base_url: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Email a signed confirmation link (sync).

        Issuing a new token invalidates any previously sent link.
        """
        token = user.generate_confirmation_token()
        link = f"{base_url.rstrip('/')}/confirm-email/{token}"
        result = cls.get_email_service().send_confirmation_email_sync(user, link)
        SecurityEvent.log_event(
            event_type="confirmation_email_sent" if result
            else "confirmation_email_send_failed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email},
        )
        return result

    @classmethod
    def confirm_email(
        cls,
        token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> User:
        """Redeem a confirmation token (sync).

        Raises:
            AuthenticationError: invalid, expired, or already-used token.
        """
        user = User.verify_confirmation_token(token)
        if user is None:
            SecurityEvent.log_event(
                event_type="email_confirmation_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Invalid, expired, or already-used token"},
            )
            raise AuthenticationError("Invalid confirmation token")

        SecurityEvent.log_event(
            event_type="email_confirmed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username},
        )
        return user

    # ------------------------------------------------------------------ #
    # Two-factor authentication
    # ------------------------------------------------------------------ #

    @classmethod
    def setup_two_factor(
        cls,
        user: User,
        method: str,
        phone_number: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enrol a 2FA method (sync).

        Supports ``authenticator`` and ``email``. ``sms`` is rejected rather
        than silently accepted, which 0.1.x did while having no delivery path
        at all.
        """
        previous = user.tf_primary_method
        result = user.setup_two_factor(method, phone_number)
        SecurityEvent.log_event(
            event_type="two_factor_enabled",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "previous_method": previous},
        )
        return result

    @classmethod
    def verify_two_factor(
        cls,
        user: User,
        code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Verify a 2FA code or recovery code (sync). Single-use."""
        ok = user.verify_two_factor(code)
        SecurityEvent.log_event(
            event_type="two_factor_verified" if ok
            else "two_factor_verification_failed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "method": user.tf_primary_method},
        )
        return ok

    @classmethod
    def disable_two_factor(
        cls,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """Disable 2FA and discard its secrets (sync)."""
        user.disable_two_factor()
        SecurityEvent.log_event(
            event_type="two_factor_disabled",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username},
        )

    @classmethod
    def _issue_email_code_or_log(
        cls,
        user: User,
        *,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> Optional[str]:
        """Mint an emailed 2FA code, or log why we could not.

        Returns the plaintext for the caller to email, or None. Persisting
        happens in the caller so the async path can await its own save.
        """
        if user.tf_primary_method != "email":
            SecurityEvent.log_event(
                event_type="two_factor_code_send_failed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Email 2FA not configured"},
            )
            return None
        try:
            return user.issue_email_two_factor_code()
        except ValueError as exc:
            SecurityEvent.log_event(
                event_type="two_factor_code_send_failed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": str(exc)},
            )
            return None

    @classmethod
    async def _issue_email_code_or_log_async(
        cls,
        user: User,
        *,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> Optional[str]:
        """Async counterpart of :meth:`_issue_email_code_or_log`.

        Minting the code is pure and shared; the audit write is not. An async
        application has an async default connection, so the sync
        ``log_event`` here would either reach for a sync connection that does
        not exist or block the loop writing to the async one.
        """
        if user.tf_primary_method != "email":
            await SecurityEvent.log_event_async(
                event_type="two_factor_code_send_failed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Email 2FA not configured"},
            )
            return None
        try:
            return user.issue_email_two_factor_code()
        except ValueError as exc:
            await SecurityEvent.log_event_async(
                event_type="two_factor_code_send_failed",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": str(exc)},
            )
            return None

    @classmethod
    def _log_email_code_sent(
        cls,
        user: User,
        sent: bool,
        *,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> None:
        SecurityEvent.log_event(
            event_type="two_factor_code_sent" if sent
            else "two_factor_code_send_failed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "method": "email",
                "email": user.email,
                "expires_in": user.email_code_expires_in,
            },
        )

    @classmethod
    async def _log_email_code_sent_async(
        cls,
        user: User,
        sent: bool,
        *,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> None:
        """Async counterpart of :meth:`_log_email_code_sent`."""
        await SecurityEvent.log_event_async(
            event_type="two_factor_code_sent" if sent
            else "two_factor_code_send_failed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "method": "email",
                "email": user.email,
                "expires_in": user.email_code_expires_in,
            },
        )

    @classmethod
    def send_two_factor_code(
        cls,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Email a fresh one-time 2FA code (sync).

        Returns True when the message was accepted. The code is not returned
        to the caller; 0.1.x returned it, so any endpoint that surfaced the
        return value handed out the second factor.

        The code is single-use and valid for
        ``UserBuiltin.email_code_expires_in`` seconds (five by default). 0.1.x
        emailed a rotating TOTP instead, which expires after 30 seconds --
        shorter than most mail delivery, so the code was usually dead on
        arrival.
        """
        code = cls._issue_email_code_or_log(
            user, ip_address=ip_address, user_agent=user_agent
        )
        if not code:
            return False

        # Persist before sending: if the process dies mid-send the code is
        # already dead, rather than live in memory and unverifiable.
        user.save_sync()
        sent = bool(
            cls.get_email_service().send_two_factor_code_sync(
                user, code, expires_in=user.email_code_expires_in
            )
        )
        cls._log_email_code_sent(
            user, sent, ip_address=ip_address, user_agent=user_agent
        )
        return sent

    @classmethod
    async def send_two_factor_code_async(
        cls,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Email a fresh one-time 2FA code (async). See
        :meth:`send_two_factor_code`."""
        code = await cls._issue_email_code_or_log_async(
            user, ip_address=ip_address, user_agent=user_agent
        )
        if not code:
            return False

        await user.save()
        sent = bool(
            await cls.get_email_service().send_two_factor_code(
                user, code, expires_in=user.email_code_expires_in
            )
        )
        await cls._log_email_code_sent_async(
            user, sent, ip_address=ip_address, user_agent=user_agent
        )
        return sent

    @staticmethod
    def generate_qrcode(user: User) -> Optional[str]:
        """SVG data URL for the user's TOTP secret (sync)."""
        if not user.totp_secret:
            return None
        return TOTPManager.generate_qrcode(user.totp_secret, user.username)

    @classmethod
    def authenticate_with_two_factor(
        cls,
        username_or_email: str,
        password: str,
        code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserBuiltin:
        """Password plus 2FA (sync).

        Raises:
            AuthenticationError: bad password, or 2FA is enabled and the code
                is wrong.
        """
        user = cls.authenticate(username_or_email, password, ip_address, user_agent)

        if not (user.totp_secret and user.tf_primary_method):
            return user

        if user.verify_two_factor(code):
            SecurityEvent.log_event(
                event_type="two_factor_authentication_succeeded",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username, "method": user.tf_primary_method},
            )
            return user

        SecurityEvent.log_event(
            event_type="two_factor_authentication_failed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "method": user.tf_primary_method,
                "reason": "Invalid code",
            },
        )
        raise AuthenticationError("Invalid two-factor code")

    # ------------------------------------------------------------------ #
    # Passwordless login
    # ------------------------------------------------------------------ #

    @classmethod
    def send_passwordless_login_link(
        cls,
        user: User,
        base_url: str,
        expires_in: int = 3600,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Email a single-use login link (sync).

        Sending a new link invalidates the previous token.
        """
        token = user.generate_login_token(expires_in)
        link = f"{base_url.rstrip('/')}/login/{token}"
        result = cls.get_email_service().send_passwordless_login_link_sync(
            user, link
        )
        SecurityEvent.log_event(
            event_type="passwordless_login_link_sent" if result
            else "passwordless_login_link_send_failed",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email},
        )
        return result

    @classmethod
    def authenticate_with_login_token(
        cls,
        token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> User:
        """Redeem a passwordless login token (sync).

        Raises:
            AuthenticationError: invalid, expired, or already-used token.
        """
        user = User.verify_login_token(token)
        if user is None:
            SecurityEvent.log_event(
                event_type="passwordless_login_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Invalid or expired token"},
            )
            raise AuthenticationError("Invalid or expired login token")

        SecurityEvent.log_event(
            event_type="passwordless_login_succeeded",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email},
        )
        return user


#: Failure counters for identifiers with no user record, which have nowhere
#: to persist state. Process-local, so it does not survive a restart and does
#: not apply to a multi-process deployment. Swap in a shared store by
#: overriding :meth:`SurrealEngineAuth._bump_attempts`.
#: Failure counters for identifiers with no user record, keyed by fingerprint.
#: Values are ``(count, last_failure_at)``. Process-local by necessity: there
#: is no record to hold the state, so a restart resets it and a multi-process
#: deployment counts per process rather than globally.
_MEMORY_ATTEMPTS: Dict[str, Tuple[int, Optional[datetime]]] = {}


def _is_unique_violation(exc: Exception) -> bool:
    """True when ``exc`` is SurrealDB's unique-index violation.

    Registering a user races: two requests can both pass the "does it exist"
    check, and only the database index keeps them honest. The SDK surfaces
    this as a ``SurrealError`` whose message names the index.
    """
    message = str(exc).lower()
    if "already exists" in message:
        return True
    return "index" in message and "already contains" in message
