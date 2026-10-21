"""
Document models for surrealengine-auth.

Targets surrealengine 2.0.0. The notable differences from 0.1.x:

* ``APIKey.user`` is a ``ReferenceField`` pointing at the user record. The old
  ``RelationField('user_keys')`` edge no longer exists; the reference is both
  simpler to query and filterable, which is what the service layer needs.
  Keys are reached with :meth:`UserBuiltin.get_api_keys`.
* Passwords are Argon2id via :mod:`surrealengine_auth.security`. The ``salt``
  column is retained solely so legacy PBKDF2 hashes stay verifiable.
* API keys store a SHA-256 digest, not the key itself.
* Confirmation tokens are HMAC-signed and expire; single-use enforcement lives
  in :attr:`UserBuiltin.confirmation_token_jti`.
* Recovery codes are stored hashed and compared in constant time.
* TOTP remembers the last accepted time step, so a code cannot be replayed
  inside its validity window.

Sync and async variants of each method share the logic in
:mod:`surrealengine_auth.security`; the pairing is deliberate so that both
paths can be kept correct, and the test suite exercises both.
"""

from __future__ import annotations

import io
import base64
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import pyotp
import qrcode
import qrcode.image.svg
from surrealengine.document import Document
from surrealengine.fields import (
    BooleanField,
    ChoiceField,
    DateTimeField,
    DictField,
    EmailField,
    IntField,
    IPAddressField,
    ListField,
    RecordIDField,
    StringField,
)
from surrealengine.exceptions import DoesNotExist

from . import security
from .security import TokenError

__all__ = ["UserBuiltin", "User", "APIKey", "SecurityEvent", "TOTPManager"]

#: TOTP validity window in 30-second steps. 1 accepts the adjacent steps to
#: tolerate clock drift between server and authenticator.
TOTP_VALID_WINDOW = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: Any) -> datetime:
    """Coerce a stored timestamp into a timezone-aware UTC datetime.

    ``DateTimeField`` returns a ``PreciseDatetime``; comparing one against an
    aware ``now()`` raises, which would turn an expired-code check into an
    unhandled error instead of a rejection.
    """
    if not isinstance(value, datetime):
        raise TypeError(f"Expected a datetime, got {type(value)!r}")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class UserBuiltin(Document):
    """Base user model. Inherit from this to add your own fields.

    Fields declared here are the whole persistence contract. ``password_hash``
    holds a self-describing PHC string; ``salt`` is legacy and is only read
    when ``password_hash`` is a bare hex digest.
    """

    username = StringField(required=True, indexed=True, unique=True)
    email = EmailField(required=True, indexed=True, unique=True)
    password_hash = StringField(required=True)
    #: Legacy PBKDF2 salt. Never written by new code paths.
    salt = StringField()

    is_active = BooleanField(default=True)
    is_admin = BooleanField(default=False)
    confirmed_at = DateTimeField()

    # Two-factor authentication
    totp_secret = StringField()
    tf_primary_method = StringField()  # 'email' | 'authenticator'
    tf_phone_number = StringField()
    #: SHA-256 digests of recovery codes, not the codes themselves.
    tf_recovery_codes = ListField(StringField())
    #: Highest TOTP time step already spent, blocking replay within the window.
    tf_last_totp_step = IntField()

    #: The emailed 2FA code, stored as a digest, with the window it is valid
    #: for. Email 2FA is a one-time code with a multi-minute lifetime, not a
    #: TOTP: a 30-second rotating code is unusable over email, where delivery
    #: alone can exceed the window.
    tf_email_code_hash = StringField()
    tf_email_code_expires_at = DateTimeField()
    #: Guesses left against the current emailed code. A six-digit code is only
    #: a million values, so it needs a bound that a short window alone does not
    #: provide.
    tf_email_code_attempts = IntField(default=0)

    #: Seconds an emailed 2FA code stays valid. Override per deployment.
    email_code_expires_in = 300
    #: Wrong codes tolerated before the emailed code is destroyed.
    email_code_max_attempts = 5

    #: Default lifetimes for issued tokens, in seconds. Set these on the class
    #: (or a subclass) to change a deployment's defaults; every call site still
    #: takes an explicit override.
    confirmation_token_expires_in = 86400
    login_token_expires_in = 3600

    # Passwordless authentication
    login_token = StringField()
    login_token_expires_at = DateTimeField()

    # Email confirmation
    #: ``jti`` of the confirmation token currently outstanding, so it can only
    #: be redeemed once and a re-send invalidates the previous link.
    confirmation_token_jti = StringField()
    confirmation_token_expires_at = DateTimeField()

    created_at = DateTimeField(default=_utcnow)
    updated_at = DateTimeField(default=_utcnow)
    last_login = DateTimeField()

    #: Failed sign-in bookkeeping for the lockout. These are typed columns
    #: rather than entries in ``metadata`` because document updates are applied
    #: with MERGE, which can add dict keys but never remove one -- a counter in
    #: a dict could be incremented forever and never reset on success. They are
    #: excluded from ``to_dict()`` (see ``_INTERNAL_FIELDS``).
    failed_attempts = IntField(default=0)
    last_failed_at = DateTimeField()

    metadata = DictField(default=dict)

    #: Never serialised by :meth:`to_dict`. These are credentials or internal
    #: bookkeeping: ``Document.to_dict`` emits every stored field, so returning
    #: one of these objects to a caller would leak the password hash, the TOTP
    #: shared secret and the recovery-code digests.
    _INTERNAL_FIELDS = frozenset(
        {
            "password_hash",
            "salt",
            "totp_secret",
            "tf_recovery_codes",
            "tf_last_totp_step",
            "tf_email_code_hash",
            "tf_email_code_attempts",
            "login_token",
            "confirmation_token_jti",
            "confirmation_token_expires_at",
            "failed_attempts",
            "last_failed_at",
        }
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the user without credentials or internal state."""
        return {
            key: value
            for key, value in super().to_dict().items()
            if key not in self._INTERNAL_FIELDS
        }

    class Meta:
        # The collection name is a placeholder. A concrete subclass supplies
        # its own via Meta, since surrealengine registers one class per
        # collection and would otherwise warn on every subclass.
        collection = "user_builtin"

    # ----------------------------------------------------------------- #
    # Passwords
    # ----------------------------------------------------------------- #

    @classmethod
    def create_user(
        cls,
        username: str,
        email: str,
        password: str,
        is_admin: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UserBuiltin":
        """Create and persist a user with a hashed password."""
        return cls._new_user(
            username, email, password, is_admin, metadata
        ).save_sync()

    @classmethod
    async def create_user_async(
        cls,
        username: str,
        email: str,
        password: str,
        is_admin: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UserBuiltin":
        """Create and persist a user with a hashed password (async)."""
        return await cls._new_user(
            username, email, password, is_admin, metadata
        ).save()

    @classmethod
    def _new_user(
        cls,
        username: str,
        email: str,
        password: str,
        is_admin: bool,
        metadata: Optional[Dict[str, Any]],
    ) -> "UserBuiltin":
        if not password:
            raise ValueError("password must not be empty")
        return cls(
            username=username,
            email=email,
            password_hash=security.hash_password(password),
            is_admin=is_admin,
            metadata=metadata or {},
        )

    def verify_password(self, password: str) -> bool:
        """Check ``password`` against the stored hash, either format."""
        return security.verify_password(password, self.password_hash, self.salt)

    def password_needs_rehash(self) -> bool:
        """True when the stored hash predates the current parameters."""
        return security.password_needs_rehash(self.password_hash)

    def _apply_new_password(self, new_password: str) -> None:
        if not new_password:
            raise ValueError("password must not be empty")
        self.password_hash = security.hash_password(new_password)
        self.salt = None
        self.updated_at = _utcnow()

    def set_password(self, new_password: str) -> None:
        """Replace the user's password without saving (sync).

        Sets the hash on the instance only; the caller decides when to
        persist. This is the 0.1.x ``set_password`` name, restored because
        callers used it to mean "hash it, I will save it". It is the
        counterpart of :meth:`update_password`, which saves for you.

        Prefer :meth:`SurrealEngineAuth.change_password`, which also revokes
        the sessions and API keys the old password had access to.
        """
        self._apply_new_password(new_password)

    async def set_password_async(self, new_password: str) -> None:
        """Replace the user's password without saving (async)."""
        self._apply_new_password(new_password)

    def update_password(self, new_password: str) -> None:
        """Replace the user's password (sync)."""
        self._apply_new_password(new_password)
        self.save_sync()

    async def update_password_async(self, new_password: str) -> None:
        """Replace the user's password (async)."""
        self._apply_new_password(new_password)
        await self.save()

    def upgrade_password_hash_with(self, password: str) -> bool:
        """Re-hash using ``password`` when the stored hash is outdated."""
        if not self.password_needs_rehash():
            return False
        self._apply_new_password(password)
        return True

    # ----------------------------------------------------------------- #
    # API keys
    # ----------------------------------------------------------------- #

    def get_api_keys(self) -> List["APIKey"]:
        """All API keys owned by this user (sync)."""
        return list(APIKey.objects.filter_sync(user=self.id).all_sync())

    async def get_api_keys_async(self) -> List["APIKey"]:
        """All API keys owned by this user (async)."""
        return list(await APIKey.objects.filter(user=self.id).all())

    def get_active_api_keys(self) -> List["APIKey"]:
        """API keys that are neither revoked, disabled, nor expired (sync)."""
        return [key for key in self.get_api_keys() if key.is_usable()]

    async def get_active_api_keys_async(self) -> List["APIKey"]:
        """API keys that are neither revoked, disabled, nor expired (async)."""
        return [key for key in await self.get_api_keys_async() if key.is_usable()]

    def create_api_key(
        self,
        name: str,
        expires_in_days: int = 365,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an API key (sync). The plaintext key is only in the result."""
        return APIKey.create(
            user=self,
            name=name,
            scopes=scopes or ["read"],
            expires_at=_utcnow() + timedelta(days=expires_in_days),
            metadata=metadata or {},
        )

    async def create_api_key_async(
        self,
        name: str,
        expires_in_days: int = 365,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an API key (async). The plaintext key is only in the result."""
        return await APIKey.create_async(
            user=self,
            name=name,
            scopes=scopes or ["read"],
            expires_at=_utcnow() + timedelta(days=expires_in_days),
            metadata=metadata or {},
        )

    def revoke_api_key(self, key_id: Any) -> bool:
        """Revoke one of this user's keys by key id (sync)."""
        key = self._find_own_key_sync(key_id)
        if key is None:
            return False
        key.revoke()
        return True

    async def revoke_api_key_async(self, key_id: Any) -> bool:
        """Revoke one of this user's keys by key id (async)."""
        key = await self._find_own_key_async(key_id)
        if key is None:
            return False
        await key.revoke_async()
        return True

    def _find_own_key_sync(self, key_id: Any) -> Optional["APIKey"]:
        needle = str(key_id)
        for key in self.get_api_keys():
            if str(key.id) == needle or key.key_id == needle:
                return key
        return None

    async def _find_own_key_async(self, key_id: Any) -> Optional["APIKey"]:
        needle = str(key_id)
        for key in await self.get_api_keys_async():
            if str(key.id) == needle or key.key_id == needle:
                return key
        return None


class User(UserBuiltin):
    """Default user model with the two-factor and token helpers.

    Behaviour lives in ``UserBuiltin``; this subclass exists so applications
    that subclass ``UserBuiltin`` themselves do not silently inherit flows
    (email confirmation, passwordless login) they may not want.
    """

    # The collection name is spelled "user", not "users", and that is
    # deliberate.
    #
    # ``Meta`` is not inherited by the metaclass: it reads only the class's own
    # ``Meta`` (``attrs.get("Meta", ...)``, no MRO walk). 0.1.x declared
    # ``collection = "users"`` on ``UserBuiltin`` but left it off ``User``, so
    # the declared name was never used -- ``User`` fell back to its lowercased
    # class name and every user record was written to ``user``. Renaming the
    # table now would leave every existing account unreachable: login would
    # fail closed against an empty table and no password hash would ever be
    # read, let alone upgraded.
    #
    # So: keep "user", and keep this the only concrete class claiming it. The
    # metaclass registers one class per collection name and warns about the
    # rest.
    class Meta:
        collection = "user"

    # ----------------------------------------------------------------- #
    # Two-factor authentication
    # ----------------------------------------------------------------- #

    def _apply_two_factor_setup(
        self, method: str, phone_number: Optional[str]
    ) -> Dict[str, Any]:
        if method not in ("authenticator", "email"):
            raise ValueError(
                f"unsupported 2FA method {method!r}; "
                "expected 'authenticator' or 'email'"
            )
        if phone_number:
            raise ValueError("phone_number is not supported")

        self.tf_primary_method = method
        self.tf_phone_number = None
        # Generate once, store the digests, return the same plaintexts. Two
        # separate calls would hand the user codes that are not on file, so
        # every one of them would be rejected at verification.
        recovery_codes = TOTPManager.generate_recovery_codes()
        self.tf_recovery_codes = [
            security.hash_recovery_code(code) for code in recovery_codes
        ]
        self.tf_last_totp_step = None
        self._clear_email_code()

        if method == "authenticator":
            # A fresh secret on every enrolment: reusing one means a leaked
            # enrolment secret stays valid forever. Only the authenticator
            # method has one; email 2FA issues a code per sign-in instead.
            self.totp_secret = TOTPManager.generate_totp_secret()
            self.updated_at = _utcnow()
            return {
                "secret": self.totp_secret,
                "qrcode": TOTPManager.generate_qrcode(
                    self.totp_secret, self.username
                ),
                # Plaintext codes, returned once so the user can store them.
                "recovery_codes": recovery_codes,
            }

        self.totp_secret = None
        self.updated_at = _utcnow()
        return {"email": self.email, "recovery_codes": recovery_codes}

    def issue_email_two_factor_code(
        self, *, expires_in: Optional[int] = None
    ) -> str:
        """Mint a one-time 2FA code, store its digest, return the plaintext.

        The plaintext is returned so it can be emailed; it is the only time
        the code exists. Issuing a new code invalidates the previous one and
        resets the guess counter, so requesting a second code does not widen
        the search space.
        """
        if self.tf_primary_method != "email":
            raise ValueError("email 2FA is not enabled for this user")
        ttl = self.email_code_expires_in if expires_in is None else int(expires_in)
        if ttl <= 0:
            raise ValueError("expires_in must be positive")
        code = f"{secrets.randbelow(1_000_000):06d}"
        self.tf_email_code_hash = security.hash_email_code(code)
        self.tf_email_code_expires_at = _utcnow() + timedelta(seconds=ttl)
        self.tf_email_code_attempts = 0
        self.updated_at = _utcnow()
        return code

    def _clear_email_code(self) -> None:
        self.tf_email_code_hash = None
        self.tf_email_code_expires_at = None
        self.tf_email_code_attempts = 0

    def _consume_email_code(self, code: str) -> bool:
        """Check a submitted code against the outstanding emailed one."""
        if not self.tf_email_code_hash:
            return False
        if not self.tf_email_code_expires_at or _utcnow() > _as_utc(
            self.tf_email_code_expires_at
        ):
            self._clear_email_code()
            return False
        if (self.tf_email_code_attempts or 0) >= self.email_code_max_attempts:
            self._clear_email_code()
            return False
        if not security.constant_time_equals(
            self.tf_email_code_hash, security.hash_email_code(code)
        ):
            self.tf_email_code_attempts = (self.tf_email_code_attempts or 0) + 1
            if self.tf_email_code_attempts >= self.email_code_max_attempts:
                # Burn the code rather than let guesses continue against it.
                self._clear_email_code()
            self.updated_at = _utcnow()
            return False
        self._clear_email_code()
        self.updated_at = _utcnow()
        return True


    def setup_two_factor(
        self, method: str, phone_number: Optional[str] = None
    ) -> Dict[str, Any]:
        """Enrol a 2FA method (sync). See :meth:`_apply_two_factor_setup`."""
        setup = self._apply_two_factor_setup(method, phone_number)
        self.save_sync()
        return setup

    async def setup_two_factor_async(
        self, method: str, phone_number: Optional[str] = None
    ) -> Dict[str, Any]:
        """Enrol a 2FA method (async)."""
        setup = self._apply_two_factor_setup(method, phone_number)
        await self.save()
        return setup

    def _consume_two_factor(self, code: str) -> bool:
        """Validate a 2FA code or recovery code, applying single-use rules."""
        if not self.tf_primary_method:
            return False
        if not code or not isinstance(code, str):
            return False

        # Recovery codes are checked first and work for either method. A
        # recovery code must not double as an emailed code, so the emailed
        # branch below hashes with a different domain.
        digest = security.hash_recovery_code(code)
        for index, stored in enumerate(self.tf_recovery_codes or []):
            if security.constant_time_equals(stored, digest):
                codes = list(self.tf_recovery_codes)
                codes.pop(index)
                self.tf_recovery_codes = codes
                self.updated_at = _utcnow()
                return "recovery"  # type: ignore[return-value]

        if self.tf_primary_method == "email":
            return self._consume_email_code(code)

        if not self.totp_secret:
            return False
        step = TOTPManager.match_totp_step(self.totp_secret, code)
        if step is not None and (self.tf_last_totp_step or 0) < step:
            self.tf_last_totp_step = step
            self.updated_at = _utcnow()
            return True  # type: ignore[return-value]
        return False

    def verify_two_factor(self, code: str) -> bool:
        """Verify a 2FA code or recovery code (sync). Consumes it on success."""
        result = self._consume_two_factor(code)
        if not result:
            return False
        self.save_sync()
        return True

    async def verify_two_factor_async(self, code: str) -> bool:
        """Verify a 2FA code or recovery code (async). Consumes it on success."""
        result = self._consume_two_factor(code)
        if not result:
            return False
        await self.save()
        return True

    def generate_two_factor_code(self) -> Optional[str]:
        """Return the current TOTP code. Only for tests and E2E flows."""
        if not self.totp_secret:
            return None
        return TOTPManager.generate_totp_code(self.totp_secret)

    def disable_two_factor(self) -> None:
        """Disable 2FA and discard all 2FA secrets (sync)."""
        self._clear_two_factor()
        self.save_sync()

    async def disable_two_factor_async(self) -> None:
        """Disable 2FA and discard all 2FA secrets (async)."""
        self._clear_two_factor()
        await self.save()

    def _clear_two_factor(self) -> None:
        self.totp_secret = None
        self.tf_primary_method = None
        self.tf_phone_number = None
        self.tf_recovery_codes = []
        self.tf_last_totp_step = None
        self._clear_email_code()
        self.updated_at = _utcnow()

    # ----------------------------------------------------------------- #
    # Email confirmation
    # ----------------------------------------------------------------- #

    def issue_confirmation_token(
        self, *, expires_in: Optional[int] = None
    ) -> Tuple[str, str]:
        """Mint a signed confirmation token and record its ``jti``.

        Returns ``(token, jti)``. The caller persists via
        :meth:`_apply_confirmation_token`.
        """
        ttl = (
            self.confirmation_token_expires_in
            if expires_in is None
            else int(expires_in)
        )
        if ttl <= 0:
            raise ValueError("expires_in must be positive")
        token = security.generate_token(
            {
                "uid": str(self.id),
                "email": self.email,
                "purpose": "email_confirmation",
            },
            expires_in=ttl,
        )
        jti = security.verify_token(token)["jti"]
        return token, jti

    def _apply_confirmation_token(
        self, jti: str, expires_in: Optional[int] = None
    ) -> None:
        """Record the outstanding token's ``jti`` and its real expiry.

        The stored deadline used to be a hard-coded day regardless of the
        lifetime the token was actually minted with, so a caller asking for a
        short-lived link still left the user redeemable for 24 hours.
        """
        ttl = (
            self.confirmation_token_expires_in
            if expires_in is None
            else int(expires_in)
        )
        if ttl <= 0:
            raise ValueError("expires_in must be positive")
        self.confirmation_token_jti = jti
        self.confirmation_token_expires_at = _utcnow() + timedelta(seconds=ttl)
        self.updated_at = _utcnow()

    def generate_confirmation_token(
        self, *, expires_in: Optional[int] = None
    ) -> str:
        """Issue and persist a signed confirmation token (sync)."""
        token, jti = self.issue_confirmation_token(expires_in=expires_in)
        self._apply_confirmation_token(jti, expires_in)
        self.save_sync()
        return token

    async def generate_confirmation_token_async(
        self, *, expires_in: Optional[int] = None
    ) -> str:
        """Issue and persist a signed confirmation token (async)."""
        token, jti = self.issue_confirmation_token(expires_in=expires_in)
        self._apply_confirmation_token(jti, expires_in)
        await self.save()
        return token

    @classmethod
    def _check_confirmation_claims(
        cls, token: str, payload: Dict[str, Any], user: "User"
    ) -> bool:
        """Validate a decoded token's claims against the stored user."""
        if payload.get("purpose") != "email_confirmation":
            return False
        if str(payload.get("uid")) != str(user.id):
            return False
        if not security.constant_time_equals(payload.get("email"), user.email):
            return False
        if not user.confirmation_token_jti or not security.constant_time_equals(
            user.confirmation_token_jti, payload.get("jti")
        ):
            return False
        expires = user.confirmation_token_expires_at
        if expires is None or expires < _utcnow():
            return False
        return True

    @classmethod
    def verify_confirmation_token(cls, token: str) -> Optional["User"]:
        """Redeem a confirmation token and mark the email confirmed (sync).

        Returns the user, or None if the token is invalid, expired, or was
        already spent. The token is invalidated by saving, so a leaked link
        cannot be replayed.
        """
        try:
            payload = security.verify_token(token)
        except TokenError:
            return None

        try:
            user = cls.objects.get_sync(id=payload.get("uid"), allow_none=True)
        except (DoesNotExist, ValueError, TypeError):
            return None
        if user is None or not cls._check_confirmation_claims(token, payload, user):
            return None

        user.confirm_email()
        return user

    @classmethod
    async def verify_confirmation_token_async(cls, token: str) -> Optional["User"]:
        """Async twin of :meth:`verify_confirmation_token`."""
        try:
            payload = security.verify_token(token)
        except TokenError:
            return None

        try:
            user = await cls.objects.get(id=payload.get("uid"), allow_none=True)
        except (DoesNotExist, ValueError, TypeError):
            return None
        if user is None or not cls._check_confirmation_claims(token, payload, user):
            return None

        await user.confirm_email_async()
        return user

    def confirm_email(self) -> bool:
        """Mark the email confirmed (sync). False if already confirmed."""
        if self.confirmed_at:
            return False
        self.confirmed_at = _utcnow()
        self.confirmation_token_jti = None
        self.confirmation_token_expires_at = None
        self.updated_at = _utcnow()
        self.save_sync()
        return True

    async def confirm_email_async(self) -> bool:
        """Mark the email confirmed (async). False if already confirmed."""
        if self.confirmed_at:
            return False
        self.confirmed_at = _utcnow()
        self.confirmation_token_jti = None
        self.confirmation_token_expires_at = None
        self.updated_at = _utcnow()
        await self.save()
        return True

    # ----------------------------------------------------------------- #
    # Passwordless login
    # ----------------------------------------------------------------- #

    def _apply_login_token(self, expires_in: Optional[int] = None) -> str:
        """Mint a passwordless login token and record when it stops working.

        Any previously issued token is replaced, so sending a second link
        invalidates the first.
        """
        ttl = (
            self.login_token_expires_in if expires_in is None else int(expires_in)
        )
        if ttl <= 0:
            raise ValueError("expires_in must be positive")
        self.login_token = security.generate_token(
            {"uid": str(self.id), "purpose": "passwordless_login"},
            expires_in=ttl,
        )
        self.login_token_expires_at = _utcnow() + timedelta(seconds=ttl)
        self.updated_at = _utcnow()
        return self.login_token

    def generate_login_token(self, expires_in: Optional[int] = None) -> str:
        """Mint a single-use passwordless login token (sync)."""
        token = self._apply_login_token(expires_in)
        self.save_sync()
        return token

    async def generate_login_token_async(
        self, expires_in: Optional[int] = None
    ) -> str:
        """Mint a single-use passwordless login token (async)."""
        token = self._apply_login_token(expires_in)
        await self.save()
        return token

    @classmethod
    def _resolve_login_token(
        cls, token: str, user: Optional["User"]
    ) -> Optional["User"]:
        if user is None:
            return None
        if not security.constant_time_equals(user.login_token, token):
            return None
        expires = user.login_token_expires_at
        if expires is None or expires < _utcnow():
            return None
        if not user.is_active:
            return None
        return user

    @classmethod
    def verify_login_token(cls, token: str) -> Optional["User"]:
        """Redeem a passwordless login token (sync). Clears it on success."""
        if not token or not isinstance(token, str):
            return None
        try:
            user = cls.objects.filter_sync(login_token=token).first_sync()
            user = cls._resolve_login_token(token, user)
            if user is None:
                return None
            user._consume_login_token()
            return user
        except Exception:  # pragma: no cover - defensive
            from .logger import get_logger

            get_logger().error("Error verifying passwordless login token")
            return None

    @classmethod
    async def verify_login_token_async(cls, token: str) -> Optional["User"]:
        """Redeem a passwordless login token (async). Clears it on success."""
        if not token or not isinstance(token, str):
            return None
        try:
            user = await cls.objects.filter(login_token=token).first()
            user = cls._resolve_login_token(token, user)
            if user is None:
                return None
            user._consume_login_token()
            await user.save()
            return user
        except Exception:  # pragma: no cover - defensive
            from .logger import get_logger

            get_logger().error("Error verifying passwordless login token")
            return None

    def _consume_login_token(self) -> None:
        self.login_token = None
        self.login_token_expires_at = None
        self.last_login = _utcnow()
        self.updated_at = _utcnow()


class APIKey(Document):
    """An API key.

    The key presented by the client is a UUID4 string. Only its SHA-256
    digest is stored, so the table cannot be dumped for usable credentials.
    ``key_id`` remains a public, non-secret identifier for display and
    revocation, matching the 0.1.x field name.
    """

    #: Public, non-secret identifier.
    key_id = StringField(default=lambda: str(uuid.uuid4()), indexed=True, unique=True)
    #: SHA-256 (or HMAC-SHA256) digest of the key. The key itself is never stored.
    key_hash = StringField(indexed=True, unique=True)
    name = StringField(required=True, indexed=True)

    is_active = BooleanField(default=True)

    created_at = DateTimeField(default=_utcnow)
    updated_at = DateTimeField(default=_utcnow)
    expires_at = DateTimeField(required=True)
    last_used_at = DateTimeField()
    revoked_at = DateTimeField()

    scopes = ListField(StringField(), default=lambda: ["read"])

    # A bare record id, not a ReferenceField. The user class is pluggable via
    # SurrealEngineAuth.configure_user_class(), so no single target collection
    # can be baked into the schema: ReferenceField emits record<user>, and
    # issuing a key for a user in any other collection is then rejected by
    # SurrealDB ("Couldn't coerce value for field 'user' ... Expected
    # 'record<user>'"), so the write fails and the key is never returned. The
    # column stays a plain record id and callers resolve the owner through the
    # configured class.
    user = RecordIDField(required=True, indexed=True)

    metadata = DictField(default=dict)

    class Meta:
        collection = "api_keys"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the key without its digest.

        ``key_hash`` is a fast-verification digest, not a secret to display,
        but publishing it is unnecessary and gives an attacker a verifiable
        offline target. The plaintext key is never stored, so nothing useful
        is lost by hiding it.
        """
        return {
            key: value
            for key, value in super().to_dict().items()
            if key != "key_hash"
        }

    # ----------------------------------------------------------------- #
    # Creation
    # ----------------------------------------------------------------- #

    @classmethod
    def _issue(
        cls,
        user: "UserBuiltin",
        name: str,
        expires_at: datetime,
        scopes: Optional[List[str]],
        metadata: Optional[Dict[str, Any]],
    ) -> Tuple["APIKey", str]:
        api_key = security.generate_api_key()
        key = cls(
            key_hash=security.hash_api_key(api_key),
            name=name,
            scopes=scopes or ["read"],
            expires_at=expires_at,
            user=user.id,
            metadata=metadata or {},
        )
        return key, api_key

    @classmethod
    def create(
        cls,
        user: "UserBuiltin",
        name: str,
        expires_at: datetime,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an API key (sync).

        The returned ``api_key`` is the only time the plaintext key exists;
        it is not recoverable afterwards.
        """
        key, api_key = cls._issue(user, name, expires_at, scopes, metadata)
        key.save_sync()
        return {"key": key.to_dict(), "user": user.to_dict(), "api_key": api_key}

    @classmethod
    async def create_async(
        cls,
        user: "UserBuiltin",
        name: str,
        expires_at: datetime,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an API key (async). See :meth:`create`."""
        key, api_key = cls._issue(user, name, expires_at, scopes, metadata)
        await key.save()
        return {"key": key.to_dict(), "user": user.to_dict(), "api_key": api_key}

    # ----------------------------------------------------------------- #
    # Verification
    # ----------------------------------------------------------------- #

    @classmethod
    def _digest_for(cls, api_key: str, app_secret: Optional[str] = None) -> str:
        return security.hash_api_key(api_key, app_secret=app_secret)

    @classmethod
    def _check_state(cls, key: Optional["APIKey"]) -> Optional["APIKey"]:
        """Return ``key`` if it may still authenticate, else None.

        0.1.x only checked ``is_active`` on the async path and checked
        neither expiry nor revocation on either path, so a revoked or expired
        key kept working.
        """
        if key is None:
            return None
        if not key.is_active or key.revoked_at:
            return None
        if key.expires_at is None or key.expires_at < _utcnow():
            return None
        return key

    def _touch(self) -> None:
        self.last_used_at = _utcnow()

    @classmethod
    def verify_key(
        cls, api_key: str, app_secret: Optional[str] = None
    ) -> Optional["APIKey"]:
        """Look up and validate a presented API key (sync)."""
        if not api_key or not isinstance(api_key, str):
            return None
        digest = cls._digest_for(api_key, app_secret)
        try:
            key = cls.objects.filter_sync(key_hash=digest).first_sync()
        except Exception:  # pragma: no cover - defensive
            from .logger import get_logger

            get_logger().error("Error looking up API key digest")
            return None

        key = cls._check_state(key)
        if key is None:
            return None
        key._touch()
        key.save_sync()
        return key

    @classmethod
    async def verify_key_async(
        cls, api_key: str, app_secret: Optional[str] = None
    ) -> Optional["APIKey"]:
        """Look up and validate a presented API key (async)."""
        if not api_key or not isinstance(api_key, str):
            return None
        digest = cls._digest_for(api_key, app_secret)
        try:
            key = await cls.objects.filter(key_hash=digest).first()
        except Exception:  # pragma: no cover - defensive
            from .logger import get_logger

            get_logger().error("Error looking up API key digest")
            return None

        key = cls._check_state(key)
        if key is None:
            return None
        key._touch()
        await key.save()
        return key

    def is_usable(self) -> bool:
        """True when this key would still authenticate."""
        return self._check_state(self) is not None

    # ----------------------------------------------------------------- #
    # Lifecycle
    # ----------------------------------------------------------------- #

    def revoke(self) -> None:
        """Revoke this key permanently (sync)."""
        self.is_active = False
        self.revoked_at = _utcnow()
        self.updated_at = _utcnow()
        self.save_sync()

    async def revoke_async(self) -> None:
        """Revoke this key permanently (async)."""
        self.is_active = False
        self.revoked_at = _utcnow()
        self.updated_at = _utcnow()
        await self.save()

    def refresh(self, expires_in_days: int = 365) -> None:
        """Extend the expiry (sync)."""
        self.expires_at = _utcnow() + timedelta(days=expires_in_days)
        self.updated_at = _utcnow()
        self.save_sync()

    async def refresh_async(self, expires_in_days: int = 365) -> None:
        """Extend the expiry (async)."""
        self.expires_at = _utcnow() + timedelta(days=expires_in_days)
        self.updated_at = _utcnow()
        await self.save()

    def has_scope(self, scope: str) -> bool:
        """True when the key carries ``scope``."""
        return scope in (self.scopes or [])

    @property
    def is_expired(self) -> bool:
        """True when the expiry is in the past."""
        return self.expires_at is None or self.expires_at < _utcnow()


class SecurityEvent(Document):
    """Audit log of authentication and account events.

    Event types are a fixed vocabulary so that queries and dashboards can
    rely on them. New types must be added to :attr:`EVENT_TYPES`.
    """

    EVENT_TYPES = [
        "login_success", "login_failed", "logout", "password_changed",
        "user_created", "user_updated", "user_deactivated", "user_activated",
        "api_key_created", "api_key_revoked", "api_key_refreshed",
        "two_factor_enabled", "two_factor_disabled", "two_factor_verified",
        "email_confirmed", "passwordless_login",
        "user_registered", "user_authenticated", "user_unauthenticated",
        "api_key_authentication_succeeded", "api_key_authentication_failed",
        "confirmation_email_sent", "confirmation_email_send_failed",
        "email_confirmation_failed", "two_factor_verification_failed",
        "two_factor_code_sent", "two_factor_code_send_failed",
        "passwordless_login_link_sent", "passwordless_login_link_send_failed",
        "passwordless_login_succeeded", "passwordless_login_failed",
        "two_factor_authentication_succeeded", "two_factor_authentication_failed",
        "account_locked",
    ]

    event_type = ChoiceField(choices=EVENT_TYPES, required=True, indexed=True)
    timestamp = DateTimeField(required=True, indexed=True)
    # A real record link, not a string. As a string the column looked right and
    # was effectively useless: the ORM turns any "table:id" value into a record
    # literal when it builds a filter, so the query compared a record against
    # a stored string and matched nothing -- and filtering by the string form
    # failed for the same reason. Every lookup by user came back empty, which
    # is the one thing an audit log has to support. A link also keeps the event
    # queryable when the user record lives in a custom collection. SurrealDB
    # does not enforce referential integrity, so events survive deletion of
    # the user, which is the behaviour an audit log wants.
    user_id = RecordIDField(indexed=True)
    ip_address = IPAddressField()
    user_agent = StringField()
    details = DictField()

    class Meta:
        collection = "security_event"

    @classmethod
    def log_event(
        cls,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        connection: Any = None,
    ) -> "SecurityEvent":
        """Record an audit event (sync).

        ``details`` is passed through :func:`security.redact`, and
        ``ip_address`` is validated. A malformed address used to raise inside
        ``IPAddressField`` and drop the whole event; now the event is written
        without the untrusted value.
        """
        from .logger import get_logger

        logger = get_logger()
        event = cls(
            event_type=event_type,
            timestamp=_utcnow(),
            user_id=security.canonical_record_id(user_id),
            ip_address=security.safe_ip_address(ip_address),
            user_agent=(user_agent or None),
            details=security.redact(details or {}),
        )
        try:
            event.save_sync(connection=connection)
            logger.info(
                "Security event logged",
                {
                    "event_type": event_type,
                    "user_id": event.user_id,
                    "ip_address": event.ip_address,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"Error logging security event {event_type}: {exc}")
        return event

    @classmethod
    async def log_event_async(
        cls,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        connection: Any = None,
    ) -> "SecurityEvent":
        """Record an audit event (async). See :meth:`log_event`."""
        from .logger import get_logger

        logger = get_logger()
        event = cls(
            event_type=event_type,
            timestamp=_utcnow(),
            user_id=security.canonical_record_id(user_id),
            ip_address=security.safe_ip_address(ip_address),
            user_agent=(user_agent or None),
            details=security.redact(details or {}),
        )
        try:
            await event.save(connection=connection)
            logger.info(
                "Security event logged",
                {
                    "event_type": event_type,
                    "user_id": event.user_id,
                    "ip_address": event.ip_address,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"Error logging security event {event_type}: {exc}")
        return event


class TOTPManager:
    """Time-based one-time password helpers.

    Thin wrapper over :mod:`pyotp` that adds the replay bookkeeping the
    model needs.
    """

    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a new base32 TOTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def generate_totp_code(totp_secret: str) -> str:
        """Return the code for the current time step."""
        return pyotp.TOTP(totp_secret).now()

    @staticmethod
    def match_totp_step(totp_secret: str, code: str) -> Optional[int]:
        """Return the time step ``code`` is valid for, or None.

        Returning the step (rather than a bool) lets the caller persist it and
        reject a code that has already been spent, which a plain
        ``totp.verify`` cannot do: it accepts the same code for the rest of
        its window.
        """
        if not totp_secret or not code or not isinstance(code, str):
            return None
        totp = pyotp.TOTP(totp_secret)
        now = int(_utcnow().timestamp()) // totp.interval
        for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
            step = now + offset
            if security.constant_time_equals(totp.at(step * totp.interval), code):
                return step
        return None

    @staticmethod
    def verify_totp_code(totp_secret: str, code: str) -> bool:
        """Stateless code check. Prefer :meth:`match_totp_step`."""
        return TOTPManager.match_totp_step(totp_secret, code) is not None

    @staticmethod
    def get_totp_uri(
        totp_secret: str, username: str, issuer: str = "SurrealEngineAuth"
    ) -> str:
        """Build the ``otpauth://`` provisioning URI."""
        return pyotp.TOTP(totp_secret).provisioning_uri(
            username, issuer_name=issuer
        )

    @staticmethod
    def generate_qrcode(
        totp_secret: str, username: str, issuer: str = "SurrealEngineAuth"
    ) -> str:
        """Render the provisioning URI as an inline SVG data URL."""
        uri = TOTPManager.get_totp_uri(totp_secret, username, issuer)
        image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)
        with io.BytesIO() as buffer:
            image.save(buffer)
            encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        return f"data:image/svg+xml;base64,{encoded}"

    @staticmethod
    def generate_recovery_codes(count: int = 10) -> List[str]:
        """Generate ``count`` single-use recovery codes."""
        return [security.generate_recovery_code() for _ in range(count)]
