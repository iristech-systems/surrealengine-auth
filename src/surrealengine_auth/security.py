"""
Cryptographic primitives for surrealengine-auth.

Every value in this module is a pure function of its inputs. Nothing here
touches the database, the connection, or the event loop, which is what allows
the sync and async code paths in :mod:`surrealengine_auth.models` and
:mod:`surrealengine_auth.service` to share one implementation instead of
drifting apart (the original package carried a separate copy of the hashing
logic in every method pair, and the copies disagreed).

Design notes
------------
* Passwords use Argon2id by default. PBKDF2-HMAC-SHA256 is still *verified*
  so that hashes written by 0.1.x keep working, and are transparently
  upgraded to Argon2id the next time the user logs in.
* Password hashes are self-describing PHC strings. The legacy ``salt`` column
  is only consulted when the stored hash lacks a PHC prefix.
* API keys are UUID4 bearer tokens. Only a SHA-256 digest is stored, so a
  database disclosure does not yield usable credentials. A keyed digest is
  used when an application secret is configured, which also lets lookups find
  a key by digest without scanning.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from argon2.low_level import Type as Argon2Type

__all__ = [
    "HashConfig",
    "TokenConfig",
    "hash_password",
    "verify_password",
    "password_needs_rehash",
    "dummy_verify",
    "generate_api_key",
    "hash_api_key",
    "AppSecretConfig",
    "constant_time_equals",
    "constant_time_contains",
    "generate_token",
    "verify_token",
    "token_is_expired",
    "hash_recovery_code",
    "normalise_recovery_code",
    "generate_recovery_code",
    "hash_email_code",
    "safe_ip_address",
    "canonical_record_id",
    "redact",
    "SENSITIVE_FIELD_NAMES",
]

# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #

#: Iteration count used by 0.1.x. Retained so old hashes stay verifiable.
LEGACY_PBKDF2_ITERATIONS = 100_000

#: OWASP's 2023 floor for PBKDF2-HMAC-SHA256. Only used for legacy fallback
#: verification, never for new hashes.
PBKDF2_FLOOR_ITERATIONS = 600_000

#: Argon2id parameters. These are the values Argon2-cffi ships as defaults,
#: chosen by the reference implementation to sit at roughly the 600k-PBKDF2
#: equivalence. They are passed explicitly so a future argon2-cffi default
#: bump cannot silently change how existing hashes verify.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    type=Argon2Type.ID,
)

_dummy_hash: Optional[str] = None


class HashConfig:
    """Process-wide switches for the hashing helpers.

    These exist so an application can roll back to PBKDF2 (or pin a specific
    cost) without forking this module. Attributes are read on every call.
    """

    algorithm: str = "argon2id"
    pbkdf2_iterations: int = PBKDF2_FLOOR_ITERATIONS
    legacy_pbkdf2_iterations: int = LEGACY_PBKDF2_ITERATIONS


def _is_legacy_pbkdf2(encoded: Optional[str]) -> bool:
    """Return True when ``encoded`` is a bare hex digest from 0.1.x."""
    if not encoded:
        return False
    return not encoded.startswith("$")


def hash_password(
    password: str,
    *,
    algorithm: Optional[str] = None,
    salt: Optional[str] = None,
    iterations: Optional[int] = None,
) -> str:
    """Hash ``password``, returning a self-describing PHC string.

    Args:
        password: The plaintext password.
        algorithm: ``"argon2id"`` (default) or ``"pbkdf2"``. When ``"pbkdf2"``
            the result is a bare hex digest and ``salt`` is required. The
            pbkdf2 branch exists to reproduce 0.1.x digests for migration
            tests; new passwords are always Argon2id.
        salt: Hex salt. Only meaningful for the ``"pbkdf2"`` algorithm.
        iterations: PBKDF2 iteration count. Defaults to
            :data:`LEGACY_PBKDF2_ITERATIONS`, the only count
            :func:`verify_password` can check a bare-hex digest against.

    Returns:
        The encoded hash.
    """
    algo = algorithm or HashConfig.algorithm
    if algo == "argon2id":
        return _hasher.hash(password)
    if algo == "pbkdf2":
        if not salt:
            salt = secrets.token_hex(16)
        # Deliberately the legacy count, not PBKDF2_FLOOR_ITERATIONS: a bare
        # hex digest carries no parameters, so verification has to assume
        # 0.1.x's 100k. Hashing at the floor here would produce digests that
        # verify_password could never accept.
        rounds = iterations or HashConfig.legacy_pbkdf2_iterations
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds
        ).hex()
    raise ValueError(f"unsupported password algorithm: {algo!r}")


def verify_password(
    password: str, encoded: Optional[str], salt: Optional[str] = None
) -> bool:
    """Verify ``password`` against a stored hash of either format.

    ``encoded`` may be an Argon2 PHC string or a legacy bare-hex PBKDF2
    digest. Legacy digests are verified with the iteration count 0.1.x used,
    because the stored digest is not self-describing.
    """
    if not password or not encoded:
        return False

    if _is_legacy_pbkdf2(encoded):
        if not salt:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            LEGACY_PBKDF2_ITERATIONS,
        ).hex()
        return hmac.compare_digest(candidate, encoded)

    try:
        return _hasher.verify(encoded, password)
    except (argon2_exceptions.VerifyMismatchError, argon2_exceptions.InvalidHashError):
        return False
    except argon2_exceptions.VerificationError:
        return False


def password_needs_rehash(encoded: Optional[str]) -> bool:
    """Return True when ``encoded`` should be replaced by a current hash."""
    if not encoded or _is_legacy_pbkdf2(encoded):
        return True
    try:
        return _hasher.check_needs_rehash(encoded)
    except argon2_exceptions.InvalidHashError:
        return True


def dummy_verify() -> None:
    """Burn an Argon2 verification to equalise timing against a missing user.

    :meth:`SurrealEngineAuth.authenticate` calls this when the username does
    not exist, so that a lookup miss costs roughly the same as a wrong
    password and cannot be distinguished by timing.
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(32))
    try:
        _hasher.verify(_dummy_hash, "not-a-real-password")
    except argon2_exceptions.VerificationError:
        pass


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #


def generate_api_key() -> str:
    """Generate an API key.

    The key is a bare UUID4 string, which is what callers present to
    ``authenticate_with_api_key``. UUID4 carries 122 random bits, which is
    ample for a bearer credential provided it is never logged and not stored
    in the clear.
    """
    import uuid

    return str(uuid.uuid4())


class _AppSecretConfig:
    """Holds the secret that keys API key digests.

    Single source of truth on purpose. Keying is applied when a digest is
    *written* and again when it is *compared*, and those two calls live in
    different layers -- issuance is a model, verification goes through the
    service facade. When the secret was carried as a parameter, a caller that
    forgot it produced a digest that could never be verified: keys silently
    stopped working the moment an app secret was configured.
    """

    def __init__(self) -> None:
        self._secret: Optional[str] = None

    def configure(self, secret: Optional[str]) -> Optional[str]:
        self._secret = secret or None
        return self._secret

    @property
    def secret(self) -> Optional[str]:
        return self._secret


AppSecretConfig = _AppSecretConfig()


def hash_api_key(api_key: str, *, app_secret: Optional[str] = None) -> str:
    """Return the digest stored for ``api_key``.

    A plain SHA-256 is sufficient: the input is a high-entropy random value,
    not a low-entropy secret that would need a slow KDF. When a secret is
    available the digest is keyed (HMAC-SHA256), which additionally prevents
    an attacker with read access to the ``api_keys`` table from confirming a
    guessed key offline.

    ``app_secret`` overrides :data:`AppSecretConfig`; passing it is only
    necessary to key a digest with something other than the configured
    secret. Leaving it unset is what keeps issuance and verification in
    agreement.
    """
    key = app_secret or AppSecretConfig.secret
    raw = api_key.encode("utf-8")
    if key:
        return hmac.new(key.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def constant_time_equals(left: Optional[str], right: Optional[str]) -> bool:
    """Compare two strings without leaking their contents through timing."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def constant_time_contains(haystack: Optional[Sequence[str]], needle: str) -> bool:
    """Return True when ``needle`` is in ``haystack``, without early exit.

    Recovery codes are user-supplied secrets, so a ``list.__contains__`` hands
    an attacker a timing signal that shortens the search. Every element is
    compared.
    """
    if not haystack:
        return False
    if not isinstance(needle, str):
        return False
    return any(constant_time_equals(candidate, needle) for candidate in haystack)


# --------------------------------------------------------------------------- #
# Signed, expiring tokens (email confirmation and passwordless login)
# --------------------------------------------------------------------------- #


class TokenConfig:
    """Signing configuration for :func:`generate_token`.

    ``secret`` is resolved once by :class:`SurrealEngineAuth` and reused for
    every token it issues.
    """

    secret: Optional[str] = None
    issuer: str = "surrealengine-auth"

    @classmethod
    def configure(cls, secret: Optional[str], issuer: Optional[str] = None) -> None:
        cls.secret = secret
        if issuer:
            cls.issuer = issuer

    @classmethod
    def generate_secret(cls) -> str:
        return secrets.token_urlsafe(32)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(secret: str, payload: bytes) -> str:
    return _b64e(hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest())


def generate_token(
    payload: Dict[str, Any],
    *,
    secret: Optional[str] = None,
    expires_in: int = 3600,
    issuer: Optional[str] = None,
) -> str:
    """Build a signed, expiring token.

    Format: ``base64url(json).base64url(hmac)``. The payload always carries
    ``exp`` and ``iat``; ``jti`` gives callers single-use semantics by
    remembering it server-side.

    This replaces the 0.1.x confirmation token, which was
    ``base64(id:email:random)`` with the random component discarded during
    verification. That format was forgeable by anyone who knew a user's id
    and email address.
    """
    key = secret or TokenConfig.secret
    if not key:
        raise RuntimeError(
            "no signing secret configured; call "
            "SurrealEngineAuth.configure_token_secret() or set "
            "SURREALENGINE_AUTH_SECRET"
        )

    now = datetime.now(timezone.utc)
    body = dict(payload)
    body["iat"] = int(now.timestamp())
    body["exp"] = int((now + timedelta(seconds=expires_in)).timestamp())
    body["iss"] = issuer or TokenConfig.issuer
    body.setdefault("jti", secrets.token_urlsafe(16))

    encoded = _b64e(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{encoded}.{_sign(key, encoded.encode('ascii'))}"


class TokenError(ValueError):
    """Raised when a token is malformed, forged, or expired."""


def verify_token(
    token: str,
    *,
    secret: Optional[str] = None,
    verify_exp: bool = True,
) -> Dict[str, Any]:
    """Verify a token's signature and expiry, returning its payload.

    Raises:
        TokenError: if the token is malformed, the signature does not match,
            or the token has expired.
    """
    key = secret or TokenConfig.secret
    if not key:
        raise TokenError("no signing secret configured")

    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed token")

    encoded, signature = token.split(".", 1)
    expected = _sign(key, encoded.encode("ascii"))
    if not hmac.compare_digest(expected, signature):
        raise TokenError("bad token signature")

    try:
        payload = json.loads(_b64d(encoded))
    except (ValueError, binascii.Error) as exc:
        raise TokenError("malformed token payload") from exc
    if not isinstance(payload, dict):
        raise TokenError("malformed token payload")

    if verify_exp and token_is_expired(payload):
        raise TokenError("token expired")
    return payload


def token_is_expired(payload: Dict[str, Any], leeway: int = 0) -> bool:
    """Return True when ``payload``'s ``exp`` is in the past."""
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return True
    now = datetime.now(timezone.utc).timestamp()
    return (now - leeway) > float(exp)


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #


def normalise_recovery_code(code: str) -> str:
    """Fold a user-typed recovery code into canonical form.

    Users routinely retype these from paper, dropping spaces and dashes or
    upper-casing them. Normalising before hashing means a valid code is not
    rejected over whitespace.
    """
    if not isinstance(code, str):
        return ""
    return "".join(ch for ch in code.strip().upper() if ch.isalnum())


def generate_recovery_code() -> str:
    """Generate a recovery code in ``xxxx-xxxx-xxxx-xxxx`` form."""
    raw = secrets.token_hex(8)
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


def hash_recovery_code(code: str, *, pepper: Optional[str] = None) -> str:
    """Hash a recovery code for storage.

    Recovery codes are high-entropy (64 bits) and are consumed once, so a
    single SHA-256 pass is appropriate; the optional pepper is for
    deployments that want to invalidate all codes by rotating one value.
    """
    normalised = normalise_recovery_code(code)
    raw = normalised.encode("utf-8")
    if pepper:
        return hmac.new(pepper.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def hash_email_code(code: str, *, pepper: Optional[str] = None) -> str:
    """Hash a one-time 2FA code emailed to the user.

    Domain-separated from :func:`hash_recovery_code` with an ``email2fa:``
    prefix. Without that, a six-digit emailed code and a high-entropy recovery
    code share a digest function and a user could present a recovery code in
    the emailed-code field, turning a one-time code into a repeatable one.
    """
    normalised = "".join(ch for ch in str(code or "").strip() if ch.isalnum())
    raw = f"email2fa:{normalised}".encode("utf-8")
    if pepper:
        return hmac.new(pepper.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


# --------------------------------------------------------------------------- #
# Logging hygiene
# --------------------------------------------------------------------------- #

#: Field names that must never be copied into a log line or audit record.
SENSITIVE_FIELD_NAMES = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "password_hash",
        "salt",
        "totp_secret",
        "tf_recovery_codes",
        "login_token",
        "key_secret",
        "key_hash",
        "api_key",
        "confirmation_token",
        "token",
        "code",
        "secret",
        "smtp_password",
    }
)

_REDACTED = "[REDACTED]"


def safe_ip_address(value: Optional[str]) -> Optional[str]:
    """Return ``value`` if it is a valid IP address, else ``None``.

    ``SecurityEvent.ip_address`` is an ``IPAddressField``, which raises on
    malformed input. A bad ``X-Forwarded-For`` value would therefore abort
    the audit write and silently lose the event. Validating here means the
    event is still recorded, without the untrusted string.
    """
    if not value or not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    # Tolerate a forwarded chain such as "203.0.113.7, 10.0.0.1".
    if "," in candidate:
        candidate = candidate.split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def canonical_record_id(value: Any) -> Optional[str]:
    """Render a record id as a plain ``table:id`` string.

    ``str(RecordID)`` produces SurrealDB's ``table:⟨id⟩`` form. That unicode
    bracketing leaks into log lines, email links and error messages, and the
    ORM re-parses any ``table:id`` string into a record literal, so a string
    column holding it can never be compared against. Normalising at the
    boundary keeps ids readable and comparable.
    """
    if value is None:
        return None
    table = getattr(value, "table_name", None)
    record = getattr(value, "id", None)
    if record is not None and table is not None:
        return f"{table}:{record}"
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if not value:
        return None
    # Drop SurrealQL's ⟨⟩ delimiters, then keep only the first separator so
    # ids containing colons survive.
    if value.endswith("⟩") and "⟨" in value:
        head, _, tail = value.rpartition(":")
        if head:
            value = f"{head}:{tail.strip('⟨⟩')}"
        else:
            value = value.strip("⟨⟩")
    table, sep, record = value.partition(":")
    if not sep:
        return None
    return f"{table}:{record.strip('⟨⟩')}"


def redact(
    value: Any, *, extra_keys: Optional[Iterable[str]] = None
) -> Any:
    """Return a copy of ``value`` safe to write to a log or audit record.

    Recursively replaces sensitive keys, and truncates long strings so an
    audit record cannot become a covert channel for exfiltrated data.
    """
    blocked = set(SENSITIVE_FIELD_NAMES)
    if extra_keys:
        blocked.update(extra_keys)

    if isinstance(value, dict):
        return {
            key: (
                _REDACTED
                if key in blocked
                else redact(item, extra_keys=extra_keys)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, extra_keys=extra_keys) for item in value]
    if isinstance(value, str) and len(value) > 512:
        return value[:509] + "..."
    return value


def fingerprint(value: Optional[str], *, length: int = 8) -> Optional[str]:
    """Return a short, non-reversible identifier for ``value``.

    Lets an operator correlate repeated failures on the same credential
    without the identifier itself being usable to authenticate.
    """
    if not value or not isinstance(value, str):
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]
