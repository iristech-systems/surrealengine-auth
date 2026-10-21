# SurrealEngine Auth

Authentication and authorization for SurrealDB applications, built on the
SurrealEngine ORM. Users, password login, API keys, two-factor authentication,
email confirmation, passwordless login, and an audit log.

Requires **Python 3.11+** and **surrealengine 2.x**.

## Install

```bash
pip install surrealengine-auth
```

SurrealDB 3 is still a pre-release, and `surrealengine` 2.x depends on it. This
package requires it explicitly, so the above normally just works, but if your
resolver refuses (older pip, or a strict index) enable pre-releases:

```bash
pip install --pre surrealengine-auth
```

`--pre` is pip's flag; if you use [uv](https://docs.astral.sh/uv/), the
equivalent is `uv pip install --prerelease=allow surrealengine-auth`.

Python 3.11–3.13 has prebuilt wheels. On 3.14 `surrealengine` has none, so pip
falls back to a Rust toolchain build and needs `maturin`.

For local or in-process SurrealDB (`mem://`, `file://`, `surrealkv://`):

```bash
pip install "surrealengine-auth[embedded]"
```

## Quick start

```python
from surrealengine import create_connection
from surrealengine_auth import SurrealEngineAuth

connection = create_connection("ws://localhost:8000/rpc", "myapp", "auth")
connection.connect()

# One-off: create the tables. Safe to call on every startup.
SurrealEngineAuth.setup_database()

# Set a secret so tokens and key digests stay valid across restarts.
SurrealEngineAuth.configure_token_secret()  # reads SURREALENGINE_AUTH_SECRET

user, created = SurrealEngineAuth.register_user(
    username="johndoe",
    email="john@example.com",
    password="correct horse battery staple",
)

user = SurrealEngineAuth.authenticate("johndoe", "correct horse battery staple")
```

`register_user` returns `(user, created)`. `created` is `False` when the
username or email is already taken, in which case `user` is `None` — see
[Return values](#return-values).

## Configuration

### Secrets

```python
SurrealEngineAuth.configure_token_secret()   # SURREALENGINE_AUTH_SECRET
SurrealEngineAuth.configure_app_secret()     # defaults to the token secret
```

`configure_token_secret()` generates a random secret and warns if none is
supplied, which means **tokens and API keys stop working when the process
restarts**. Set `SURREALENGINE_AUTH_SECRET` in production.

The app secret keys API key digests (HMAC-SHA256). An attacker who reads the
`api_keys` table cannot confirm a guessed key offline without it.

### Email

```python
SurrealEngineAuth.configure_email_service(
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_username="...",
    smtp_password="...",
    use_tls=True,
    default_sender="noreply@example.com",
)
```

Or set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
`SMTP_USE_TLS`, `SMTP_USE_SSL`, `SMTP_SENDER`.

### Your own user model

```python
from surrealengine_auth import SurrealEngineAuth, UserBuiltin

class Account(UserBuiltin):
    organisation = StringField(required=True)

    class Meta:
        collection = "accounts"

SurrealEngineAuth.configure_user_class(Account)
```

`UserBuiltin` is a base, not a table. Declare `Meta.collection` on your
concrete subclass — the metaclass does not inherit `Meta`, so a subclass
without one falls back to its lowercased class name.

## Users

```python
user, created = SurrealEngineAuth.register_user(
    "johndoe", "john@example.com", "a password",
    metadata={"first_name": "John"},
)

user = SurrealEngineAuth.get_user_by_username("johndoe")
user = SurrealEngineAuth.get_user_by_email("john@example.com")
user = SurrealEngineAuth.get_user_by_id(user.id)

SurrealEngineAuth.update_user(user, email="new@example.com")
SurrealEngineAuth.deactivate_user(user)   # also revokes every API key
SurrealEngineAuth.activate_user(user)

page = SurrealEngineAuth.list_users(page_number=1, page_size=50)
# {"items": [...], "total": n, "page": 1, "per_page": 50, "size": k, "pages": m}
```

Passwords are Argon2id by default. A hash written by 0.1.x (PBKDF2-SHA256,
100k rounds, with the salt in a separate column) still verifies, and is
rewritten as Argon2id the first time that user logs in.

### Changing a password

```python
# Requires the old password.
SurrealEngineAuth.change_password(user, "a new password", current_password="the old one")

# Or when the caller has already established the user's identity.
SurrealEngineAuth.change_password(user, "a new password")
```

Changing a password revokes everything the old one could reach: the account's
API keys, any outstanding passwordless-login token, and any emailed 2FA code.
It also clears the lockout counter. Each revocation is recorded in the audit
log.

To change the hash without saving — for a caller that manages the save
itself — use `user.set_password(new_password)` and then `user.save()`.

### Account lockout

Five failed attempts locks an account for 15 minutes. Tune with
`SurrealEngineAuth.max_attempts` and `SurrealEngineAuth.lockout_seconds`.
Failed attempts are recorded against the supplied identifier, so an unknown
username is throttled too — otherwise lockout is free to bypass by guessing
names that do not exist.

## API keys

```python
result = SurrealEngineAuth.create_api_key(
    user, "My API Key", expires_in_days=365, scopes=["read", "write"],
)

result["key"]      # the APIKey record, without its digest
result["api_key"]  # the plaintext key — returned exactly once

user = SurrealEngineAuth.authenticate_with_api_key(result["api_key"])
```

The plaintext key exists only in that response. It is never stored and cannot
be recovered; only its keyed digest is kept. If you lose it, create a new key.

```python
keys = SurrealEngineAuth.list_api_keys(user)
active = SurrealEngineAuth.list_active_api_keys(user)
SurrealEngineAuth.revoke_api_key(user, key.key_id)
SurrealEngineAuth.refresh_api_key(key, expires_in_days=30)
SurrealEngineAuth.get_api_key(key.key_id)
```

Keys are bare UUID4 strings. The 0.1.x `"<id>.<secret>"` format is gone — see
[Upgrading from 0.1.x](docs/MIGRATION.md).

## Two-factor authentication

```python
setup = SurrealEngineAuth.setup_two_factor(user, "authenticator")
setup["qrcode"]         # SVG data URL, show it to the user
setup["secret"]         # TOTP secret
setup["recovery_codes"] # shown once, store them

SurrealEngineAuth.send_two_factor_code(user)   # email method only; returns bool

user = SurrealEngineAuth.authenticate_with_two_factor(
    "john@example.com", "password", "123456",
)

SurrealEngineAuth.disable_two_factor(user)
```

Methods: `"authenticator"` (TOTP) and `"email"`.

**Email codes are six digits, valid for five minutes, single use, and capped
at five attempts.** Adjust with `User.email_code_expires_in` (seconds) and
`User.email_code_max_attempts`.

`send_two_factor_code` returns whether the message was accepted. It never
returns the code — 0.1.x did, so any endpoint that passed the return value
through to a response was handing out the second factor.

`setup_two_factor` returns the recovery codes once. They are stored hashed;
`verify_two_factor` accepts either a live TOTP/email code or one recovery
code, and consumes a recovery code on use.

## Email confirmation

```python
if created:
    SurrealEngineAuth.send_confirmation_email(user, "https://app.example.com")

user = SurrealEngineAuth.confirm_email(token_from_the_link)
```

Tokens are HMAC-signed with a `jti` so a confirmation link cannot be replayed.
Lifetime is `User.confirmation_token_expires_in` (default 24 hours), and can
be overridden per call.

## Passwordless login

```python
SurrealEngineAuth.send_passwordless_login_link(user, "https://app.example.com")
user = SurrealEngineAuth.authenticate_with_login_token(token)
```

One-time, like confirmation. Lifetime is `User.login_token_expires_in`
(default 15 minutes).

## Audit log

Every login, failure, key change, and 2FA event is written to `SecurityEvent`
with a redacted `details` payload, the user link, IP, and user agent.

```python
from surrealengine_auth import SecurityEvent

events = SecurityEvent.objects.filter(
    event_type="user_unauthenticated", user_id=user.id
).all()
```

`event_type` is a fixed vocabulary (`SecurityEvent.EVENT_TYPES`). Read it
rather than hardcoding strings — see
[Audit event names](docs/MIGRATION.md#audit-event-names) for types that are
declared but not currently emitted.

`details` never stores password hashes, codes, recovery codes, tokens, or
key digests — only field names and reasons. A malformed IP address is dropped
rather than failing the whole event.

## Async

Every method has an `_async` twin with the same signature:

```python
user = await SurrealEngineAuth.authenticate_async("johndoe", "password")
```

The async path is complete, not partial: it never touches a synchronous
connection, so it works in an async-only application.

## Return values

Two things changed from 0.1.x and are worth stating plainly:

- `authenticate` **raises** `AuthenticationError` on failure. It no longer
  returns `None`, so a missing `if user:` check is a crash rather than an
  unauthenticated request.
- `register_user` returns `(None, False)` when the username or email is
  taken. 0.1.x returned the existing `User` object, which carried
  `password_hash`, `salt`, `totp_secret`, and `login_token`. The service
  refuses to decrypt or re-issue a password; check the flag and treat the
  outcome as a no-op.

Both are the same shape as the corresponding `User` model methods.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Requirements

- Python 3.11+
- surrealengine 2.x

## License

MIT
