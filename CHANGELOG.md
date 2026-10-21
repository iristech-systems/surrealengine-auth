# Changelog

## 0.2.0

SurrealEngine 2.x release. Python 3.11+.

Read [docs/MIGRATION.md](docs/MIGRATION.md) before upgrading. In short: user
passwords keep working, API keys do not.

### Breaking

- **Requires surrealengine 2.x** and Python 3.11+.
- **Requires the SurrealDB 3 pre-release.** `surrealengine` 2.x depends on
  `surrealdb>=3.0.0b7`, and pip only considers pre-release versions of a
  package when some requirement names one explicitly. This package now depends
  on `surrealdb>=3.0.0b7` directly, so `pip install surrealengine-auth`
  resolves without `--pre`; otherwise it fails with "surrealengine==2.0.0
  cannot be used". Drop the pin once a stable SurrealDB 3 ships.
- **API keys are no longer `"<id>.<secret>"`.** They are bare UUID4s, stored
  as a keyed digest. `APIKey.formatted_key` and `APIKey.parse_key()` are
  removed, and the `key_secret` column is gone. Existing keys stop working.
- **`authenticate` raises `AuthenticationError`** on failure instead of
  returning `None`.
- **`register_user` returns `(None, False)`** when the username or email is
  taken, instead of the existing `User` — which carried `password_hash`,
  `salt`, `totp_secret`, and `login_token`.
- **`send_two_factor_code` returns `bool`**, not the code.
- **`AuthService` renamed to `SurrealEngineAuth`.**
- **Requires aiosmtplib 4 or later.** The message is now passed positionally,
  which aiosmtplib 4.0 made necessary; see the email fix below.

### Added

- **`change_password(user, password)` and `change_password_async(user, password)`.**
  0.1.x had no service-level way to change a password, so callers reached for
  `user.set_password(...)`, which hashed the new password and left every API
  key and session the old password had opened still usable. The new method
  revokes the account's API keys and its outstanding passwordless-login and
  email-2FA material, clears the lockout counter, and records a
  `password_changed` event. Pass `current_password` to require the old
  password.
- **`UserBuiltin.set_password(password)`** is back, hashing without saving,
  for callers that set the hash and save it themselves.

### Fixed

- **Email delivery was broken on aiosmtplib 4 and later.** The message was
  passed as `message=message`, but aiosmtplib 4.0 made positional arguments
  positional-only, so every send raised `TypeError` — which the call site
  caught and reported as `False`. No email left the process: no confirmation
  link, no passwordless link, no 2FA code. 0.1.x had the same call and the
  same bug. The message is now passed positionally, and the tests deliver
  mail over a real SMTP conversation rather than a stub.
- **Subclassing `UserBuiltin` no longer warns.** `UserBuiltin.Meta.collection`
  is a placeholder (`user_builtin`) rather than `users`, so an application
  that declares its own `Meta.collection` no longer collides with it and
  triggers a `RuntimeWarning` about a collection already being registered.
- **The `Meta` class is not inherited.** surrealengine's metaclass reads only
  a class's own `Meta`, so 0.1.x's `UserBuiltin.Meta.collection = "users"` was
  never used and every user record went to the table derived from the class
  name, `user`. The declared name was a trap for anyone reading the code to
  work out where their data lives.
- **`setup_database()` works on an existing database.** It raised
  `AlreadyExistsError` on a second call, and on any database 0.1.x created.
  It now converges the tables to the model without touching rows, and is
  declared idempotent, as its docstring always claimed.
- **Legacy users can be upgraded.** `user.metadata` was defined as a required
  `object`, but 0.1.x rows have no value for it, so writing the upgraded
  Argon2id hash failed with `Couldn't coerce value for field 'metadata'`. It is
  now `option<object> FLEXIBLE`.
- **API keys verify when an app secret is configured.** Digests were keyed at
  verification but hashed unkeyed at creation, so every key stopped working
  the moment a secret was set. The secret now has one source of truth.
- **Audit events are findable by user.** `security_event.user_id` was a string
  while the ORM serialises record-shaped values into record literals, so every
  filter by user matched nothing.
- **The async email-2FA path no longer uses synchronous audit writes**, which
  either grabbed a connection that did not exist or blocked the event loop.
- **Password hashes upgrade on login.** 0.1.x PBKDF2 hashes verified but were
  never rewritten; they are now re-hashed as Argon2id on success.
- **Recovery codes work.** Enrollment returned freshly generated codes instead
  of the ones stored, so no recovery code ever verified.
- **Lockout counts unknown usernames**, so lockout is not bypassed by guessing
  names that do not exist.
- **The user table stayed `user`.** `Meta` is not inherited by the
  metaclass, so 0.1.x wrote every user to the table derived from the class
  name. Renaming it to `users` would have made every existing account
  unreachable.
- `list_users` counts with `SELECT count() ... GROUP ALL` rather than
  materialising every row.

### Changed

- Passwords use Argon2id.
- Email 2FA is a real six-digit code: single use, five-minute lifetime, five
  attempts. 0.1.x emailed a rotating TOTP that expired after 30 seconds, so it
  was usually dead on arrival.
- Confirmation and passwordless tokens are HMAC-signed, expiring, and
  non-replayable. Both lifetimes are configurable.
- Audit `details` is redacted; malformed IPs are dropped rather than failing
  the event.
- `to_dict()` omits password, TOTP, lockout, and key-digest fields.
- `surrealengine_auth.security` is new: hashing, tokens, key generation,
  record-id canonicalisation, and redaction.

### Known gaps

- Five event types are declared in `SecurityEvent.EVENT_TYPES` but never
  emitted (`login_success`, `login_failed`, `user_created`,
  `passwordless_login`, `logout`). See
  [docs/MIGRATION.md](docs/MIGRATION.md#audit-event-names).
- No rate limiting on registration or passwordless link requests.
- Lockout counters are per-process unless a shared store is wired in.

## 0.1.0

Initial release.
