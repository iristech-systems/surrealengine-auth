# Security Policy

## Reporting

Report a vulnerability privately, not as a public issue. Include the version,
the affected method, and a reproduction if you have one. Fixes ship as a patch
release.

## What this package does

Authentication, API keys, two-factor, and an audit log. It is not an
authorization framework — permission scopes on API keys are stored and
enforced by you, not by this package.

## Cryptography

**Passwords** are hashed with Argon2id. 0.1.x PBKDF2-SHA256 hashes (100k
rounds, salt in a separate column) are still verified, and are rewritten as
Argon2id on the next successful login.

**API keys** are 128-bit random UUID4s. Only a keyed digest (HMAC-SHA256, keyed
with the app secret) is stored, so read access to the `api_keys` table does not
let an attacker confirm a guessed key offline. Plaintext exists only in the
`create_api_key` response.

**Email 2FA codes** are six digits, so they are stored as digests too — an
attacker with read access to the `user` table cannot read live codes. They are
single use, expire after five minutes, and are capped at five attempts.

**Recovery codes** are stored hashed, shown once, and consumed on use.

**Tokens** (email confirmation, passwordless login) are HMAC-signed and carry
an expiry and a `jti`, so a link cannot be replayed.

## Secrets

`SURREALENGINE_AUTH_SECRET` keys both token signing and API key digests.

If it is unset, a random secret is generated at startup and a warning is
logged. **Tokens and API keys then stop working when the process restarts**,
and two instances behind a load balancer will not accept each other's tokens.
Set it in production.

`configure_token_secret()` and `configure_app_secret()` default to the same
value. Use a separate app secret only if you want key digests to survive a
token-secret rotation.

## Audit log

`SecurityEvent` records logins, failures, key changes, and 2FA activity.

`details` is passed through a redaction helper: password hashes, TOTP
secrets, 2FA codes, recovery codes, tokens, and key digests are replaced, and
only field names and reasons are stored. A malformed IP address is dropped
rather than failing the event.

`event_type` is a fixed vocabulary in `SecurityEvent.EVENT_TYPES`. Note that
five declared types are never emitted — see
[docs/MIGRATION.md](docs/MIGRATION.md#audit-event-names).

## Lockout

Failed logins are counted per identifier, including identifiers that match no
account, so lockout cannot be sidestepped by guessing names that do not exist.
Defaults are 5 attempts and 900 seconds; tune with `max_attempts` and
`lockout_seconds`.

Lockout is per-identifier in application memory unless a shared store is
wired in, so across multiple processes the effective threshold multiplies.

## Known gaps

- **No session management.** This package does not issue, rotate, or revoke
  sessions. If you use passwordless or 2FA logins, the token you hand out is
  the session.
- **No CSRF protection.** Not applicable to API clients; if you bridge these
  calls to a browser session, that is your layer.
- **No brute-force throttling on `authenticate_with_api_key`.** API keys are
  128-bit, so guessing is not the risk; key *distribution* is.
- **No rate limiting** on registration or passwordless link requests. Both
  send email, so both are usable for mail-bombing a third party. Put a rate
  limit in front of them.
