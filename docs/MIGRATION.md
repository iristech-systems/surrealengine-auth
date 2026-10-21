# Upgrading from 0.1.x to 0.2.0

0.2.0 moves to surrealengine 2.x. Read this before deploying: there is one
change that invalidates data, one that changes call signatures, and a set of
behaviour changes that are silent.

**Short version: your users keep working. Your API keys do not.**

## 1. Upgrade path

```
pip install "surrealengine-auth>=0.2"
```

Then, once, at startup:

```python
SurrealEngineAuth.setup_database()
```

`setup_database()` is now safe to call on every startup and safe to call
against a database 0.1.x created. It converges the tables to the current
schema and does not touch your rows.

Before 0.2.0 it was neither: it raised `AlreadyExistsError` on a second call,
and raised on a database it had not created itself.

## 2. What keeps working

### Passwords

0.1.x stored PBKDF2-SHA256 (100,000 rounds) as a bare hex digest in
`password_hash`, with the salt in a separate `salt` column. Both columns are
still read. Those users can log in, and their hash is rewritten as Argon2id
on first successful login.

```python
user = SurrealEngineAuth.authenticate("johndoe", "their real password")
user.password_hash.startswith("$argon2id$")   # True, now
```

No action needed. The `salt` column is kept deliberately for this reason.

### Audit rows

Existing `security_event` rows are left alone. New rows are written with a
record link in `user_id`; old rows keep their string form. See
[Audit event names](#audit-event-names).

## 3. What breaks

### API keys are invalid

This is the one piece of data that does not carry over.

0.1.x stored the key secret in plaintext in a `key_secret` column and
presented keys as `"<key_id>.<key_secret>"`. 0.2.0 stores a keyed digest in
`key_hash` and presents a bare UUID4. Neither half of the old scheme is
recoverable into the new one, and no code path is kept for it.

- `APIKey.formatted_key` — **removed** (raised `AttributeError` in earlier
  2.0 pre-releases; it does not exist at all now).
- `APIKey.parse_key()` — **removed**.
- `key_secret` column — **removed**.

```python
# 0.1.x
result = AuthService.create_api_key(user, "My Key", expires_at=...)
formatted = result["key"].formatted_key

# 0.2.0
result = SurrealEngineAuth.create_api_key(user, "My Key", expires_in_days=365)
result["api_key"]     # the plaintext, returned exactly once
```

Anyone holding an old key gets `AuthenticationError`. Hand out new ones. The
`api_keys` table is not cleared automatically, so old rows stay inert.

### Return values

```python
# 0.1.x: authenticate returned None on failure
user = AuthService.authenticate("johndoe", password)
if user: ...

# 0.2.0: it raises
user = SurrealEngineAuth.authenticate("johndoe", password)
```

A missing `if user:` check is now a crash rather than an unauthenticated
request. That is the point, but it will surface in endpoints that had the
check.

```python
# 0.1.x: a taken username returned the existing User, leaking its secrets
user, created = AuthService.register_user(...)

# 0.2.0: (None, False)
user, created = SurrealEngineAuth.register_user(...)
```

`register_user` will not hand back another user's record, so it cannot be
used to read `password_hash`, `salt`, `totp_secret`, or `login_token`. Check
`created` and treat `False` as "someone already has this account" rather than
logging the newcomer in.

`send_two_factor_code` returns `bool`, not the code. 0.1.x returned the code
itself, so any endpoint returning it to the client was handing out the second
factor.

### Model and service names

`AuthService` → `SurrealEngineAuth`.

## 4. The user table is named `user`

`User.Meta.collection` is `"user"`, singular. This looks like a typo and is
not.

0.1.x declared `collection = "users"` on `UserBuiltin` but not on `User`.
The metaclass reads only a class's own `Meta`, never the parent, so the
declared name was never used — `User` fell back to its lowercased class name
and every user record went to `user`.

Renaming the table to `users` would leave every existing account unreachable:
login would fail closed against an empty table, and no password hash would
ever be read. If you have checked `INFO FOR DB` and your users really are in
`users`, define your own subclass with the collection you want and pass it to
`configure_user_class`.

## 5. Schema changes applied by `setup_database()`

`setup_database()` converges these. Each was verified against a 0.1.x-shaped
database.

| Table | Change |
| --- | --- |
| `user` | table becomes `SCHEMAFULL`; `metadata` becomes `option<object> FLEXIBLE` |
| `api_keys` | `key_secret` removed, `key_hash` added, `user` becomes a record link |
| `security_event` | `user_id` becomes a record link (`option<record>`) |

Two of these are worth understanding rather than trusting.

**`metadata` is optional.** It is declared `object FLEXIBLE`, which does *not*
accept an absent value. 0.1.x rows have no `metadata`, so without the
`option<>` wrapper the row becomes unwritable — a user authenticates, and then
cannot save their upgraded password hash. The field is `FLEXIBLE` so unknown
keys still work; `option<object>` without `FLEXIBLE` would reject them.

**Field definitions are applied with `OVERWRITE`.** Plain `DEFINE FIELD` errors
on a field that already exists, and redefining a column without `OVERWRITE`
leaves the table rejecting writes once it holds a value of the old type.

If you have added fields to the `user` table outside the model, they are not
in the model's field list and their definitions are dropped by the
`SCHEMAFULL` conversion. Declare them on your user subclass so
`setup_database()` keeps them.

## 6. Audit event names

`SecurityEvent.EVENT_TYPES` is the fixed vocabulary, and the docstring
promises that dashboards can rely on it. Five entries are currently declared
but never emitted, so a query on them returns nothing:

| Declared | Actually emitted |
| --- | --- |
| `login_success` | `user_authenticated` |
| `login_failed` | `user_unauthenticated` |
| `user_created` | `user_registered` |
| `passwordless_login` | `passwordless_login_succeeded` |
| `logout` | *(nothing — there is no logout method)* |

Query the right-hand names. If you are writing alerting, use
`user_unauthenticated` and `account_locked`.

## 7. Other behaviour changes

- **Email 2FA is a real code.** 0.1.x emailed a rotating TOTP that expired
  after 30 seconds, so it was usually dead on arrival. It is now a six-digit
  code, single use, valid five minutes, five attempts
  (`User.email_code_expires_in`, `User.email_code_max_attempts`).
- **Recovery codes are shown once and stored hashed.** 0.1.x returned codes
  that were never the ones stored, so recovery never worked.
- **Lockout counts unknown usernames.** It is tracked against the supplied
  identifier, so guessing names that do not exist is throttled too.
- **Tokens are HMAC-signed and expiring**, with a `jti` so confirmation and
  passwordless links cannot be replayed.
- **Secrets**: set `SURREALENGINE_AUTH_SECRET`. Without it a random secret is
  generated per process, and every token and API key stops working on restart.
- **Python 3.11+** and **surrealengine 2.x** are required.

## 8. Embedded databases: the on-disk format changed

This one is not caused by this package, but it will stop an upgrade in its
tracks.

`surrealengine` 2.x depends on SurrealDB 3, and SurrealDB 3 cannot open the
on-disk stores that SurrealDB 1.x wrote. An embedded database created by an
older release fails to open:

```
Unsupported manifest format version: 0
```

That is the manifest of a 1.x store. It is not a corruption, and nothing in
the old file is readable by the new engine — the format itself changed.

**If you use an embedded store** (`file://`, `surrealkv://`), move the old
data directory aside and let the new engine create a fresh one:

```bash
mv ./my-surreal-data ./my-surreal-data.surrealdb1
```

Then start the application, which seeds a new store, and migrate the data you
need across with `EXPORT` / `IMPORT` from a 1.x instance before you retire
it. If the embedded store was only ever a cache, deleting it is enough.

**If you use a remote SurrealDB** (`ws://`, `wss://`, `http://`, `https://`),
nothing on disk changes and this section does not apply — but check the
server's own upgrade notes, since the wire protocol also moved between 1.x
and 3.x.

## 9. Checklist

1. Set `SURREALENGINE_AUTH_SECRET`.
2. Upgrade, then call `setup_database()` once.
3. Log in as a 0.1.x user and confirm `password_hash` is now Argon2id.
4. Re-issue API keys. Old ones stop working.
5. Find any `if user:` after `authenticate` — it now raises.
6. Find any `register_user` call that used the returned user without
   checking `created`.
7. Update audit queries to the emitted event names.
8. If you use an embedded store, move the old data directory aside (see
   section 8).

`tests/test_migration.py` covers all of the above against a database built to
look like 0.1.x. Run it against your own data if you want to be sure:

```python
user = SurrealEngineAuth.get_user_by_username("an_existing_username")
```
