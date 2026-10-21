"""
SurrealEngine Authentication and Authorization.

Targets surrealengine 2.0.0.

Setup::

    from surrealengine import create_connection
    from surrealengine_auth import SurrealEngineAuth

    create_connection("ws://localhost:8000/rpc", namespace="app",
                      database="app", username="root", password="root",
                      async_mode=False)
    SurrealEngineAuth.configure_token_secret(os.environ["AUTH_SECRET"])
    SurrealEngineAuth.setup_database()

Register and sign in::

    user, created = SurrealEngineAuth.register_user("alice", "alice@example.com", "hunter2")
    if not created:
        ...  # username or email already taken; user is None

    user = SurrealEngineAuth.authenticate("alice", "hunter2")

API keys are bare UUID4 strings, stored only as digests::

    created = SurrealEngineAuth.create_api_key(user, name="CI", scopes=["read"])
    api_key = created["api_key"]  # shown once, never recoverable again
    user = SurrealEngineAuth.authenticate_with_api_key(api_key)

Failed authentication raises :class:`AuthenticationError` rather than
returning None, so a caller cannot accidentally treat "wrong password" as
success. See :mod:`surrealengine_auth.service` for the full surface and
CHANGELOG.md for the 0.1.x migration notes.
"""

from .models import APIKey, SecurityEvent, TOTPManager, User, UserBuiltin
from .service import (
    AuthenticationError,
    LockoutError,
    PermissionDenied,
    SurrealEngineAuth,
)
from .email_service import EmailService
from .logger import SurrealEngineLogger, get_logger
from . import security

__all__ = [
    "APIKey",
    "AuthenticationError",
    "EmailService",
    "LockoutError",
    "PermissionDenied",
    "SecurityEvent",
    "SurrealEngineAuth",
    "SurrealEngineLogger",
    "TOTPManager",
    "User",
    "UserBuiltin",
    "get_logger",
    "security",
]

__version__ = "0.2.0"
