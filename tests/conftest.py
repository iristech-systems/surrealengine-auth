"""
Shared test fixtures.

Every test runs against a real SurrealDB instance from surrealengine's
embedded engine (``mem://``), so schema generation, index enforcement, and
SurrealQL behaviour are all genuinely exercised rather than mocked.
"""

import pytest
import pytest_asyncio

from surrealengine import create_connection

from surrealengine_auth import SurrealEngineAuth, security
from surrealengine_auth.models import APIKey, SecurityEvent, User
from surrealengine_auth.service import _MEMORY_ATTEMPTS


TEST_SECRET = "test-signing-secret-0123456789abcdef"


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def async_connection():
    """An async embedded connection registered as the default."""
    conn = create_connection(
        "mem://", "auth_test", "async_db", async_mode=True, make_default=True
    )
    await conn.connect()
    for model in (User, APIKey, SecurityEvent):
        await model.create_table()
        await model.create_indexes()
    yield conn
    await conn.disconnect()


@pytest.fixture
def sync_connection():
    """A sync embedded connection registered as the default.

    Also creates the schema, since sync tests use their own database.
    """
    conn = create_connection(
        "mem://", "auth_test", "sync_db", async_mode=False, make_default=True
    )
    conn.connect()
    for model in (User, APIKey, SecurityEvent):
        model.create_table_sync()
        model.create_indexes_sync()
    yield conn
    conn.disconnect()


@pytest.fixture(autouse=True)
def reset_service_state():
    """Keep class-level configuration from leaking between tests."""
    _MEMORY_ATTEMPTS.clear()
    SurrealEngineAuth._user_class = User
    # Through the public API: the secret is also read from AppSecretConfig when
    # keying digests, and poking the private attribute skipped that.
    SurrealEngineAuth.configure_app_secret(TEST_SECRET)
    SurrealEngineAuth.max_attempts = 5
    security.TokenConfig.configure(TEST_SECRET)
    yield
    _MEMORY_ATTEMPTS.clear()


@pytest.fixture
def user(sync_connection):
    """A registered, active user."""
    created, ok = SurrealEngineAuth.register_user(
        "alice", "alice@example.com", "correct horse battery staple"
    )
    assert ok, "fixture user should be created"
    return created


@pytest_asyncio.fixture
async def async_user(async_connection):
    """A registered, active user on the async connection.

    Deliberately separate from ``async_connection``: the async path must work
    with no sync connection configured at all, which is exactly the
    configuration that broke the old lockout helpers.
    """
    created, ok = await SurrealEngineAuth.register_user_async(
        "alice", "alice@example.com", "correct horse battery staple"
    )
    assert ok, "fixture user should be created"
    return created
