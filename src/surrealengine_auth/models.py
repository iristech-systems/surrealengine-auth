from datetime import datetime, timedelta, UTC
import uuid
import secrets
import hashlib
from typing import Optional, List, Dict, Any, Union
import asyncio
from surrealengine.document import Document
from surrealengine.fields import (
    StringField, DateTimeField, BooleanField, RelationField, 
    ListField, DictField
)

class User(Document):
    """
    User model for authentication and authorization.
    """

    # Basic user information
    username = StringField(required=True,  )
    email = StringField(required=True,  )
    password_hash = StringField(required=True)
    salt = StringField(required=True)

    # User status
    is_active = BooleanField(default=True)
    is_admin = BooleanField(default=False)

    # Timestamps
    created_at = DateTimeField(default=lambda: datetime.now(UTC))
    updated_at = DateTimeField(default=lambda: datetime.now(UTC))
    last_login = DateTimeField()

    # Additional user data
    metadata = DictField(default=dict)

    class Meta:
        collection = "users"
        indexes = [
            {"name": "user_email_index", "fields": ["email"], "unique": True}
        ]

    @classmethod
    def create_user(cls, username: str, email: str, password: str, 
                   is_admin: bool = False, metadata: Dict[str, Any] = None) -> "User":
        """
        Create a new user with hashed password.

        Args:
            username: Unique username
            email: User's email address
            password: Plain text password (will be hashed)
            is_admin: Whether the user has admin privileges
            metadata: Additional user data

        Returns:
            New User instance
        """
        salt = secrets.token_hex(16)
        password_hash = cls._hash_password(password, salt)

        return cls(
            username=username,
            email=email,
            password_hash=password_hash,
            salt=salt,
            is_admin=is_admin,
            metadata=metadata or {}
        ).save_sync()

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """Hash a password with the given salt."""
        return hashlib.pbkdf2_hmac(
            "sha256", 
            password.encode("utf-8"), 
            salt.encode("utf-8"), 
            100000
        ).hex()

    def verify_password(self, password: str) -> bool:
        """Verify if the provided password matches the stored hash."""
        hashed = self._hash_password(password, self.salt)
        return secrets.compare_digest(hashed, self.password_hash)

    def update_password(self, new_password: str) -> None:
        """Update the user's password."""
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(new_password, salt)

        self.salt = salt
        self.password_hash = password_hash
        self.updated_at = datetime.now(UTC)
        self.save_sync()

    def create_api_key(self, name: str, expires_in_days: int = 365, 
                      scopes: List[str] = None, metadata: Dict[str, Any] = None) -> Dict:
        """
        Create a new API key for this user.

        Args:
            name: Name/description of the API key
            expires_in_days: Number of days until the key expires
            scopes: List of permission scopes for this key
            metadata: Additional key data

        Returns:
            New APIKey instance
        """
        return APIKey.create(
            user=self,
            name=name,
            scopes=scopes or ["read"],
            expires_at=datetime.now(UTC) + timedelta(days=expires_in_days),
            metadata=metadata or {}
        )

    def revoke_api_key(self, key_id: str) -> bool:
        """
        Revoke an API key by its ID.

        Args:
            key_id: ID of the API key to revoke

        Returns:
            True if the key was found and revoked, False otherwise
        """
        for key in self.api_keys:
            if str(key.id) == key_id:
                key.revoke()
                return True
        return False

    def get_active_api_keys(self) -> List["APIKey"]:
        """Get all active (non-expired, non-revoked) API keys for this user."""
        now = datetime.now(UTC)
        return [key for key in self.resolve_relation_sync('user_keys') if key.is_active and key.expires_at > now]


class APIKey(Document):
    """
    API key model for authentication and authorization.
    """

    # Key information
    key_id = StringField(default=lambda: str(uuid.uuid4()), )
    key_secret = StringField(required=True)
    name = StringField(required=True)

    # Key status
    is_active = BooleanField(default=True)

    # Timestamps
    created_at = DateTimeField(default=lambda: datetime.now(UTC))
    updated_at = DateTimeField(default=lambda: datetime.now(UTC))
    expires_at = DateTimeField(required=True)
    last_used_at = DateTimeField()
    revoked_at = DateTimeField()

    # Permissions
    scopes = ListField(StringField(), default=lambda: ["read"])

    user = Document.relates('user_keys')
    # Additional key data
    metadata = DictField(default=dict)

    class Meta:
        collection = "api_keys"
        indexes = [
            {"name": "api_key_id_index", "fields": ["key_id"], "unique": True}
        ]

    @classmethod
    def create(cls, user: User, name: str, expires_at: datetime, 
              scopes: List[str] = None, metadata: Dict[str, Any] = None) -> Dict:
        """
        Create a new API key.

        Args:
            user: User that owns this key
            name: Name/description of the key
            expires_at: Expiration datetime
            scopes: List of permission scopes
            metadata: Additional key data

        Returns:
            New APIKey instance with generated key
        """
        key_secret = secrets.token_urlsafe(32)

        new_key = cls(
            key_secret=key_secret,
            name=name,
            scopes=scopes or ["read"],
            expires_at=expires_at,
            metadata=metadata or {}
        ).save_sync()

        new_key.relate_to_sync('user_keys',user)
        return {'key': new_key.to_dict(),
                'user': user.to_dict()}

    @classmethod
    def verify_key(cls, key_id: str, key_secret: str) -> Optional["APIKey"]:
        """
        Verify an API key by its ID and secret.

        Args:
            key_id: The key ID
            key_secret: The key secret

        Returns:
            APIKey instance if valid, None otherwise
        """
        try:
            key = cls.objects.filter_sync(key_id=key_id).first_sync()

            if not key or not key.is_active or key.revoked_at:
                return None

            if key.expires_at < datetime.now(UTC):
                return None

            if not secrets.compare_digest(key.key_secret, key_secret):
                return None

            # Update last used timestamp
            key.last_used_at = datetime.now(UTC)
            key.save_sync()

            return key
        except (ValueError, Exception):
            return None

    def revoke(self) -> None:
        """Revoke this API key."""
        self.is_active = False
        self.revoked_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        self.save_sync()

    def refresh(self, expires_in_days: int = 365) -> None:
        """Extend the expiration of this API key."""
        self.expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
        self.updated_at = datetime.now(UTC)
        self.save_sync()

    def has_scope(self, scope: str) -> bool:
        """Check if this API key has the specified scope."""
        return scope in self.scopes

    @property
    def is_expired(self) -> bool:
        """Check if this API key is expired."""
        return self.expires_at < datetime.now(UTC)

    @property
    def formatted_key(self) -> str:
        """Get the formatted API key (ID.secret)."""
        return f"{self.key_id}.{self.key_secret}"

    @classmethod
    def parse_key(cls, api_key: str) -> tuple:
        """
        Parse an API key string into ID and secret.

        Args:
            api_key: API key string in format "id.secret"

        Returns:
            Tuple of (key_id, key_secret)
        """
        try:
            key_id, key_secret = api_key.split(".", 1)
            return key_id, key_secret
        except ValueError:
            return None, None