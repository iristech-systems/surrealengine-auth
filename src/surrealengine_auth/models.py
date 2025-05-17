from datetime import datetime, timedelta, UTC
import uuid
import secrets
import hashlib
import base64
import io
from typing import Optional, List, Dict, Any, Union, Tuple
import asyncio
import pyotp
import qrcode
import qrcode.image.svg
from surrealengine.document import Document
from surrealengine.fields import (
    StringField, DateTimeField, BooleanField, RelationField, 
    ListField, DictField
)

class UserBuiltin(Document):
    """
    Base user model for authentication and authorization.
    This class is meant to be inherited by custom user models.
    """

    # Basic user information
    username = StringField(required=True,  )
    email = StringField(required=True,  )
    password_hash = StringField(required=True)
    salt = StringField(required=True)

    # User status
    is_active = BooleanField(default=True)
    is_admin = BooleanField(default=False)

    # Account activation
    confirmed_at = DateTimeField()

    # Two-factor authentication
    totp_secret = StringField()
    tf_primary_method = StringField()  # 'email', 'sms', 'authenticator'
    tf_phone_number = StringField()
    tf_recovery_codes = ListField(StringField())

    # Passwordless authentication
    login_token = StringField()
    login_token_expires_at = DateTimeField()

    # Timestamps
    created_at = DateTimeField(default=lambda: datetime.now(UTC))
    updated_at = DateTimeField(default=lambda: datetime.now(UTC))
    last_login = DateTimeField()

    # Additional user data
    metadata = DictField(default=dict)

    # Relation to API keys
    api_keys = Document.relates('user_keys')

    @classmethod
    def create_user(cls, username: str, email: str, password: str, 
                   is_admin: bool = False, metadata: Dict[str, Any] = None) -> "UserBuiltin":
        """
        Create a new user with hashed password (synchronous version).

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

    @classmethod
    async def create_user_async(cls, username: str, email: str, password: str, 
                   is_admin: bool = False, metadata: Dict[str, Any] = None) -> "UserBuiltin":
        """
        Create a new user with hashed password (asynchronous version).

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

        return await cls(
            username=username,
            email=email,
            password_hash=password_hash,
            salt=salt,
            is_admin=is_admin,
            metadata=metadata or {}
        ).save()

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
        """Update the user's password (synchronous version)."""
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(new_password, salt)

        self.salt = salt
        self.password_hash = password_hash
        self.updated_at = datetime.now(UTC)
        self.save_sync()

    async def update_password_async(self, new_password: str) -> None:
        """Update the user's password (asynchronous version)."""
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(new_password, salt)

        self.salt = salt
        self.password_hash = password_hash
        self.updated_at = datetime.now(UTC)
        await self.save()

    def create_api_key(self, name: str, expires_in_days: int = 365, 
                      scopes: List[str] = None, metadata: Dict[str, Any] = None) -> Dict:
        """
        Create a new API key for this user (synchronous version).

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

    async def create_api_key_async(self, name: str, expires_in_days: int = 365, 
                      scopes: List[str] = None, metadata: Dict[str, Any] = None) -> Dict:
        """
        Create a new API key for this user (asynchronous version).

        Args:
            name: Name/description of the API key
            expires_in_days: Number of days until the key expires
            scopes: List of permission scopes for this key
            metadata: Additional key data

        Returns:
            New APIKey instance
        """
        return await APIKey.create_async(
            user=self,
            name=name,
            scopes=scopes or ["read"],
            expires_at=datetime.now(UTC) + timedelta(days=expires_in_days),
            metadata=metadata or {}
        )

    def revoke_api_key(self, key_id: str) -> bool:
        """
        Revoke an API key by its ID (synchronous version).

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

    async def revoke_api_key_async(self, key_id: str) -> bool:
        """
        Revoke an API key by its ID (asynchronous version).

        Args:
            key_id: ID of the API key to revoke

        Returns:
            True if the key was found and revoked, False otherwise
        """
        key = await APIKey.objects.get(key_id=key_id)
        user_relations = await key.resolve_relation('user_keys')
        if user_relations:
            if key and self.id in [user.get('id') for user in user_relations]:
                print(key.key_id)
                await key.revoke_async()
                return True
        return False

    def get_active_api_keys(self) -> List["APIKey"]:
        """Get all active (non-expired, non-revoked) API keys for this user (synchronous version)."""
        now = datetime.now(UTC)
        return [key for key in self.resolve_relation_sync('user_keys') if key.is_active and key.expires_at > now]

    async def get_active_api_keys_async(self) -> List["APIKey"]:
        """Get all active (non-expired, non-revoked) API keys for this user (asynchronous version)."""
        now = datetime.now(UTC)
        keys = await self.resolve_relation('user_keys')
        return [key for key in keys if key.is_active and key.expires_at > now]

    class Meta:
        collection = "users"
        indexes = [
            {"name": "user_email_index", "fields": ["email"], "unique": True}
        ]


class User(UserBuiltin):
    """
    Default User model for authentication and authorization.
    Inherits all fields and methods from UserBuiltin.
    """
    pass

    # Two-factor authentication methods
    def setup_two_factor(self, method: str, phone_number: Optional[str] = None) -> Dict[str, Any]:
        """
        Set up two-factor authentication for the user (synchronous version).

        Args:
            method: The 2FA method ('email', 'sms', 'authenticator')
            phone_number: Phone number for SMS-based 2FA

        Returns:
            Dict with setup information (varies by method)
        """
        # Generate TOTP secret if not already set
        if not self.totp_secret:
            self.totp_secret = TOTPManager.generate_totp_secret()

        # Set primary method
        self.tf_primary_method = method

        # Set phone number for SMS method
        if method == 'sms' and phone_number:
            self.tf_phone_number = phone_number

        # Generate recovery codes if not already set
        if not self.tf_recovery_codes:
            self.tf_recovery_codes = TOTPManager.generate_recovery_codes()

        self.updated_at = datetime.now(UTC)
        self.save_sync()

        # Return setup information based on method
        if method == 'authenticator':
            return {
                'secret': self.totp_secret,
                'qrcode': TOTPManager.generate_qrcode(self.totp_secret, self.username),
                'recovery_codes': self.tf_recovery_codes
            }
        elif method == 'email':
            return {
                'email': self.email,
                'recovery_codes': self.tf_recovery_codes
            }
        elif method == 'sms':
            return {
                'phone_number': self.tf_phone_number,
                'recovery_codes': self.tf_recovery_codes
            }
        return {}

    async def setup_two_factor_async(self, method: str, phone_number: Optional[str] = None) -> Dict[str, Any]:
        """
        Set up two-factor authentication for the user (asynchronous version).

        Args:
            method: The 2FA method ('email', 'sms', 'authenticator')
            phone_number: Phone number for SMS-based 2FA

        Returns:
            Dict with setup information (varies by method)
        """
        # Generate TOTP secret if not already set
        if not self.totp_secret:
            self.totp_secret = TOTPManager.generate_totp_secret()

        # Set primary method
        self.tf_primary_method = method

        # Set phone number for SMS method
        if method == 'sms' and phone_number:
            self.tf_phone_number = phone_number

        # Generate recovery codes if not already set
        if not self.tf_recovery_codes:
            self.tf_recovery_codes = TOTPManager.generate_recovery_codes()

        self.updated_at = datetime.now(UTC)
        await self.save()

        # Return setup information based on method
        if method == 'authenticator':
            return {
                'secret': self.totp_secret,
                'qrcode': TOTPManager.generate_qrcode(self.totp_secret, self.username),
                'recovery_codes': self.tf_recovery_codes
            }
        elif method == 'email':
            return {
                'email': self.email,
                'recovery_codes': self.tf_recovery_codes
            }
        elif method == 'sms':
            return {
                'phone_number': self.tf_phone_number,
                'recovery_codes': self.tf_recovery_codes
            }
        return {}

    def verify_two_factor(self, code: str) -> bool:
        """
        Verify a two-factor authentication code (synchronous version).

        Args:
            code: The 2FA code to verify

        Returns:
            True if the code is valid, False otherwise
        """
        if not self.totp_secret or not self.tf_primary_method:
            return False

        # Check if it's a recovery code
        if code in self.tf_recovery_codes:
            # Remove the used recovery code
            self.tf_recovery_codes.remove(code)
            self.updated_at = datetime.now(UTC)
            self.save_sync()
            return True

        # Verify TOTP code
        return TOTPManager.verify_totp_code(self.totp_secret, code)

    async def verify_two_factor_async(self, code: str) -> bool:
        """
        Verify a two-factor authentication code (asynchronous version).

        Args:
            code: The 2FA code to verify

        Returns:
            True if the code is valid, False otherwise
        """
        if not self.totp_secret or not self.tf_primary_method:
            return False

        # Check if it's a recovery code
        if code in self.tf_recovery_codes:
            # Remove the used recovery code
            self.tf_recovery_codes.remove(code)
            self.updated_at = datetime.now(UTC)
            await self.save()
            return True

        # Verify TOTP code
        return TOTPManager.verify_totp_code(self.totp_secret, code)

    def generate_two_factor_code(self) -> Optional[str]:
        """
        Generate a two-factor authentication code.

        Returns:
            The generated code, or None if 2FA is not set up
        """
        if not self.totp_secret:
            return None

        return TOTPManager.generate_totp_code(self.totp_secret)

    def disable_two_factor(self) -> None:
        """Disable two-factor authentication for the user (synchronous version)."""
        self.totp_secret = None
        self.tf_primary_method = None
        self.tf_phone_number = None
        self.tf_recovery_codes = []
        self.updated_at = datetime.now(UTC)
        self.save_sync()

    async def disable_two_factor_async(self) -> None:
        """Disable two-factor authentication for the user (asynchronous version)."""
        self.totp_secret = None
        self.tf_primary_method = None
        self.tf_phone_number = None
        self.tf_recovery_codes = []
        self.updated_at = datetime.now(UTC)
        await self.save()

    # Account activation methods
    def generate_confirmation_token(self) -> str:
        """
        Generate a token for email confirmation.

        Returns:
            The confirmation token
        """
        # Create a unique token using user ID and email
        data = f"{self.id}:{self.email}:{secrets.token_hex(16)}"
        return base64.urlsafe_b64encode(data.encode()).decode()

    @classmethod
    def verify_confirmation_token(cls, token: str) -> Optional["User"]:
        """
        Verify a confirmation token and return the associated user (synchronous version).

        Args:
            token: The confirmation token

        Returns:
            The user if the token is valid, None otherwise
        """
        try:
            # Decode the token
            data = base64.urlsafe_b64decode(token.encode()).decode()
            user_id, email, _ = data.split(':', 2)

            # Find the user
            user = cls.objects.get_sync(id=user_id)

            # Verify the email matches
            if user and user.email == email:
                return user

        except Exception:
            pass

        return None

    @classmethod
    async def verify_confirmation_token_async(cls, token: str) -> Optional["User"]:
        """
        Verify a confirmation token and return the associated user (asynchronous version).

        Args:
            token: The confirmation token

        Returns:
            The user if the token is valid, None otherwise
        """
        try:
            # Decode the token
            data = base64.urlsafe_b64decode(token.encode()).decode()
            user_id, email, _ = data.split(':', 2)

            # Find the user
            user = await cls.objects.get(id=user_id)

            # Verify the email matches
            if user and user.email == email:
                return user

        except Exception:
            pass

        return None

    def confirm_email(self) -> bool:
        """
        Confirm the user's email address (synchronous version).

        Returns:
            True if the email was confirmed, False if already confirmed
        """
        if self.confirmed_at:
            return False

        self.confirmed_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        self.save_sync()
        return True

    async def confirm_email_async(self) -> bool:
        """
        Confirm the user's email address (asynchronous version).

        Returns:
            True if the email was confirmed, False if already confirmed
        """
        if self.confirmed_at:
            return False

        self.confirmed_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        await self.save()
        return True

    # Passwordless authentication methods
    def generate_login_token(self, expires_in: int = 3600) -> str:
        """
        Generate a token for passwordless login (synchronous version).

        Args:
            expires_in: Token expiration time in seconds (default: 1 hour)

        Returns:
            The login token
        """
        # Create a unique token
        self.login_token = secrets.token_urlsafe(32)
        self.login_token_expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        self.updated_at = datetime.now(UTC)
        self.save_sync()
        return self.login_token

    async def generate_login_token_async(self, expires_in: int = 3600) -> str:
        """
        Generate a token for passwordless login (asynchronous version).

        Args:
            expires_in: Token expiration time in seconds (default: 1 hour)

        Returns:
            The login token
        """
        # Create a unique token
        self.login_token = secrets.token_urlsafe(32)
        self.login_token_expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        self.updated_at = datetime.now(UTC)
        await self.save()
        return self.login_token

    @classmethod
    def verify_login_token(cls, token: str) -> Optional["User"]:
        """
        Verify a login token and return the associated user (synchronous version).

        Args:
            token: The login token

        Returns:
            The user if the token is valid, None otherwise
        """
        try:
            # Find the user with this token
            user = cls.objects.filter_sync(login_token=token).first_sync()

            # Check if the token is valid and not expired
            if user and user.login_token_expires_at and user.login_token_expires_at > datetime.now(UTC):
                # Clear the token
                user.login_token = None
                user.login_token_expires_at = None
                user.last_login = datetime.now(UTC)
                user.updated_at = datetime.now(UTC)
                user.save_sync()
                return user

        except Exception:
            pass

        return None

    @classmethod
    async def verify_login_token_async(cls, token: str) -> Optional["User"]:
        """
        Verify a login token and return the associated user (asynchronous version).

        Args:
            token: The login token

        Returns:
            The user if the token is valid, None otherwise
        """
        try:
            # Find the user with this token
            user = await (await cls.objects.filter(login_token=token)).first()

            # Check if the token is valid and not expired
            if user and user.login_token_expires_at and user.login_token_expires_at > datetime.now(UTC):
                # Clear the token
                user.login_token = None
                user.login_token_expires_at = None
                user.last_login = datetime.now(UTC)
                user.updated_at = datetime.now(UTC)
                await user.save()
                return user

        except Exception:
            pass

        return None


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
        Create a new API key (synchronous version).

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
    async def create_async(cls, user: User, name: str, expires_at: datetime, 
              scopes: List[str] = None, metadata: Dict[str, Any] = None) -> Dict:
        """
        Create a new API key (asynchronous version).

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

        new_key = await cls(
            key_secret=key_secret,
            name=name,
            scopes=scopes or ["read"],
            expires_at=expires_at,
            metadata=metadata or {}
        ).save()

        await new_key.relate_to('user_keys',user)
        return {'key': new_key.to_dict(),
                'user': user.to_dict()}

    @classmethod
    def verify_key(cls, key_id: str, key_secret: str) -> Optional["APIKey"]:
        """
        Verify an API key by its ID and secret (synchronous version).

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

    @classmethod
    async def verify_key_async(cls, key_id: str, key_secret: str) -> Optional["APIKey"]:
        """
        Verify an API key by its ID and secret (asynchronous version).

        Args:
            key_id: The key ID
            key_secret: The key secret

        Returns:
            APIKey instance if valid, None otherwise
        """
        try:
            key = await (await cls.objects.filter(key_id=key_id)).first()

            if not key or not key.is_active or key.revoked_at:
                return None

            if key.expires_at < datetime.now(UTC):
                return None

            if not secrets.compare_digest(key.key_secret, key_secret):
                return None

            # Update last used timestamp
            key.last_used_at = datetime.now(UTC)
            await key.save()

            return key
        except (ValueError, Exception):
            return None

    def revoke(self) -> None:
        """Revoke this API key (synchronous version)."""
        self.is_active = False
        self.revoked_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        self.save_sync()

    async def revoke_async(self) -> None:
        """Revoke this API key (asynchronous version)."""
        self.is_active = False
        self.revoked_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        await self.save()

    def refresh(self, expires_in_days: int = 365) -> None:
        """Extend the expiration of this API key (synchronous version)."""
        self.expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
        self.updated_at = datetime.now(UTC)
        self.save_sync()

    async def refresh_async(self, expires_in_days: int = 365) -> None:
        """Extend the expiration of this API key (asynchronous version)."""
        self.expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
        self.updated_at = datetime.now(UTC)
        await self.save()

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


class TOTPManager:
    """
    Manager for Time-based One-Time Password (TOTP) operations.
    Used for two-factor authentication with authenticator apps.
    """

    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def generate_totp_code(totp_secret: str) -> str:
        """Generate a TOTP code for the given secret."""
        totp = pyotp.TOTP(totp_secret)
        return totp.now()

    @staticmethod
    def verify_totp_code(totp_secret: str, code: str) -> bool:
        """Verify a TOTP code against the given secret."""
        totp = pyotp.TOTP(totp_secret)
        return totp.verify(code)

    @staticmethod
    def get_totp_uri(totp_secret: str, username: str, issuer: str = "SurrealEngineAuth") -> str:
        """Get the TOTP URI for QR code generation."""
        totp = pyotp.TOTP(totp_secret)
        return totp.provisioning_uri(username, issuer_name=issuer)

    @staticmethod
    def generate_qrcode(totp_secret: str, username: str, issuer: str = "SurrealEngineAuth") -> str:
        """Generate a QR code for the TOTP secret."""
        uri = TOTPManager.get_totp_uri(totp_secret, username, issuer)

        # Generate QR code as SVG
        qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)

        # Convert to base64 for embedding in HTML
        with io.BytesIO() as buffer:
            qr.save(buffer)
            image_data = base64.b64encode(buffer.getvalue()).decode('ascii')

        return f"data:image/svg+xml;base64,{image_data}"

    @staticmethod
    def generate_recovery_codes(count: int = 10) -> List[str]:
        """Generate recovery codes for two-factor authentication."""
        codes = []
        for _ in range(count):
            # Generate a 16-character hex code
            code = secrets.token_hex(8)
            # Format as xxxx-xxxx-xxxx-xxxx
            formatted_code = f"{code[:4]}-{code[4:8]}-{code[8:12]}-{code[12:16]}"
            codes.append(formatted_code)
        return codes
