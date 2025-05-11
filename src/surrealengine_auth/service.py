from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple, Union

from .models import User, APIKey

class AuthService:
    """
    Service class for authentication and authorization operations.
    Provides a higher-level interface for managing users and API keys.
    """

    @staticmethod
    def register_user(username: str, email: str, password: str, 
                     is_admin: bool = False, metadata: Dict[str, Any] = None) -> Tuple[User, bool]:
        """
        Register a new user.

        Args:
            username: Unique username
            email: User's email address
            password: Plain text password (will be hashed)
            is_admin: Whether the user has admin privileges
            metadata: Additional user data

        Returns:
            Tuple of (User, created) where created is True if a new user was created
        """
        # Check if user already exists
        existing_user = User.objects.filter_sync(username=username).first_sync()
        if existing_user:
            return existing_user, False

        existing_email = User.objects.filter_sync(email=email).first_sync()
        if existing_email:
            return existing_email, False

        # Create new user
        user = User.create_user(
            username=username,
            email=email,
            password=password,
            is_admin=is_admin,
            metadata=metadata
        )

        return user, True

    @staticmethod
    def authenticate(username_or_email: str, password: str) -> Optional[User]:
        """
        Authenticate a user with username/email and password.

        Args:
            username_or_email: Username or email address
            password: Plain text password

        Returns:
            User instance if authentication successful, None otherwise
        """
        # Try to find user by username or email
        user = User.objects.filter_sync(username=username_or_email).first_sync()
        if not user:
            user = User.objects.filter_sync(email=username_or_email).first_sync()

        if not user or not user.is_active:
            return None

        # Verify password
        if not user.verify_password(password):
            return None

        # Update last login timestamp
        user.last_login = datetime.utcnow()
        user.save_sync()

        return user

    @staticmethod
    def authenticate_with_api_key(api_key: str) -> Optional[APIKey]:
        """
        Authenticate using an API key.

        Args:
            api_key: API key string in format "id.secret"

        Returns:
            APIKey instance if authentication successful, None otherwise
        """
        check_key = APIKey.objects.get_sync(key_id=api_key)
        if not check_key or not (user := check_key.resolve_relation_sync('user')) or not len(user) > 0:
            return None

        return User.objects.get_sync(email=user[0].get('email'))

    @staticmethod
    def create_api_key(user: User, name: str, expires_in_days: int = 365,
                      scopes: List[str] = None, metadata: Dict[str, Any] = None) -> APIKey:
        """
        Create a new API key for a user.

        Args:
            user: User that will own the key
            name: Name/description of the key
            expires_in_days: Number of days until the key expires
            scopes: List of permission scopes
            metadata: Additional key data

        Returns:
            New APIKey instance
        """
        return user.create_api_key(
            name=name,
            expires_in_days=expires_in_days,
            scopes=scopes,
            metadata=metadata
        )

    @staticmethod
    def revoke_api_key(user: User, key_id: str) -> bool:
        """
        Revoke an API key.

        Args:
            user: User that owns the key
            key_id: ID of the key to revoke

        Returns:
            True if the key was found and revoked, False otherwise
        """
        return user.revoke_api_key(key_id)

    @staticmethod
    def refresh_api_key(api_key: APIKey, expires_in_days: int = 365) -> APIKey:
        """
        Refresh an API key's expiration.

        Args:
            api_key: API key to refresh
            expires_in_days: Number of days to extend the expiration

        Returns:
            Updated APIKey instance
        """
        api_key.refresh(expires_in_days)
        return api_key

    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[User]:
        """Get a user by ID."""
        try:
            return User.objects.get_sync(id=user_id)
        except:
            return None

    @staticmethod
    def get_user_by_username(username: str) -> Optional[User]:
        """Get a user by username."""
        return User.objects.filter_sync(username=username).first_sync()

    @staticmethod
    def get_user_by_email(email: str) -> Optional[User]:
        """Get a user by email."""
        return User.objects.filter_sync(email=email).first_sync()

    @staticmethod
    def get_api_key(key_id: str) -> Optional[APIKey]:
        """Get an API key by ID."""
        try:
            return APIKey.objects.filter_sync(key_id=key_id).first_sync()
        except:
            return None

    @staticmethod
    def list_users(limit: int = 100, offset: int = 0) -> List[User]:
        """List users with pagination."""
        return User.objects.filter_sync().limit(limit).start(offset).all_sync()

    @staticmethod
    def list_api_keys(user: User) -> List[APIKey]:
        """List all API keys for a user."""
        return user.resolve_relation_sync('user_keys')

    @staticmethod
    def list_active_api_keys(user: User) -> List[APIKey]:
        """List active (non-expired, non-revoked) API keys for a user."""
        return [api_key for api_key in user.resolve_relation_sync('user_keys') if api_key.is_active]

    @staticmethod
    def update_user(user: User, **kwargs) -> User:
        """
        Update user attributes.

        Args:
            user: User to update
            **kwargs: Attributes to update

        Returns:
            Updated User instance
        """
        # Handle password separately
        if 'password' in kwargs:
            user.update_password(kwargs.pop('password'))

        # Update other attributes
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)

        user.updated_at = datetime.utcnow()
        user.save_sync()
        return user

    @staticmethod
    def deactivate_user(user: User) -> User:
        """
        Deactivate a user account.

        Args:
            user: User to deactivate

        Returns:
            Updated User instance
        """
        user.is_active = False
        user.updated_at = datetime.utcnow()
        user.save_sync()

        # Revoke all active API keys
        for key in user.get_active_api_keys():
            key.revoke()

        return user

    @staticmethod
    def activate_user(user: User) -> User:
        """
        Activate a user account.

        Args:
            user: User to activate

        Returns:
            Updated User instance
        """
        user.is_active = True
        user.updated_at = datetime.utcnow()
        user.save_sync()
        return user