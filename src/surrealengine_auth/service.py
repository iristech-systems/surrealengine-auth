from datetime import datetime, timedelta, UTC
from typing import Optional, List, Dict, Any, Tuple, Union, Type
import os

from .models import User, UserBuiltin, APIKey, TOTPManager, SecurityEvent
from .email_service import EmailService

class SurrealEngineAuth:
    """
    Service class for authentication and authorization operations.
    Provides a higher-level interface for managing users and API keys.
    """

    # Initialize email service with default settings
    _email_service = None

    # Default user class
    _user_class = User

    @classmethod
    def get_email_service(cls) -> EmailService:
        """Get the email service instance, creating it if necessary."""
        if cls._email_service is None:
            # Default email service configuration
            cls._email_service = EmailService(
                smtp_host=os.environ.get("SMTP_HOST", "localhost"),
                smtp_port=int(os.environ.get("SMTP_PORT", "25")),
                smtp_username=os.environ.get("SMTP_USERNAME"),
                smtp_password=os.environ.get("SMTP_PASSWORD"),
                use_tls=os.environ.get("SMTP_USE_TLS", "False").lower() == "true",
                use_ssl=os.environ.get("SMTP_USE_SSL", "False").lower() == "true",
                default_sender=os.environ.get("SMTP_SENDER", "noreply@example.com")
            )
        return cls._email_service

    @classmethod
    def configure_email_service(cls, **kwargs) -> None:
        """Configure the email service with custom settings."""
        cls._email_service = EmailService(**kwargs)

    @classmethod
    def configure_user_class(cls, user_class: Type[UserBuiltin]) -> None:
        """
        Configure the user class to use for authentication and authorization.

        Args:
            user_class: A class that inherits from UserBuiltin
        """
        if not issubclass(user_class, UserBuiltin):
            raise TypeError("user_class must be a subclass of UserBuiltin")
        cls._user_class = user_class

    @classmethod
    def register_user(cls, username: str, email: str, password: str, 
                     is_admin: bool = False, metadata: Dict[str, Any] = None,
                     ip_address: str = None, user_agent: str = None) -> Tuple[UserBuiltin, bool]:
        """
        Register a new user (synchronous version).

        Args:
            username: Unique username
            email: User's email address
            password: Plain text password (will be hashed)
            is_admin: Whether the user has admin privileges
            metadata: Additional user data
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            Tuple of (User, created) where created is True if a new user was created
        """
        # Check if user already exists
        existing_user = cls._user_class.objects.filter_sync(username=username).first_sync()
        if existing_user:
            return existing_user, False

        existing_email = cls._user_class.objects.filter_sync(email=email).first_sync()
        if existing_email:
            return existing_email, False

        # Create new user
        user = cls._user_class.create_user(
            username=username,
            email=email,
            password=password,
            is_admin=is_admin,
            metadata=metadata
        )

        # Log security event
        SecurityEvent.log_event(
            event_type="user_registered",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email}
        )

        return user, True

    @classmethod
    async def register_user_async(cls, username: str, email: str, password: str, 
                     is_admin: bool = False, metadata: Dict[str, Any] = None,
                     ip_address: str = None, user_agent: str = None) -> Tuple[UserBuiltin, bool]:
        """
        Register a new user (asynchronous version).

        Args:
            username: Unique username
            email: User's email address
            password: Plain text password (will be hashed)
            is_admin: Whether the user has admin privileges
            metadata: Additional user data
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            Tuple of (User, created) where created is True if a new user was created
        """
        # Check if user already exists
        existing_user = await cls._user_class.objects.filter(username=username)
        if existing_user:
            return existing_user, False

        existing_email = await cls._user_class.objects.filter(email=email)
        if existing_email:
            return existing_email, False

        # Create new user
        user = await cls._user_class.create_user_async(
            username=username,
            email=email,
            password=password,
            is_admin=is_admin,
            metadata=metadata
        )

        # Log security event
        await SecurityEvent.log_event_async(
            event_type="user_registered",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username, "email": user.email}
        )

        return user, True

    @classmethod
    def authenticate(cls, username_or_email: str, password: str, ip_address: str = None, user_agent: str = None) -> Optional[UserBuiltin]:
        """
        Authenticate a user with username/email and password (synchronous version).

        Args:
            username_or_email: Username or email address
            password: Plain text password
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            User instance if authentication successful, None otherwise
        """
        # Try to find user by username or email
        user = cls._user_class.objects.filter_sync(username=username_or_email).first_sync()
        if not user:
            user = cls._user_class.objects.filter_sync(email=username_or_email).first_sync()

        if not user or not user.is_active:

            # Log security event for failed authentication
            SecurityEvent.log_event(
                event_type="user_unauthenticated",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"identifier": username_or_email, "reason": "User not found or inactive"}
            )
            return None

        # Verify password
        if not user.verify_password(password):
            # Log security event for failed authentication
            SecurityEvent.log_event(
                event_type="user_unauthenticated",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username, "reason": "Invalid password"}
            )
            return None

        # Update last login timestamp
        user.last_login = datetime.now(UTC)
        user.save_sync()

        # Log security event for successful authentication
        SecurityEvent.log_event(
            event_type="user_authenticated",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username}
        )

        return user

    @classmethod
    async def authenticate_async(cls, username_or_email: str, password: str, ip_address: str = None, user_agent: str = None) -> Optional[UserBuiltin]:
        """
        Authenticate a user with username/email and password (asynchronous version).

        Args:
            username_or_email: Username or email address
            password: Plain text password
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            User instance if authentication successful, None otherwise
        """
        # Try to find user by username or email
        user = await cls._user_class.objects.filter(username=username_or_email).first()
        if not user:
            user = await cls._user_class.objects.filter(email=username_or_email).first()

        if not user or not user.is_active:

            # Log security event for failed authentication
            await SecurityEvent.log_event_async(
                event_type="user_unauthenticated",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"identifier": username_or_email, "reason": "User not found or inactive"}
            )
            return None

        # Verify password
        if not user.verify_password(password):
            # Log security event for failed authentication
            await SecurityEvent.log_event_async(
                event_type="user_unauthenticated",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username, "reason": "Invalid password"}
            )
            return None

        # Update last login timestamp
        user.last_login = datetime.now(UTC)
        await user.save()

        # Log security event for successful authentication
        await SecurityEvent.log_event_async(
            event_type="user_authenticated",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={"username": user.username}
        )

        return user

    @classmethod
    def authenticate_with_api_key(cls, api_key: str, ip_address: str = None, user_agent: str = None) -> Optional[UserBuiltin]:
        """
        Authenticate using an API key (synchronous version).

        Args:
            api_key: API key string in format "id.secret"
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            User instance if authentication successful, None otherwise
        """
        check_key = APIKey.objects.get_sync(key_id=api_key)

        if not check_key or not (user_data := check_key.resolve_relation_sync('user_keys')) or not len(user_data) > 0:
            # Log security event for failed API key authentication
            SecurityEvent.log_event(
                event_type="api_key_authentication_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"api_key": api_key, "reason": "Invalid API key or no associated user"}
            )
            return None

        user = cls._user_class.objects.get_sync(email=user_data[0].get('email'))
        if user:
            # Log security event for successful API key authentication
            SecurityEvent.log_event(
                event_type="api_key_authentication_succeeded",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username, "api_key": api_key}
            )

        return user

    @classmethod
    async def authenticate_with_api_key_async(cls, api_key: str, ip_address: str = None, user_agent: str = None) -> Optional[UserBuiltin]:
        """
        Authenticate using an API key (asynchronous version).

        Args:
            api_key: API key string in format "id.secret"
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            User instance if authentication successful, None otherwise
        """
        check_key = await APIKey.objects.get(key_id=api_key)

        if not check_key or not check_key.is_active or not (user_data := await check_key.resolve_relation('user_keys')) or not len(user_data) > 0:
            # Log security event for failed API key authentication
            await SecurityEvent.log_event_async(
                event_type="api_key_authentication_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"api_key": api_key, "reason": "Invalid API key or no associated user"}
            )
            return None

        user = await cls._user_class.objects.get(email=user_data[0].get('email'))
        if user:
            # Log security event for successful API key authentication
            await SecurityEvent.log_event_async(
                event_type="api_key_authentication_succeeded",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username, "api_key": api_key}
            )

        return user

    @classmethod
    def create_api_key(cls, user: UserBuiltin, name: str, expires_in_days: int = 365,
                      scopes: List[str] = None, metadata: Dict[str, Any] = None,
                      ip_address: str = None, user_agent: str = None) -> Dict:
        """
        Create a new API key for a user (synchronous version).

        Args:
            user: User that will own the key
            name: Name/description of the key
            expires_in_days: Number of days until the key expires
            scopes: List of permission scopes
            metadata: Additional key data
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            New APIKey instance
        """
        api_key = user.create_api_key(
            name=name,
            expires_in_days=expires_in_days,
            scopes=scopes,
            metadata=metadata
        )

        # Log security event for API key creation
        SecurityEvent.log_event(
            event_type="api_key_created",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "api_key_id": api_key['key_id'],
                "api_key_name": api_key['name']
            }
        )

        return api_key

    @classmethod
    async def create_api_key_async(cls, user: UserBuiltin, name: str, expires_in_days: int = 365,
                      scopes: List[str] = None, metadata: Dict[str, Any] = None,
                      ip_address: str = None, user_agent: str = None) -> Dict:
        """
        Create a new API key for a user (asynchronous version).

        Args:
            user: User that will own the key
            name: Name/description of the key
            expires_in_days: Number of days until the key expires
            scopes: List of permission scopes
            metadata: Additional key data
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            New APIKey instance
        """
        # We need to add an async version of create_api_key to the User class
        api_key = await user.create_api_key_async(
            name=name,
            expires_in_days=expires_in_days,
            scopes=scopes,
            metadata=metadata
        )

        # Log security event for API key creation
        await SecurityEvent.log_event_async(
            event_type="api_key_created",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "api_key_id": api_key['key']['key_id'],
                "api_key_name": api_key['key']['name']
            }
        )

        return api_key

    @classmethod
    def revoke_api_key(cls, user: UserBuiltin, key_id: str, 
                      ip_address: str = None, user_agent: str = None) -> bool:
        """
        Revoke an API key (synchronous version).

        Args:
            user: User that owns the key
            key_id: ID of the key to revoke
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            True if the key was found and revoked, False otherwise
        """
        result = user.revoke_api_key(key_id)

        if result:

            # Log security event for API key revocation
            SecurityEvent.log_event(
                event_type="api_key_revoked",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "api_key_id": key_id
                }
            )

        return result

    @classmethod
    async def revoke_api_key_async(cls, user: UserBuiltin, key_id: str,
                                 ip_address: str = None, user_agent: str = None) -> bool:
        """
        Revoke an API key (asynchronous version).

        Args:
            user: User that owns the key
            key_id: ID of the key to revoke
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            True if the key was found and revoked, False otherwise
        """
        # We need to add an async version of revoke_api_key to the User class
        result = await user.revoke_api_key_async(key_id)

        if result:

            # Log security event for API key revocation
            await SecurityEvent.log_event_async(
                event_type="api_key_revoked",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "api_key_id": key_id
                }
            )

        return result

    @classmethod
    def refresh_api_key(cls, api_key: APIKey, expires_in_days: int = 365,
                       ip_address: str = None, user_agent: str = None) -> APIKey:
        """
        Refresh an API key's expiration (synchronous version).

        Args:
            api_key: API key to refresh
            expires_in_days: Number of days to extend the expiration
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            Updated APIKey instance
        """
        # Store old expiration date for logging
        old_expires_at = api_key.expires_at

        # Refresh the API key
        api_key.refresh(expires_in_days)

        # Get the user associated with this API key
        user_data = api_key.resolve_relation_sync('user_keys')
        if user_data and len(user_data) > 0:
            user_id = user_data[0].get('id')
            username = user_data[0].get('username')

            # Log security event
            SecurityEvent.log_event(
                event_type="api_key_refreshed",
                user_id=str(user_id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": username,
                    "api_key_id": str(api_key.id),
                    "api_key_name": api_key.name,
                    "old_expires_at": old_expires_at.isoformat() if old_expires_at else None,
                    "new_expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                    "expires_in_days": expires_in_days
                }
            )

        return api_key

    @classmethod
    async def refresh_api_key_async(cls, api_key: APIKey, expires_in_days: int = 365,
                                  ip_address: str = None, user_agent: str = None) -> APIKey:
        """
        Refresh an API key's expiration (asynchronous version).

        Args:
            api_key: API key to refresh
            expires_in_days: Number of days to extend the expiration
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            Updated APIKey instance
        """
        # Store old expiration date for logging
        old_expires_at = api_key.expires_at

        # Refresh the API key
        await api_key.refresh_async(expires_in_days)

        # Get the user associated with this API key
        user_data = await api_key.resolve_relation('user_keys')
        if user_data and len(user_data) > 0:
            user_id = user_data[0].get('id')
            username = user_data[0].get('username')

            # Log security event
            await SecurityEvent.log_event_async(
                event_type="api_key_refreshed",
                user_id=str(user_id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": username,
                    "api_key_id": str(api_key.id),
                    "api_key_name": api_key.name,
                    "old_expires_at": old_expires_at.isoformat() if old_expires_at else None,
                    "new_expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                    "expires_in_days": expires_in_days
                }
            )

        return api_key

    @classmethod
    def get_user_by_id(cls, user_id: str, dereference: bool = False) -> Optional[UserBuiltin]:
        """
        Get a user by ID (synchronous version).

        Args:
            user_id: The ID of the user to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The user if found, None otherwise
        """
        try:
            return cls._user_class.objects.get_sync(id=user_id, dereference=dereference)
        except:
            return None

    @classmethod
    async def get_user_by_id_async(cls, user_id: str, dereference: bool = False) -> Optional[UserBuiltin]:
        """
        Get a user by ID (asynchronous version).

        Args:
            user_id: The ID of the user to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The user if found, None otherwise
        """
        try:
            return await cls._user_class.objects.get(id=user_id, dereference=dereference)
        except:
            return None

    @classmethod
    def get_user_by_username(cls, username: str, dereference: bool = False) -> Optional[UserBuiltin]:
        """
        Get a user by username (synchronous version).

        Args:
            username: The username of the user to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The user if found, None otherwise
        """
        result = cls._user_class.objects.filter_sync(username=username)
        if dereference:
            result = result.dereference()
        return result.first_sync()

    @classmethod
    async def get_user_by_username_async(cls, username: str, dereference: bool = False) -> Optional[UserBuiltin]:
        """
        Get a user by username (asynchronous version).

        Args:
            username: The username of the user to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The user if found, None otherwise
        """
        result = await cls._user_class.objects.filter(username=username)
        if dereference:
            result = result.dereference()
        return await result.first()

    @classmethod
    def get_user_by_email(cls, email: str, dereference: bool = False) -> Optional[UserBuiltin]:
        """
        Get a user by email (synchronous version).

        Args:
            email: The email of the user to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The user if found, None otherwise
        """
        result = cls._user_class.objects.filter_sync(email=email)
        if dereference:
            result = result.dereference()
        return result.first_sync()

    @classmethod
    async def get_user_by_email_async(cls, email: str, dereference: bool = False) -> Optional[UserBuiltin]:
        """
        Get a user by email (asynchronous version).

        Args:
            email: The email of the user to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The user if found, None otherwise
        """
        result = await cls._user_class.objects.filter(email=email)
        if dereference:
            result = result.dereference()
        return await result.first()

    @staticmethod
    def get_api_key(key_id: str, dereference: bool = False) -> Optional[APIKey]:
        """
        Get an API key by ID (synchronous version).

        Args:
            key_id: The ID of the API key to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The API key if found, None otherwise
        """
        try:
            result = APIKey.objects.filter_sync(key_id=key_id)
            if dereference:
                result = result.dereference()
            return result.first_sync()
        except:
            return None

    @staticmethod
    async def get_api_key_async(key_id: str, dereference: bool = False) -> Optional[APIKey]:
        """
        Get an API key by ID (asynchronous version).

        Args:
            key_id: The ID of the API key to retrieve
            dereference: Whether to automatically resolve references

        Returns:
            The API key if found, None otherwise
        """
        try:
            result = await APIKey.objects.filter(key_id=key_id)
            if dereference:
                result = result.dereference()
            return await result.first()
        except:
            return None

    @classmethod
    def list_users(cls, page_number: int = 1, page_size: int = 100) -> Dict[str, Any]:
        """
        List users with pagination (synchronous version).

        Args:
            page_number: The page number to retrieve (starting from 1)
            page_size: The number of items per page

        Returns:
            A dictionary containing the users and pagination metadata
        """
        result = cls._user_class.objects.filter_sync().page(page_number, page_size).all_sync()
        return {
            'items': result.items,
            'total': result.total,
            'page': result.page,
            'size': result.size,
            'pages': result.pages
        }

    @classmethod
    async def list_users_async(cls, page_number: int = 1, page_size: int = 100) -> Dict[str, Any]:
        """
        List users with pagination (asynchronous version).

        Args:
            page_number: The page number to retrieve (starting from 1)
            page_size: The number of items per page

        Returns:
            A dictionary containing the users and pagination metadata
        """
        result = await (await cls._user_class.objects.filter().page(page_number, page_size)).all()
        return {
            'items': result.items,
            'total': result.total,
            'page': result.page,
            'size': result.size,
            'pages': result.pages
        }

    @staticmethod
    def list_api_keys(user: UserBuiltin) -> List[APIKey]:
        """List all API keys for a user (synchronous version)."""
        return user.api_keys.get_related_documents_sync()

    @staticmethod
    async def list_api_keys_async(user: UserBuiltin) -> List[APIKey]:
        """List all API keys for a user (asynchronous version)."""
        return await user.api_keys.get_related_documents()

    @staticmethod
    def list_active_api_keys(user: UserBuiltin) -> List[APIKey]:
        """List active (non-expired, non-revoked) API keys for a user."""
        return [api_key for api_key in user.api_keys.get_related_documents_sync() if api_key.is_active]

    @classmethod
    def update_user(cls, user: UserBuiltin, ip_address: str = None, user_agent: str = None, **kwargs) -> UserBuiltin:
        """
        Update user attributes.

        Args:
            user: User to update
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)
            **kwargs: Attributes to update

        Returns:
            Updated User instance
        """
        # Track if password was changed for security event
        password_changed_flag = False

        # Keep track of updated fields for logging
        updated_fields = {}

        # Handle password separately
        if 'password' in kwargs:
            user.update_password(kwargs.pop('password'))
            password_changed_flag = True
            updated_fields['password'] = '********'  # Don't log the actual password

        # Update other attributes
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
                updated_fields[key] = value

        user.updated_at = datetime.now(UTC)
        user.save_sync()

        # Log security event for user update
        SecurityEvent.log_event(
            event_type="user_updated",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "updated_fields": updated_fields
            }
        )

        # Log security event for password change if applicable
        if password_changed_flag:
            SecurityEvent.log_event(
                event_type="password_changed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username
                }
            )

        return user

    @classmethod
    def deactivate_user(cls, user: UserBuiltin, ip_address: str = None, user_agent: str = None) -> UserBuiltin:
        """
        Deactivate a user account.

        Args:
            user: User to deactivate
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            Updated User instance
        """
        user.is_active = False
        user.updated_at = datetime.now(UTC)
        user.save_sync()

        # Revoke all active API keys
        revoked_keys = []
        for key in user.get_active_api_keys():
            key_id = str(key.id)
            key.revoke()
            revoked_keys.append(key_id)

            # Log security event for each revoked API key
            SecurityEvent.log_event(
                event_type="api_key_revoked",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "api_key_id": key_id,
                    "reason": "User account deactivated"
                }
            )

        # Log security event for user deactivation
        SecurityEvent.log_event(
            event_type="user_deactivated",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "email": user.email,
                "revoked_api_keys": revoked_keys
            }
        )

        return user

    @classmethod
    def activate_user(cls, user: UserBuiltin, ip_address: str = None, user_agent: str = None) -> UserBuiltin:
        """
        Activate a user account.

        Args:
            user: User to activate
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            Updated User instance
        """
        user.is_active = True
        user.updated_at = datetime.now(UTC)
        user.save_sync()

        # Log security event for user activation
        SecurityEvent.log_event(
            event_type="user_activated",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "email": user.email
            }
        )

        return user

    @classmethod
    def send_confirmation_email(cls, user: User, base_url: str, 
                              ip_address: str = None, user_agent: str = None) -> bool:
        """
        Send an account confirmation email to the user.

        Args:
            user: User to send the confirmation email to
            base_url: Base URL for the confirmation link
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            True if the email was sent successfully, False otherwise
        """
        # Generate confirmation token
        token = user.generate_confirmation_token()

        # Create confirmation link
        confirmation_link = f"{base_url.rstrip('/')}/confirm-email/{token}"

        # Send email
        result = cls.get_email_service().send_confirmation_email_sync(user, confirmation_link)

        # Log security event
        if result:
            SecurityEvent.log_event(
                event_type="confirmation_email_sent",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "email": user.email
                }
            )
        else:
            SecurityEvent.log_event(
                event_type="confirmation_email_send_failed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "email": user.email
                }
            )

        return result

    @classmethod
    def confirm_email(cls, token: str, ip_address: str = None, user_agent: str = None) -> Optional[User]:
        """
        Confirm a user's email address using a confirmation token.

        Args:
            token: The confirmation token
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            The user if the confirmation was successful, None otherwise
        """
        # Verify the token and get the user
        user = User.verify_confirmation_token(token)

        if not user:
            # Log security event for invalid token
            SecurityEvent.log_event(
                event_type="email_confirmation_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "reason": "Invalid or expired token"
                }
            )
            return None

        # Confirm the email
        if user.confirm_email():
            # Log security event for successful confirmation
            SecurityEvent.log_event(
                event_type="email_confirmed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "email": user.email
                }
            )
            return user
        else:
            # Log security event for confirmation failure
            SecurityEvent.log_event(
                event_type="email_confirmation_failed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "email": user.email,
                    "reason": "Email already confirmed or confirmation failed"
                }
            )
            return None

    @classmethod
    def setup_two_factor(cls, user: User, method: str, phone_number: Optional[str] = None,
                        ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """
        Set up two-factor authentication for a user.

        Args:
            user: User to set up 2FA for
            method: 2FA method ('email', 'sms', 'authenticator')
            phone_number: Phone number for SMS-based 2FA
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            Dict with setup information (varies by method)
        """
        result = user.setup_two_factor(method, phone_number)

        # Log security event
        SecurityEvent.log_event(
            event_type="two_factor_enabled",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "method": method,
                "phone_number": phone_number if method == 'sms' else None
            }
        )

        return result

    @classmethod
    def verify_two_factor(cls, user: User, code: str, 
                         ip_address: str = None, user_agent: str = None) -> bool:
        """
        Verify a two-factor authentication code.

        Args:
            user: User to verify the code for
            code: The 2FA code to verify
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            True if the code is valid, False otherwise
        """
        result = user.verify_two_factor(code)

        # Log security event
        if result:
            SecurityEvent.log_event(
                event_type="two_factor_verified",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username}
            )
        else:
            SecurityEvent.log_event(
                event_type="two_factor_verification_failed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={"username": user.username}
            )

        return result

    @classmethod
    def disable_two_factor(cls, user: User, ip_address: str = None, user_agent: str = None) -> None:
        """
        Disable two-factor authentication for a user.

        Args:
            user: User to disable 2FA for
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)
        """
        # Store the method before disabling
        method = user.tf_primary_method

        user.disable_two_factor()

        # Log security event
        SecurityEvent.log_event(
            event_type="two_factor_disabled",
            user_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "username": user.username,
                "previous_method": method
            }
        )

    @classmethod
    def send_two_factor_code(cls, user: User, ip_address: str = None, user_agent: str = None) -> Optional[str]:
        """
        Generate and send a two-factor authentication code.

        Args:
            user: User to send the code to
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            The generated code if sent successfully, None otherwise
        """
        if not user.totp_secret or not user.tf_primary_method:
            # Log security event for failure
            SecurityEvent.log_event(
                event_type="two_factor_code_send_failed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "reason": "2FA not set up properly"
                }
            )
            return None

        # Generate code
        code = user.generate_two_factor_code()
        if not code:
            # Log security event for failure
            SecurityEvent.log_event(
                event_type="two_factor_code_send_failed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "reason": "Failed to generate code"
                }
            )
            return None

        # Send code based on method
        if user.tf_primary_method == 'email':
            if cls.get_email_service().send_two_factor_code_sync(user, code):
                # Log security event for success
                SecurityEvent.log_event(
                    event_type="two_factor_code_sent",
                    user_id=str(user.id),
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "username": user.username,
                        "method": "email",
                        "email": user.email
                    }
                )
                return code
            else:
                # Log security event for failure
                SecurityEvent.log_event(
                    event_type="two_factor_code_send_failed",
                    user_id=str(user.id),
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "username": user.username,
                        "method": "email",
                        "reason": "Email sending failed"
                    }
                )
        # SMS implementation would go here
        # if user.tf_primary_method == 'sms':
        #     if send_sms_code(user.phone_number, code):
        #         # Log security event for success
        #         SecurityEvent.log_event(
        #             event_type="two_factor_code_sent",
        #             user_id=str(user.id),
        #             ip_address=ip_address,
        #             user_agent=user_agent,
        #             details={
        #                 "username": user.username,
        #                 "method": "sms",
        #                 "phone_number": user.tf_phone_number
        #             }
        #         )
        #         return code
        #     else:
        #         # Log security event for failure
        #         SecurityEvent.log_event(
        #             event_type="two_factor_code_send_failed",
        #             user_id=str(user.id),
        #             ip_address=ip_address,
        #             user_agent=user_agent,
        #             details={
        #                 "username": user.username,
        #                 "method": "sms",
        #                 "reason": "SMS sending failed"
        #             }
        #         )

        return None

    @classmethod
    def generate_qrcode(cls, user: User) -> Optional[str]:
        """
        Generate a QR code for two-factor authentication setup.

        Args:
            user: User to generate the QR code for

        Returns:
            QR code as a data URL, or None if 2FA is not set up
        """
        if not user.totp_secret:
            return None

        return TOTPManager.generate_qrcode(user.totp_secret, user.username)

    @classmethod
    def send_passwordless_login_link(cls, user: User, base_url: str, expires_in: int = 3600,
                                   ip_address: str = None, user_agent: str = None) -> bool:
        """
        Generate and send a passwordless login link.

        Args:
            user: User to send the login link to
            base_url: Base URL for the login link
            expires_in: Token expiration time in seconds (default: 1 hour)
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            True if the email was sent successfully, False otherwise
        """
        # Generate login token
        token = user.generate_login_token(expires_in)

        # Create login link
        login_link = f"{base_url.rstrip('/')}/login/{token}"

        # Send email
        result = cls.get_email_service().send_passwordless_login_link_sync(user, login_link)

        # Log security event
        if result:
            SecurityEvent.log_event(
                event_type="passwordless_login_link_sent",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "email": user.email,
                    "expires_in": expires_in
                }
            )
        else:
            SecurityEvent.log_event(
                event_type="passwordless_login_link_send_failed",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "email": user.email
                }
            )

        return result

    @classmethod
    def authenticate_with_login_token(cls, token: str, ip_address: str = None, user_agent: str = None) -> Optional[User]:
        """
        Authenticate a user with a passwordless login token.

        Args:
            token: The login token
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            The user if authentication was successful, None otherwise
        """
        user = User.verify_login_token(token)

        if user:
            # Log security event for successful authentication
            SecurityEvent.log_event(
                event_type="passwordless_login_succeeded",
                user_id=str(user.id),
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": user.username,
                    "email": user.email
                }
            )

            # Update last login timestamp
            user.last_login = datetime.now(UTC)
            user.save_sync()
        else:
            # Log security event for failed authentication
            SecurityEvent.log_event(
                event_type="passwordless_login_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "reason": "Invalid or expired token"
                }
            )

        return user

    @classmethod
    def authenticate_with_two_factor(cls, username_or_email: str, password: str, code: str, 
                                    ip_address: str = None, user_agent: str = None) -> Optional[User]:
        """
        Authenticate a user with username/email, password, and 2FA code.

        Args:
            username_or_email: Username or email address
            password: Plain text password
            code: Two-factor authentication code
            ip_address: IP address of the client (optional)
            user_agent: User agent of the client (optional)

        Returns:
            User instance if authentication successful, None otherwise
        """
        # First authenticate with username/password
        user = cls.authenticate(username_or_email, password, ip_address, user_agent)

        # If user is not authenticated, return None
        if not user:
            return None

        # If user is authenticated and has 2FA enabled, verify the code
        if user.totp_secret and user.tf_primary_method:
            if user.verify_two_factor(code):
                # Log security event for successful 2FA authentication
                SecurityEvent.log_event(
                    event_type="two_factor_authentication_succeeded",
                    user_id=str(user.id),
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "username": user.username,
                        "method": user.tf_primary_method
                    }
                )
                return user
            else:
                # Log security event for failed 2FA authentication
                SecurityEvent.log_event(
                    event_type="two_factor_authentication_failed",
                    user_id=str(user.id),
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "username": user.username,
                        "method": user.tf_primary_method,
                        "reason": "Invalid code"
                    }
                )
                return None

        # If user is authenticated but doesn't have 2FA enabled, return the user
        return user
