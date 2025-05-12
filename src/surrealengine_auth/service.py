from datetime import datetime, timedelta, UTC
from typing import Optional, List, Dict, Any, Tuple, Union
import os

from .models import User, APIKey, TOTPManager
from .email_service import EmailService

class AuthService:
    """
    Service class for authentication and authorization operations.
    Provides a higher-level interface for managing users and API keys.
    """

    # Initialize email service with default settings
    _email_service = None

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
    def authenticate_with_api_key(api_key: str) -> Optional[User]:
        """
        Authenticate using an API key.

        Args:
            api_key: API key string in format "id.secret"

        Returns:
            APIKey instance if authentication successful, None otherwise
        """
        check_key = APIKey.objects.get_sync(key_id=api_key)

        if not check_key or not (user := check_key.resolve_relation_sync('user_keys')) or not len(user) > 0:
            return None

        return User.objects.get_sync(email=user[0].get('email'))

    @staticmethod
    def create_api_key(user: User, name: str, expires_in_days: int = 365,
                      scopes: List[str] = None, metadata: Dict[str, Any] = None) -> Dict:
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
        user.updated_at = datetime.now(UTC)
        user.save_sync()
        return user

    @classmethod
    def send_confirmation_email(cls, user: User, base_url: str) -> bool:
        """
        Send an account confirmation email to the user.

        Args:
            user: User to send the confirmation email to
            base_url: Base URL for the confirmation link

        Returns:
            True if the email was sent successfully, False otherwise
        """
        # Generate confirmation token
        token = user.generate_confirmation_token()

        # Create confirmation link
        confirmation_link = f"{base_url.rstrip('/')}/confirm-email/{token}"

        # Send email
        return cls.get_email_service().send_confirmation_email_sync(user, confirmation_link)

    @classmethod
    def confirm_email(cls, token: str) -> Optional[User]:
        """
        Confirm a user's email address using a confirmation token.

        Args:
            token: The confirmation token

        Returns:
            The user if the confirmation was successful, None otherwise
        """
        # Verify the token and get the user
        user = User.verify_confirmation_token(token)

        if user:
            # Confirm the email
            if user.confirm_email():
                return user

        return None

    @classmethod
    def setup_two_factor(cls, user: User, method: str, phone_number: Optional[str] = None) -> Dict[str, Any]:
        """
        Set up two-factor authentication for a user.

        Args:
            user: User to set up 2FA for
            method: 2FA method ('email', 'sms', 'authenticator')
            phone_number: Phone number for SMS-based 2FA

        Returns:
            Dict with setup information (varies by method)
        """
        return user.setup_two_factor(method, phone_number)

    @classmethod
    def verify_two_factor(cls, user: User, code: str) -> bool:
        """
        Verify a two-factor authentication code.

        Args:
            user: User to verify the code for
            code: The 2FA code to verify

        Returns:
            True if the code is valid, False otherwise
        """
        return user.verify_two_factor(code)

    @classmethod
    def disable_two_factor(cls, user: User) -> None:
        """
        Disable two-factor authentication for a user.

        Args:
            user: User to disable 2FA for
        """
        user.disable_two_factor()

    @classmethod
    def send_two_factor_code(cls, user: User) -> Optional[str]:
        """
        Generate and send a two-factor authentication code.

        Args:
            user: User to send the code to

        Returns:
            The generated code if sent successfully, None otherwise
        """
        if not user.totp_secret or not user.tf_primary_method:
            return None

        # Generate code
        code = user.generate_two_factor_code()
        if not code:
            return None

        # Send code based on method
        if user.tf_primary_method == 'email':
            if cls.get_email_service().send_two_factor_code_sync(user, code):
                return code
        # SMS implementation would go here

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
    def send_passwordless_login_link(cls, user: User, base_url: str, expires_in: int = 3600) -> bool:
        """
        Generate and send a passwordless login link.

        Args:
            user: User to send the login link to
            base_url: Base URL for the login link
            expires_in: Token expiration time in seconds (default: 1 hour)

        Returns:
            True if the email was sent successfully, False otherwise
        """
        # Generate login token
        token = user.generate_login_token(expires_in)

        # Create login link
        login_link = f"{base_url.rstrip('/')}/login/{token}"

        # Send email
        return cls.get_email_service().send_passwordless_login_link_sync(user, login_link)

    @classmethod
    def authenticate_with_login_token(cls, token: str) -> Optional[User]:
        """
        Authenticate a user with a passwordless login token.

        Args:
            token: The login token

        Returns:
            The user if authentication was successful, None otherwise
        """
        return User.verify_login_token(token)

    @classmethod
    def authenticate_with_two_factor(cls, username_or_email: str, password: str, code: str) -> Optional[User]:
        """
        Authenticate a user with username/email, password, and 2FA code.

        Args:
            username_or_email: Username or email address
            password: Plain text password
            code: Two-factor authentication code

        Returns:
            User instance if authentication successful, None otherwise
        """
        # First authenticate with username/password
        user = cls.authenticate(username_or_email, password)

        # If user is authenticated and has 2FA enabled, verify the code
        if user and user.totp_secret and user.tf_primary_method:
            if user.verify_two_factor(code):
                return user
            return None

        # If user is authenticated but doesn't have 2FA enabled, return the user
        return user
