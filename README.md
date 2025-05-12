# SurrealEngine Auth

A comprehensive authentication and authorization module for SurrealEngine applications. This package provides user management, password authentication, and API key functionality for applications using SurrealDB through the SurrealEngine ORM.

## Features

- **User Management**: Create, authenticate, and manage user accounts
- **Password Security**: Secure password hashing with salt
- **API Key Management**: Create, verify, revoke, and refresh API keys
- **Permission Scopes**: Control access with customizable permission scopes
- **Expiration Control**: Set and manage expiration dates for API keys
- **Two-Factor Authentication**: Support for email, SMS, and authenticator app-based 2FA
- **Account Activation**: Email-based account activation and confirmation
- **QR Code Generation**: Generate QR codes for authenticator app setup
- **Passwordless Authentication**: Login via email links without passwords
- **Email Templates**: Customizable email templates using Jinja2

## Installation

```bash
pip install surrealengine-auth
```

## Quick Start

```python
from surrealengine.auth import AuthService, User, APIKey

# Register a new user
user, created = AuthService.register_user(
    username="johndoe",
    email="john@example.com",
    password="securepassword"
)

# Create an API key for the user
api_key = AuthService.create_api_key(
    user=user,
    name="My API Key",
    expires_in_days=365,
    scopes=["read", "write"]
)

# Get the formatted API key to provide to the user
formatted_key = api_key.formatted_key

# Later, authenticate with the API key
authenticated_user = AuthService.authenticate_with_api_key(formatted_key)
if authenticated_user:
    print(f"Authenticated as {authenticated_user.username}")
```

## User Management

### Creating Users

```python
user, created = AuthService.register_user(
    username="johndoe",
    email="john@example.com",
    password="securepassword",
    is_admin=False,
    metadata={"first_name": "John", "last_name": "Doe"}
)
```

### Authenticating Users

```python
# Authenticate with username/email and password
user = AuthService.authenticate("johndoe", "securepassword")
# or
user = AuthService.authenticate("john@example.com", "securepassword")

if user:
    print(f"Authenticated as {user.username}")
```

### Managing User Accounts

```python
# Update user information
AuthService.update_user(user, email="newemail@example.com", metadata={"phone": "123-456-7890"})

# Change password
AuthService.update_user(user, password="newpassword")

# Deactivate account
AuthService.deactivate_user(user)

# Reactivate account
AuthService.activate_user(user)
```

## API Key Management

### Creating API Keys

```python
api_key = AuthService.create_api_key(
    user=user,
    name="My API Key",
    expires_in_days=365,
    scopes=["read", "write"],
    metadata={"app": "mobile"}
)
```

### Using API Keys

```python
# Authenticate with API key
user = AuthService.authenticate_with_api_key(formatted_key)

# Check if key has specific permissions
if api_key.has_scope("write"):
    # Allow write operations
    pass
```

### Managing API Keys

```python
# List all API keys for a user
keys = AuthService.list_api_keys(user)

# List only active keys
active_keys = AuthService.list_active_api_keys(user)

# Revoke a key
AuthService.revoke_api_key(user, key_id)

# Refresh/extend a key's expiration
AuthService.refresh_api_key(api_key, expires_in_days=30)
```

## Email Configuration

```python
# Configure the email service
AuthService.configure_email_service(
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_username="username",
    smtp_password="password",
    use_tls=True,
    default_sender="noreply@example.com"
)

# Or use environment variables
# SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_USE_TLS, SMTP_SENDER
```

## Account Activation

```python
# When registering a user, send a confirmation email
user, created = AuthService.register_user(
    username="johndoe",
    email="john@example.com",
    password="securepassword"
)
if created:
    AuthService.send_confirmation_email(user, "https://example.com")

# When the user clicks the confirmation link, confirm their email
user = AuthService.confirm_email(token)
if user:
    print(f"Email confirmed for {user.username}")
```

## Two-Factor Authentication

```python
# Set up two-factor authentication
setup_info = AuthService.setup_two_factor(user, "authenticator")
qr_code = setup_info["qrcode"]  # Show this QR code to the user
recovery_codes = setup_info["recovery_codes"]  # Store these safely

# Or set up email-based 2FA
AuthService.setup_two_factor(user, "email")

# Authenticate with 2FA
user = AuthService.authenticate_with_two_factor(
    "john@example.com", 
    "password", 
    "123456"  # Code from authenticator app or email
)

# Send a 2FA code via email
code = AuthService.send_two_factor_code(user)

# Disable 2FA
AuthService.disable_two_factor(user)
```

## Passwordless Authentication

```python
# Send a passwordless login link
AuthService.send_passwordless_login_link(user, "https://example.com")

# When the user clicks the link, authenticate them
user = AuthService.authenticate_with_login_token(token)
if user:
    print(f"Authenticated as {user.username}")
```

## Requirements

- Python 3.9+
- SurrealEngine

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
