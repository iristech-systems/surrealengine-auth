"""
SurrealEngine Authentication and Authorization Module.

This module provides user and API key management for SurrealEngine applications.
It includes models, services, and API endpoints for authentication and authorization.

Example usage:

    # Import the auth module
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
    key_id, key_secret = APIKey.parse_key(formatted_key)
    api_key = APIKey.verify_key(key_id, key_secret)
    if api_key:
        user = api_key.user
        print(f"Authenticated as {user.username}")
    
    # Or use the service for authentication
    api_key = AuthService.authenticate_with_api_key(formatted_key)
    if api_key:
        user = api_key.user
        print(f"Authenticated as {user.username}")
"""

from .models import User, APIKey
from .service import AuthService

__all__ = ["User", "APIKey", "AuthService"]