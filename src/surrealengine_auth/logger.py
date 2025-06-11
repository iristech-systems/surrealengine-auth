import logging
from typing import Optional, Dict, Any, Union
import os
import sys

class SurrealEngineLogger:
    """
    Logger for SurrealEngine applications.
    Provides standardized logging with configurable log levels and formats.
    """
    
    # Default log levels
    LEVELS = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    
    # Default log format
    DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    def __init__(
        self, 
        name: str = 'surrealengine_auth',
        level: str = 'info',
        format_string: Optional[str] = None,
        log_to_console: bool = True,
        log_to_file: bool = False,
        log_file_path: Optional[str] = None
    ):
        """
        Initialize the logger.
        
        Args:
            name: Logger name
            level: Log level ('debug', 'info', 'warning', 'error', 'critical')
            format_string: Log format string
            log_to_console: Whether to log to console
            log_to_file: Whether to log to file
            log_file_path: Path to log file (if log_to_file is True)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.LEVELS.get(level.lower(), logging.INFO))
        self.logger.handlers = []  # Clear existing handlers
        
        # Set format
        formatter = logging.Formatter(format_string or self.DEFAULT_FORMAT)
        
        # Add console handler
        if log_to_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # Add file handler
        if log_to_file:
            if not log_file_path:
                log_file_path = os.path.join(os.getcwd(), f'{name}.log')
            file_handler = logging.FileHandler(log_file_path)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log a debug message."""
        self.logger.debug(message, extra=extra or {})
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log an info message."""
        self.logger.info(message, extra=extra or {})
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log a warning message."""
        self.logger.warning(message, extra=extra or {})
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log an error message."""
        self.logger.error(message, extra=extra or {})
    
    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log a critical message."""
        self.logger.critical(message, extra=extra or {})
    
    def log_security_event(
        self, 
        event_type: str, 
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None, 
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            user_id: ID of the user involved
            ip_address: IP address of the client
            user_agent: User agent of the client
            details: Additional details about the event
        """
        extra = {
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details or {}
        }
        
        self.info(f"Security event: {event_type}", extra=extra)
        
        # Also log to SecurityEvent model if available
        try:
            from .models import SecurityEvent
            SecurityEvent.log_event(
                event_type=event_type,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details
            )
        except ImportError:
            pass  # SecurityEvent model not available
        except Exception as e:
            self.error(f"Failed to log security event to database: {e}")

# Create a default logger instance
default_logger = SurrealEngineLogger()

def get_logger(
    name: Optional[str] = None,
    level: Optional[str] = None,
    format_string: Optional[str] = None,
    log_to_console: Optional[bool] = None,
    log_to_file: Optional[bool] = None,
    log_file_path: Optional[str] = None
) -> SurrealEngineLogger:
    """
    Get a logger instance with the specified configuration.
    If no configuration is provided, returns the default logger.
    
    Args:
        name: Logger name
        level: Log level
        format_string: Log format string
        log_to_console: Whether to log to console
        log_to_file: Whether to log to file
        log_file_path: Path to log file
        
    Returns:
        A configured logger instance
    """
    if all(param is None for param in [name, level, format_string, log_to_console, log_to_file, log_file_path]):
        return default_logger
    
    return SurrealEngineLogger(
        name=name or default_logger.logger.name,
        level=level or 'info',
        format_string=format_string,
        log_to_console=log_to_console if log_to_console is not None else True,
        log_to_file=log_to_file if log_to_file is not None else False,
        log_file_path=log_file_path
    )