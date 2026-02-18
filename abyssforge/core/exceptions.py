"""
AbyssForge Custom Exceptions
"""


class AbyssForgeError(Exception):
    """Base exception for AbyssForge."""
    pass


class ScannerError(AbyssForgeError):
    """Raised when a scanning error occurs."""
    pass


class RequestError(AbyssForgeError):
    """Raised when an HTTP request fails."""
    pass


class ModuleError(AbyssForgeError):
    """Raised when a module encounters an error."""
    pass


class ConfigError(AbyssForgeError):
    """Raised when configuration is invalid."""
    pass


class PayloadError(AbyssForgeError):
    """Raised when payload loading fails."""
    pass


class ReportError(AbyssForgeError):
    """Raised when report generation fails."""
    pass


class DatabaseError(AbyssForgeError):
    """Raised when database operations fail."""
    pass


class ValidationError(AbyssForgeError):
    """Raised when input validation fails."""
    pass


class TimeoutError(AbyssForgeError):
    """Raised when a request times out."""
    pass


class RateLimitError(AbyssForgeError):
    """Raised when rate limit is exceeded."""
    pass
