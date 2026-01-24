from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

__all__ = (
    "AuthenticationError",
    "CookieConflictError",
    "HTTPError",
    "HeaderError",
    "ProtocolError",
    "RemoteProtocolError",
    "StreamConsumed",
    "StreamError",
    "TLSError",
    "RotatorError",
    "TooManyRedirects",
    "URLError",
)


class HTTPError(Exception):
    """HTTP Error"""

    def __init__(self, message: str, **kwargs) -> None:
        self.message = message
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(message)


class AuthenticationError(HTTPError):
    """Authentication Error"""


class HeaderError(HTTPError):
    """Header Error"""


class ProtocolError(HTTPError):
    """Protocol Error"""


class RemoteProtocolError(HTTPError):
    """Remote Protocol Error"""


class TooManyRedirects(HTTPError):
    """Too Many Redirects."""


class TLSError(HTTPError):
    """TLS Error"""


class Base64DecodeError(HTTPError):
    """Base64 Decode Error"""


class URLError(HTTPError):
    pass


class ProxyError(HTTPError):
    pass


class URLParamsError(URLError):
    pass


class CookieError(HTTPError):
    pass


class CookieConflictError(CookieError):
    pass


class StreamError(HTTPError):
    pass


class StreamConsumed(StreamError):
    pass


class StreamClosed(StreamError):
    pass


class RotatorError(HTTPError):
    pass
