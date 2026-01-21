from __future__ import annotations

from base64 import b64encode
from typing import Any, Union

from ..exceptions import AuthenticationError
from .request import Request

__all__ = (
    "Auth",
    "BasicAuth",
)


class Auth:
    """Base Auth"""

    def build_auth(self, request: Request) -> Union[Request, Any]:
        pass


class BasicAuth(Auth):
    """Basic Authentication"""

    def __init__(self, username: Union[str, bytes], password: Union[str, bytes]):
        self.username = username
        self.password = password

    def build_auth(self, request: Request):
        return self._build_auth_headers(request)

    def _build_auth_headers(self, request: Request):
        auth_token = b64encode(b":".join([self._encode(self.username), self._encode(self.password)])).decode()
        request.headers["Authorization"] = "Basic %s" % auth_token

    def _encode(self, value: Union[str, bytes]) -> bytes:
        if isinstance(value, str):
            return value.encode("latin1")

        if not isinstance(value, bytes):
            raise AuthenticationError("`username` or `password` parameter must be str or byte.")

        return value
