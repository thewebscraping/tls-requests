from __future__ import annotations

import importlib.metadata

try:
    __version__ = importlib.metadata.version("wrapper-tls-requests")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0"

__title__ = "wrapper-tls-requests"
__description__ = (
    "A powerful and lightweight Python library for making secure and reliable HTTP/TLS fingerprint requests."
)
__author__ = "Tu Pham"
__license__ = "MIT"

from .api import *
from .client import *
from .exceptions import *
from .models import *
from .settings import *
from .types import *

__all__ = [
    "__version__",
    "__author__",
    "__title__",
    "__description__",
    "AsyncClient",
    "Client",
    "Cookies",
    "CustomTLSClientConfig",
    "Headers",
    "Proxy",
    "Request",
    "Response",
    "StatusCodes",
    "TLSClient",
    "TLSConfig",
    "TLSLibrary",
    "TLSResponse",
    "URL",
    "URLParams",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
]

from .api import request

__all__ += ["request"]

__locals = locals()
for __name in __all__:
    if not __name.startswith("__"):
        setattr(__locals[__name], "__module__", "tls_requests")  # noqa
