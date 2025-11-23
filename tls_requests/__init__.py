from .__version__ import __description__, __title__, __version__
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
