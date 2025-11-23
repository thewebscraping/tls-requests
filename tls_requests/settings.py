from __future__ import annotations

from .__version__ import __version__

CHUNK_SIZE = 65_536
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_REDIRECTS = 9
DEFAULT_FOLLOW_REDIRECTS = True
DEFAULT_TLS_DEBUG = False
DEFAULT_TLS_INSECURE_SKIP_VERIFY = False
DEFAULT_TLS_HTTP2 = "auto"
DEFAULT_TLS_IDENTIFIER = "chrome_133"
DEFAULT_HEADERS = {
    "accept": "*/*",
    "connection": "keep-alive",
    "user-agent": f"Python-TLS-Requests/{__version__}",
    "accept-encoding": "gzip, deflate, br, zstd",
}
