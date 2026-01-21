from __future__ import annotations

from typing import Dict, Literal

CHUNK_SIZE: int = 65_536
DEFAULT_TIMEOUT: float = 30.0
DEFAULT_MAX_REDIRECTS: int = 9
DEFAULT_FOLLOW_REDIRECTS: bool = True
DEFAULT_DEBUG: bool = False
DEFAULT_PROTOCOL_RACING: bool = True
DEFAULT_ALLOW_HTTP: bool = False
DEFAULT_INSECURE_SKIP_VERIFY: bool = False
DEFAULT_HTTP2: Literal["auto", "http1", "http2"] = "auto"
DEFAULT_CLIENT_IDENTIFIER: str = "chrome_133"

BROWSER_HEADERS: Dict[str, Dict[str, str]] = {
    "chrome": {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br, zstd",
        "sec-ch-ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    },
    "firefox": {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
        "accept-encoding": "gzip, deflate, br, zstd",
        "upgrade-insecure-requests": "1",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
    },
    "safari": {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
    },
}
