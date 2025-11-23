from typing import Any

from ..settings import DEFAULT_TIMEOUT
from ..types import (CookieTypes, HeaderTypes, MethodTypes, ProxyTypes,
                     RequestData, RequestFiles, TimeoutTypes, URLParamTypes,
                     URLTypes)
from .cookies import Cookies
from .encoders import StreamEncoder
from .headers import Headers
from .urls import URL, Proxy

__all__ = ["Request"]


class Request:
    def __init__(
        self,
        method: MethodTypes,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        proxy: ProxyTypes = None,
        timeout: TimeoutTypes = None,
    ) -> None:
        self._content = None
        self._session_id = None
        self.url = URL(url, params=params)
        self.method = method.upper()
        self.cookies = Cookies(cookies)
        self.proxy = Proxy(proxy) if proxy else None
        self.timeout = timeout if isinstance(timeout, (float, int)) else DEFAULT_TIMEOUT
        self.stream = StreamEncoder(data, files, json)
        self.headers = self._prepare_headers(headers)

    def _prepare_headers(self, headers) -> Headers:
        headers = Headers(headers)
        headers.update(self.stream.headers)
        if self.url.host and "Host" not in headers:
            headers.setdefault(b"Host", self.url.host)

        return headers

    @property
    def id(self):
        return self._session_id

    @property
    def content(self) -> bytes:
        return self._content

    def read(self):
        return b"".join(self.stream.render())

    async def aread(self):
        return b"".join(await self.stream.render())

    def __repr__(self) -> str:
        return "<%s: (%s, %s)>" % (self.__class__.__name__, self.method, self.url)
