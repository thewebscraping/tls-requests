from __future__ import annotations

from typing import Any, Optional, Union

from ..settings import DEFAULT_TIMEOUT
from ..types import (
    CookieTypes,
    HeaderTypes,
    MethodTypes,
    RequestData,
    RequestFiles,
    TimeoutTypes,
    URLParamTypes,
    URLTypes,
)
from .cookies import Cookies
from .encoders import StreamEncoder
from .headers import Headers
from .urls import URL, Proxy

__all__ = ("Request",)


class Request:
    def __init__(
        self,
        method: MethodTypes,
        url: URLTypes,
        *,
        data: Optional[RequestData] = None,
        files: Optional[RequestFiles] = None,
        json: Optional[Any] = None,
        params: URLParamTypes = None,
        headers: Optional[HeaderTypes] = None,
        cookies: CookieTypes = None,
        proxy: Optional[Union[Proxy, URL, str, bytes]] = None,
        timeout: Optional[TimeoutTypes] = None,
        protocol_racing: Optional[bool] = None,
        allow_http: Optional[bool] = None,
        stream_id: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        self._content: bytes = b""
        self._session_id: str = ""
        self._extra_config = kwargs
        self.url = URL(url, params=params)
        self.method = method.upper()
        self.cookies = Cookies(cookies)
        self.proxy = Proxy(proxy) if proxy else None
        self.timeout = timeout if isinstance(timeout, (float, int)) else DEFAULT_TIMEOUT
        self.protocol_racing = protocol_racing
        self.allow_http = allow_http
        self.stream_id = stream_id
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

    def read(self) -> bytes:
        if not self._content:
            self._content = b"".join(self.stream.render())
        return self._content

    async def aread(self) -> bytes:
        if not self._content:
            self._content = b"".join([chunk async for chunk in self.stream])
        return self._content

    def __repr__(self) -> str:
        return "<%s: (%s, %s)>" % (self.__class__.__name__, self.method, self.url)
