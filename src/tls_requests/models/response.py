from __future__ import annotations

import binascii
import codecs
import datetime
import typing
from email.message import Message
from typing import Any, Callable, Optional, TypeVar, Union

from ..exceptions import Base64DecodeError, HTTPError
from ..settings import CHUNK_SIZE
from ..types import CookieTypes, HeaderTypes, ResponseHistory
from ..utils import b64decode, chardet, to_json
from .cookies import Cookies
from .encoders import StreamEncoder
from .headers import Headers
from .request import Request
from .status_codes import StatusCodes
from .tls import TLSResponse

__all__ = ("Response",)

T = TypeVar("T", bound="Response")

REDIRECT_STATUS = (
    StatusCodes.MOVED_PERMANENTLY,  # 301
    StatusCodes.FOUND,  # 302
    StatusCodes.SEE_OTHER,  # 303
    StatusCodes.TEMPORARY_REDIRECT,  # 307
    StatusCodes.PERMANENT_REDIRECT,  # 308
)


class Response:
    def __init__(
        self,
        status_code: int,
        *,
        headers: Optional[HeaderTypes] = None,
        cookies: CookieTypes = None,
        request: Optional[Request] = None,
        history: Optional[ResponseHistory] = None,
        body: Optional[bytes] = None,
        stream: Optional[StreamEncoder] = None,
        default_encoding: Union[str, Callable[..., Any]] = "utf-8",
    ) -> None:
        self._content: bytes = b""
        self._elapsed: Optional[datetime.timedelta] = None
        self._encoding: Optional[str] = None
        self._text: Optional[str] = None
        self._response_id: str = ""
        self._http_version: str = "HTTP/1.1"
        self._request: Optional[Request] = request
        self._cookies = Cookies(cookies)
        self._is_stream_consumed = False
        self._is_closed = False
        self._next: Optional[Request] = None
        self.headers = Headers(headers)
        self.status_code = status_code
        self.history = history if isinstance(history, list) else []
        self.default_encoding = default_encoding
        self.stream: Optional[StreamEncoder] = None
        if isinstance(stream, StreamEncoder):
            self.stream = stream
        else:
            self.stream = StreamEncoder.from_bytes(body or b"", chunk_size=CHUNK_SIZE)

    @property
    def id(self) -> str:
        return self._response_id

    @property
    def elapsed(self) -> datetime.timedelta:
        return self._elapsed or datetime.timedelta(0)

    @elapsed.setter
    def elapsed(self, elapsed: datetime.timedelta) -> None:
        self._elapsed = elapsed

    @property
    def request(self) -> Request:
        if self._request is None:
            raise RuntimeError("The request instance has not been set on this response.")
        return self._request

    @request.setter
    def request(self, value: Request) -> None:
        self._request = value

    @property
    def next(self):
        return self._next

    @next.setter
    def next(self, value: Request) -> None:
        if isinstance(value, Request):
            self._next = value

    @property
    def http_version(self) -> str:
        return self._http_version or "HTTP/1.1"

    @property
    def cookies(self) -> Cookies:
        if self._request:
            # Fix missing domain in cookies by backfilling from request URL
            # Ref: https://github.com/thewebscraping/tls-requests/issues/47
            for cookie in self._cookies.cookiejar:
                if not cookie.domain:
                    cookie.domain = self._request.url.host
                    cookie.domain_specified = False
                    cookie.domain_initial_dot = False
        return self._cookies

    @property
    def reason(self) -> str:
        if self.status_code == 0:
            return self.text or StatusCodes.get_reason(self.status_code)
        return StatusCodes.get_reason(self.status_code)

    @property
    def url(self):
        return self.request.url

    @property
    def content(self) -> bytes:
        return self._content

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = ""
            if self.content:
                decoder = codecs.getincrementaldecoder(self.encoding)(errors="replace")
                self._text = decoder.decode(self.content)
        return self._text

    @property
    def charset(self) -> Optional[str]:
        if self.headers.get("Content-Type"):
            msg = Message()
            msg["content-type"] = self.headers["Content-Type"]
            return msg.get_content_charset(failobj=None)
        return None

    @property
    def encoding(self) -> str:
        if self._encoding is None:
            encoding = self.charset or self.default_encoding
            if not encoding and chardet and self.content:
                encoding = chardet.detect(self.content)["encoding"]
            try:
                if encoding:
                    # fix: charset=utf-8,gbk
                    if callable(encoding):
                        encoding = typing.cast(str, encoding(self))

                    if isinstance(encoding, str):
                        encoding = encoding.split(",")[0].strip()
                        codecs.lookup(encoding)
                        self._encoding = encoding
                else:
                    raise LookupError
            except LookupError:
                self._encoding = "utf-8"  # fallback to utf-8

        # Always ensure self._encoding is not None at this point
        if self._encoding is None:
            self._encoding = "utf-8"

        return self._encoding

    @property
    def ok(self) -> bool:
        try:
            self.raise_for_status()
        except HTTPError:
            return False
        return True

    def __bool__(self) -> bool:
        return self.ok

    @property
    def is_redirect(self) -> bool:
        return "Location" in self.headers and self.status_code in REDIRECT_STATUS

    @property
    def is_permanent_redirect(self):
        return "Location" in self.headers and self.status_code in (
            StatusCodes.MOVED_PERMANENTLY,
            StatusCodes.PERMANENT_REDIRECT,
        )

    def raise_for_status(self) -> "Response":
        http_error_msg = ""
        if self.status_code < 100:
            http_error_msg = "{0} TLS Client Error: {1} for url: {2}"

        elif 400 <= self.status_code < 500:
            http_error_msg = "{0} Client Error: {1} for url: {2}"

        elif 500 <= self.status_code < 600:
            http_error_msg = "{0} Server Error: {1} for url: {2}"

        if http_error_msg:
            raise HTTPError(
                http_error_msg.format(
                    self.status_code,
                    (self.reason if self.status_code < 100 else StatusCodes.get_reason(self.status_code)),
                    self.url,
                ),
                response=self,
            )

        return self

    def json(self, **kwargs: Any) -> Any:
        return to_json(self.text, **kwargs)

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def read(self) -> bytes:
        if self.stream is None:
            return b""
        with self.stream as stream:
            self._content = b"".join(stream.render())
            return self._content

    async def aread(self) -> bytes:
        if self.stream is None:
            return b""
        with self.stream as stream:
            self._content = b"".join([chunk async for chunk in stream])
            return self._content

    @property
    def closed(self):
        return self._is_closed

    def close(self) -> None:
        if not self._is_closed:
            self._is_closed = True
            self._is_stream_consumed = True
            if self.stream:
                self.stream.close()

        # Fix pickle dump
        # Ref: https://github.com/thewebscraping/tls-requests/issues/35
        self.stream = None

    async def aclose(self) -> None:
        return self.close()

    @classmethod
    def from_tls_response(cls, response: TLSResponse, is_byte_response: bool = False) -> "Response":
        def _parse_response_body(value: Optional[str]) -> bytes:
            if value:
                if is_byte_response and response.status > 0:
                    try:
                        content = b64decode(value.split(",")[-1])
                        return content
                    except (binascii.Error, AssertionError):
                        raise Base64DecodeError("Couldn't decode the base64 string into bytes.")
                return value.encode("utf-8")
            return b""

        ret = cls(
            status_code=response.status,
            body=_parse_response_body(response.body),
            headers=response.headers,
            cookies=response.cookies,
        )
        ret._response_id = response.id or ""
        ret._http_version = response.usedProtocol or "HTTP/1.1"
        return ret
