from __future__ import annotations

import datetime
import time
import typing
import uuid
from enum import Enum
from typing import (Any, Callable, Literal, Mapping, Optional, Sequence,
                    TypeVar, Union)

from .exceptions import ProxyError, RemoteProtocolError, TooManyRedirects
from .models import (URL, Auth, BasicAuth, Cookies, HeaderRotator, Headers,
                     Proxy, ProxyRotator, Request, Response, StatusCodes,
                     TLSClient, TLSConfig, TLSIdentifierRotator, URLParams)
from .settings import (DEFAULT_FOLLOW_REDIRECTS, DEFAULT_HEADERS,
                       DEFAULT_MAX_REDIRECTS, DEFAULT_TIMEOUT,
                       DEFAULT_TLS_HTTP2, DEFAULT_TLS_IDENTIFIER)
from .types import (AuthTypes, CookieTypes, HeaderTypes, HookTypes,
                    ProtocolTypes, ProxyTypes, RequestData, RequestFiles,
                    TimeoutTypes, TLSIdentifierTypes, URLParamTypes, URLTypes)
from .utils import get_logger

__all__ = ["AsyncClient", "Client"]

T = TypeVar("T", bound="Client")
A = TypeVar("A", bound="AsyncClient")


logger = get_logger("TLSRequests")


class ProtocolType(str, Enum):
    AUTO = "auto"
    HTTP1 = "http1"
    HTTP2 = "http2"


class ClientState(int, Enum):
    UNOPENED = 1
    OPENED = 2
    CLOSED = 3


class BaseClient:
    """
    A TLS-enabled HTTP client supporting advanced configuration options, including headers, cookies,
    URL parameters, and proxy settings. It provides seamless HTTP/1.1 and HTTP/2 support with optional
    authentication and robust redirect handling.

    Attributes:
        auth (Optional[AuthTypes]): Authentication options (e.g., tuples for basic auth, callable objects).
        params (Optional[URLParamTypes]): URL parameters to include in requests.
        headers (Optional[HeaderTypes]): Default headers for all requests.
        cookies (Optional[CookieTypes]): Default cookies for all requests.
        proxy (Optional[ProxyTypes]): Proxy configurations (e.g., proxy URL or instance).
        timeout (Optional[float | int]): Timeout for requests, in seconds.
        follow_redirects (bool): Whether to automatically follow redirects.
        max_redirects (int): Maximum number of redirects allowed.
        http2 (Optional[ProtocolTypes]): Specifies protocol options (e.g., 'auto', 'http1', 'http2', True, False, None).
        verify (bool): Whether to verify TLS certificates.
        client_identifier (Optional[TLSIdentifierTypes]): Identifier to emulate specific clients.
        encoding (str): Default encoding for response decoding.

    Methods:
        build_request: Constructs and returns a `Request` instance with provided parameters.
        prepare_headers: Merges default and custom headers for a request.
        prepare_cookies: Merges default and custom cookies for a request.
        prepare_params: Merges default and custom URL parameters for a request.
        prepare_config: Prepares TLS and other configurations for sending a request.
        close: Closes the client session and cleans up resources.

    Properties:
        - `session`: Returns the underlying TLS session object.
        - `config`: Returns the current configuration.
        - `is_closed`: Indicates if the client is closed.
        - `headers`, `cookies`, `params`: Manage default headers, cookies, and parameters.

    Lifecycle Management:
        - Use the `BaseClient` within a context manager to ensure proper resource cleanup.
        - Methods `__enter__` and `__exit__` handle opening and closing sessions automatically.
    """

    def __init__(
        self,
        *,
        auth: AuthTypes = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        proxy: ProxyTypes = None,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        http2: ProtocolTypes = DEFAULT_TLS_HTTP2,
        verify: bool = True,
        client_identifier: Optional[TLSIdentifierTypes] = DEFAULT_TLS_IDENTIFIER,
        hooks: HookTypes = None,
        encoding: str = "utf-8",
        **config,
    ) -> None:
        self._session = TLSClient.initialize()
        self._config = TLSConfig.from_kwargs(**config)
        self._params = URLParams(params)
        self._cookies = Cookies(cookies)
        self._state = ClientState.UNOPENED
        self._header_rotator: Optional[HeaderRotator] = None
        self._headers: Headers = Headers()
        if isinstance(headers, HeaderRotator):
            self._header_rotator = headers
        elif isinstance(headers, list):
            self._header_rotator = HeaderRotator.from_file(headers)
        elif headers is not None:
            self._headers = Headers(headers)
        self._hooks = hooks if isinstance(hooks, dict) else {}
        self.auth = auth
        self.proxy = ProxyRotator.from_file(proxy) if isinstance(proxy, list) else proxy
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.http2 = http2
        self.verify = verify
        self.client_identifier = (
            TLSIdentifierRotator.from_file(client_identifier)
            if isinstance(client_identifier, list)
            else client_identifier
        )
        self.encoding = encoding

    @property
    def session(self) -> TLSClient:
        return self._session

    @property
    def config(self) -> TLSConfig:
        return self._config

    @property
    def closed(self) -> bool:
        return bool(self._state == ClientState.CLOSED)

    @property
    def headers(self) -> Headers:
        for k, v in DEFAULT_HEADERS.items():
            if k not in self._headers:
                self._headers[k] = v
        return self._headers

    @headers.setter
    def headers(self, headers: HeaderTypes) -> None:
        if isinstance(headers, HeaderRotator):
            self._header_rotator = headers
        elif isinstance(headers, list):
            self._header_rotator = HeaderRotator.from_file(headers)
        elif headers is not None:
            self._headers = Headers(headers)

    @property
    def cookies(self) -> Cookies:
        return self._cookies

    @cookies.setter
    def cookies(self, cookies: CookieTypes) -> None:
        self._cookies = Cookies(cookies)

    @property
    def params(self) -> URLParams:
        return self._params

    @params.setter
    def params(self, params: URLParamTypes) -> None:
        self._params = URLParams(params)

    @property
    def hooks(self) -> Mapping[Literal["request", "response"], list[Callable]]:
        return self._hooks

    @hooks.setter
    def hooks(self, hooks: HookTypes) -> None:
        self._hooks = self._rebuild_hooks(hooks)

    def prepare_auth(self, request: Request, auth: AuthTypes, *args, **kwargs) -> Union[Request, Any]:
        """Build Auth Request instance"""

        if isinstance(auth, tuple) and len(auth) == 2:
            auth = BasicAuth(auth[0], auth[1])
            return auth.build_auth(request)

        if callable(auth):
            return auth(request)

        if isinstance(auth, Auth):
            return auth.build_auth(request)

        return auth

    def prepare_headers(self, headers: HeaderTypes = None, user_agent: Optional[str] = None) -> Headers:
        """Prepare Headers. Gets base headers from rotator if available."""
        if headers is None:
            return self.headers.copy()
        if isinstance(headers, HeaderRotator):
            return headers.next(user_agent=user_agent)
        return Headers(headers)

    def prepare_cookies(self, cookies: CookieTypes = None) -> Cookies:
        """Prepare Cookies"""

        merged_cookies = self.cookies.copy()
        return merged_cookies.update(cookies)

    def prepare_params(self, params: URLParamTypes = None) -> URLParams:
        """Prepare URL Params"""

        merged_params = self.params.copy()
        return merged_params.update(params)

    def prepare_proxy(self, proxy: ProxyTypes | None) -> Optional[Proxy]:
        if proxy is None:
            return None
        if isinstance(proxy, ProxyRotator):
            return proxy.next()
        if isinstance(proxy, (str, bytes)):
            return Proxy(proxy)
        if isinstance(proxy, Proxy):
            return proxy
        if isinstance(proxy, URL):
            return Proxy(str(proxy))
        raise ProxyError(f"Unsupported proxy type: {type(proxy)}")

    def prepare_tls_identifier(self, identifier: Optional[str, TLSIdentifierRotator]) -> str:
        if isinstance(identifier, str):
            return identifier
        if isinstance(identifier, TLSIdentifierRotator):
            return identifier.next()
        return DEFAULT_TLS_IDENTIFIER

    def prepare_config(self, request: Request, tls_identifier: str = DEFAULT_TLS_IDENTIFIER):
        """Prepare TLS Config"""

        config = self.config.copy_with(
            method=request.method,
            url=request.url,
            body=request.read(),
            headers=dict(request.headers),
            cookies=[dict(name=k, value=v) for k, v in request.cookies.items()],
            proxy=request.proxy.url if request.proxy else None,
            timeout=request.timeout,
            http2=True if self.http2 in ["auto", "http2", True, None] else False,
            verify=self.verify,
            tls_identifier=tls_identifier,
        )

        # Set Request SessionId.
        request._session_id = config.sessionId
        return config

    def build_request(
        self,
        method: str,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        timeout: TimeoutTypes = None,
    ) -> Request:
        """Build Request instance"""

        return Request(
            method,
            url,
            data=data,
            files=files,
            json=json,
            params=self.prepare_params(params),
            headers=self.prepare_headers(headers),
            cookies=self.prepare_cookies(cookies),
            proxy=self.prepare_proxy(self.proxy),
            timeout=timeout or self.timeout,
        )

    def build_hook_request(self, request: Request, *args, **kwargs) -> Union[Request, Any]:
        request_hooks = self._rebuild_hooks(self.hooks).get("request")
        if isinstance(request_hooks, Sequence):
            for hook in request_hooks:
                if callable(hook):
                    return hook(request)
        return None

    def build_hook_response(self, response: Response, *args, **kwargs) -> Union[Response, Any]:
        request_hooks = self._rebuild_hooks(self.hooks).get("response")
        if isinstance(request_hooks, Sequence):
            for hook in request_hooks:
                if callable(hook):
                    return hook(response)
        return None

    def _rebuild_hooks(self, hooks: HookTypes):
        if isinstance(hooks, dict):
            return {
                str(k).lower(): [func for func in items if callable(func)]
                for k, items in hooks.items()
                if str(k) in ["request", "response"] and isinstance(items, Sequence)
            }
        return None

    def _rebuild_redirect_request(self, request: Request, response: Response) -> Request:
        """Rebuild Redirect Request"""

        return Request(
            method=self._rebuild_redirect_method(request, response),
            url=self._rebuild_redirect_url(request, response),
            headers=request.headers,
            cookies=response.cookies,
        )

    def _rebuild_redirect_method(self, request: Request, response: Response):
        """Rebuild Redirect Method"""

        method = request.method
        if response.status_code == StatusCodes.SEE_OTHER and method != "HEAD":
            method = "GET"

        if response.status_code == StatusCodes.FOUND and method != "HEAD":
            method = "GET"

        if response.status_code == StatusCodes.MOVED_PERMANENTLY and method == "POST":
            method = "GET"

        return method

    def _rebuild_redirect_url(self, request: Request, response: Response) -> URL:
        """Rebuild Redirect URL"""

        try:
            url = URL(response.headers["Location"])
        except KeyError:
            raise RemoteProtocolError("Invalid URL in Location headers: %s" % e)

        if not url.netloc:
            for missing_field in ["scheme", "host", "port"]:
                setattr(url, missing_field, getattr(request.url, missing_field, ""))

        # TLS error transport between  HTTP/1.x -> HTTP/2
        if url.scheme != request.url.scheme:
            if request.url.scheme == "http":
                url.scheme = request.url.scheme
            else:
                if self.http2 in ["auto", None]:
                    self.session.destroy_session(self.config.sessionId)
                    self.config.sessionId = str(uuid.uuid4())
                else:
                    raise RemoteProtocolError(
                        "Switching remote scheme from HTTP/2 to HTTP/1 is not supported. Please initialize Client with"
                        " parameter `http2` to `auto`."
                    )

        setattr(url, "_url", None)  # reset url
        if not url.url:
            raise RemoteProtocolError("Invalid URL in Location headers: %s" % e)

        return url

    def _send(self, request: Request, *, history: list = None, start: float = None) -> Response:
        start = start or time.perf_counter()
        tls_identifier = self.prepare_tls_identifier(self.client_identifier)
        config = self.prepare_config(request, tls_identifier=tls_identifier)
        response = Response.from_tls_response(
            self.session.request(config.to_dict()),
            is_byte_response=config.isByteResponse,
        )
        response.request = request
        response.default_encoding = self.encoding
        response.elapsed = datetime.timedelta(seconds=time.perf_counter() - start)
        if response.is_redirect:
            response.next = self._rebuild_redirect_request(response.request, response)
            if self.follow_redirects:
                is_break = bool(len(history) < self.max_redirects)
                if not is_break:
                    raise TooManyRedirects("Too many redirects.")

                while is_break:
                    history.append(response)
                    return self._send(response.next, history=history, start=start)

        response.history = history
        return response

    def close(self) -> None:
        """Close TLS Client session."""

        self.session.destroy_session(self.config.sessionId)
        self._state = ClientState.CLOSED

    def __enter__(self: T) -> T:
        if self._state == ClientState.OPENED:
            raise RuntimeError("It is not possible to open a client instance more than once.")

        if self._state == ClientState.CLOSED:
            raise RuntimeError("The client instance cannot be reopened after it has been closed.")

        self._state = ClientState.OPENED
        return self

    def __exit__(self, *args, **kwargs) -> None:
        self.close()


class Client(BaseClient):
    """
    An HTTP client with advanced features such as connection pooling, HTTP/2 support,
    automatic redirects, and cookie persistence.

    This client is thread-safe and can be shared between threads for efficient HTTP
    interactions in multi-threaded applications.

    Usage:
        ```python
            >>> with tls_requests.AsyncClient(http2='auto', follow_redirects=True) as client:
                    response = client.get('https://httpbin.org/get')
                    response.raise_for_status()
            >>> response
            <Response [200]>
        ```

    Parameters:
        - Inherits all parameters and configurations from `tls_requests.BaseClient`.
    """

    def request(
        self,
        method: str,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ):
        """
        Constructs and sends an HTTP request.

        This method builds a `Request` object based on the given parameters, sends
        it using the configured client, and returns the server's response.

        Parameters:
            - **method** (str): HTTP method to use (e.g., `"GET"`, `"POST"`).
            - **url** (URLTypes): The URL to send the request to.
            - **params** (optional): Query parameters to include in the request URL.
            - **data** (optional): Form data to include in the request body.
            - **json** (optional): A JSON serializable object to include in the request body.
            - **headers** (optional): Custom headers to include in the request.
            - **cookies** (optional): Cookies to include with the request.
            - **files** (optional): Files to upload in a multipart request.
            - **auth** (optional): Authentication credentials or handler.
            - **timeout** (optional): Timeout configuration for the request.
            - **follow_redirects** (optional): Whether to follow HTTP redirects.

        Returns:
            - **Response**: The client's response to the HTTP request.

        Usage:
            ```python
                >>> r = client.request('GET', 'https://httpbin.org/get')
                >>> r
                <Response [200]>
            ```
        """

        request = self.build_request(
            method=method,
            url=url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
        )
        return self.send(request, auth=auth, follow_redirects=follow_redirects)

    def send(
        self,
        request: Request,
        *,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    ):
        if self._state == ClientState.CLOSED:
            raise RuntimeError("Cannot send a request, as the client has been closed.")

        self._state = ClientState.OPENED
        for fn in [self.prepare_auth, self.build_hook_request]:
            request_ = fn(request, auth or self.auth, follow_redirects)
            if isinstance(request_, Request):
                request = request_

        self.follow_redirects = follow_redirects
        response = self._send(request, start=time.perf_counter(), history=[])

        if isinstance(self.proxy, ProxyRotator) and response.request.proxy:
            proxy_success = 200 <= response.status_code < 500 and response.status_code not in [407]
            self.proxy.mark_result(
                proxy=response.request.proxy,
                success=proxy_success,
                latency=response.elapsed,
            )

        if self.hooks.get("response"):
            response_ = self.build_hook_response(response)
            if isinstance(response_, Response):
                response = response_
        else:
            response.read()

        response.close()
        return response

    def get(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ):
        """
        Send a `GET` request.

        **Parameters**: See `tls_requests.request`.
        """
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def options(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send an `OPTIONS` request.

        **Parameters**: See `tls_requests.request`.
        """
        return self.request(
            "OPTIONS",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def head(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `HEAD` request.

        **Parameters**: See `tls_requests.request`.
        """
        return self.request(
            "HEAD",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def post(
        self,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `POST` request.

        **Parameters**: See `tls_requests.request`.
        """
        return self.request(
            "POST",
            url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def put(
        self,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `PUT` request.

        **Parameters**: See `tls_requests.request`.
        """
        return self.request(
            "PUT",
            url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def patch(
        self,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `PATCH` request.

        **Parameters**: See `tls_requests.request`.
        """
        return self.request(
            "PATCH",
            url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def delete(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `DELETE` request.

        **Parameters**: See `tls_requests.request`.
        """
        return self.request(
            "DELETE",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )


class AsyncClient(BaseClient):
    """
    An asynchronous HTTP client, with connection pooling, HTTP/2, redirects,
    cookie persistence, etc.

    It can be shared between tasks.

    Usage:

    ```python
    >>> import asyncio
    >>> async def fetch(url: str, params: URLParamTypes = None)
            async with tls_requests.AsyncClient(http2='auto', follow_redirects=True) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
                return response
    >>> response = asyncio.run(fetch('https://httpbin.org/get'))
    ```

    **Parameters:** See `tls_requests.BaseClient`.
    """

    async def aprepare_headers(self, headers: HeaderTypes = None, user_agent: Optional[str] = None) -> Headers:
        """Prepare Headers. Gets base headers from rotator if available."""
        if headers is None:
            return self.headers.copy()
        if isinstance(headers, HeaderRotator):
            return await headers.anext(user_agent=user_agent)
        return Headers(headers)

    async def aprepare_proxy(self, proxy: ProxyTypes | None) -> Optional[Proxy]:
        if proxy is None:
            return None
        if isinstance(proxy, ProxyRotator):
            return await proxy.anext()
        if isinstance(proxy, (str, bytes)):
            return Proxy(proxy)
        if isinstance(proxy, Proxy):
            return proxy
        if isinstance(proxy, URL):
            return Proxy(str(proxy))
        raise ProxyError(f"Unsupported proxy type: {type(proxy)}")

    async def aprepare_tls_identifier(self, identifier) -> str:
        if isinstance(identifier, str):
            return identifier
        if isinstance(identifier, TLSIdentifierRotator):
            return await identifier.anext()
        return DEFAULT_TLS_IDENTIFIER

    async def abuild_request(
        self,
        method: str,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        timeout: TimeoutTypes = None,
    ) -> Request:
        headers = await self.aprepare_headers(headers)
        proxy = await self.aprepare_proxy(self.proxy)
        return Request(
            method,
            url,
            data=data,
            files=files,
            json=json,
            params=self.prepare_params(params),
            headers=headers,
            cookies=self.prepare_cookies(cookies),
            proxy=proxy,
            timeout=timeout or self.timeout,
        )

    async def request(
        self,
        method: str,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """Async Request"""

        request = await self.abuild_request(
            method=method,
            url=url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
        )
        return await self.send(request, auth=auth, follow_redirects=follow_redirects)

    async def get(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `GET` request.

        **Parameters**: See `tls_requests.request`.
        """
        return await self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    async def options(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send an `OPTIONS` request.

        **Parameters**: See `tls_requests.request`.
        """
        return await self.request(
            "OPTIONS",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    async def head(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `HEAD` request.

        **Parameters**: See `tls_requests.request`.
        """
        return await self.request(
            "HEAD",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    async def post(
        self,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `POST` request.

        **Parameters**: See `tls_requests.request`.
        """
        return await self.request(
            "POST",
            url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    async def put(
        self,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `PUT` request.

        **Parameters**: See `tls_requests.request`.
        """
        return await self.request(
            "PUT",
            url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    async def patch(
        self,
        url: URLTypes,
        *,
        data: RequestData = None,
        files: RequestFiles = None,
        json: typing.Any = None,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `PATCH` request.

        **Parameters**: See `tls_requests.request`.
        """
        return await self.request(
            "PATCH",
            url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    async def delete(
        self,
        url: URLTypes,
        *,
        params: URLParamTypes = None,
        headers: HeaderTypes = None,
        cookies: CookieTypes = None,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Response:
        """
        Send a `DELETE` request.

        **Parameters**: See `tls_requests.request`.
        """
        return await self.request(
            "DELETE",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    async def send(
        self,
        request: Request,
        *,
        stream: bool = False,
        auth: AuthTypes = None,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    ) -> Response:
        if self._state == ClientState.CLOSED:
            pass  # pass duplicated code
            raise RuntimeError("Cannot send a request, as the client has been closed.")

        self._state = ClientState.OPENED
        for fn in [self.prepare_auth, self.build_hook_request]:
            request_ = fn(request, auth or self.auth, follow_redirects)
            if isinstance(request_, Request):
                request = request_

        self.follow_redirects = follow_redirects
        response = await self._send(request, start=time.perf_counter(), history=[])

        if isinstance(self.proxy, ProxyRotator) and response.request.proxy:
            proxy_success = 200 <= response.status_code < 500 and response.status_code not in [407]
            await self.proxy.amark_result(
                proxy=response.request.proxy,
                success=proxy_success,
                latency=response.elapsed,
            )

        if self.hooks.get("response"):
            response_ = self.build_hook_response(response)
            if isinstance(response_, Response):
                response = response_
        else:
            await response.aread()

        await response.aclose()
        return response

    async def _send(self, request: Request, *, history: list = None, start: float = None) -> Response:
        start = start or time.perf_counter()
        tls_identifier = await self.aprepare_tls_identifier(self.client_identifier)
        config = self.prepare_config(request, tls_identifier=tls_identifier)
        response = Response.from_tls_response(
            await self.session.arequest(config.to_dict()),
            is_byte_response=config.isByteResponse,
        )
        response.request = request
        response.default_encoding = self.encoding
        response.elapsed = datetime.timedelta(seconds=time.perf_counter() - start)
        if response.is_redirect:
            response.next = self._rebuild_redirect_request(response.request, response)
            if self.follow_redirects:
                is_break = bool(len(history) < self.max_redirects)
                if not is_break:
                    raise TooManyRedirects("Too many redirects.")

                while is_break:
                    history.append(response)
                    return await self._send(response.next, history=history, start=start)

        response.history = history
        return response

    async def aclose(self) -> None:
        return self.close()

    async def __aenter__(self: A) -> A:
        if self._state == ClientState.OPENED:
            raise RuntimeError("It is not possible to open a client instance more than once.")

        if self._state == ClientState.CLOSED:
            raise RuntimeError("The client instance cannot be reopened after it has been closed.")

        self._state = ClientState.OPENED
        return self

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.aclose()
