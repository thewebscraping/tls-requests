from __future__ import annotations

from typing import Any, Optional

from .client import Client
from .models import Response
from .settings import (
    DEFAULT_ALLOW_HTTP,
    DEFAULT_CLIENT_IDENTIFIER,
    DEFAULT_DEBUG,
    DEFAULT_FOLLOW_REDIRECTS,
    DEFAULT_HTTP2,
    DEFAULT_PROTOCOL_RACING,
    DEFAULT_TIMEOUT,
)
from .types import (
    AuthTypes,
    CookieTypes,
    HeaderTypes,
    IdentifierArgTypes,
    IdentifierTypes,
    MethodTypes,
    ProtocolTypes,
    ProxyTypes,
    RequestData,
    RequestFiles,
    TimeoutTypes,
    URLParamTypes,
    URLTypes,
)

__all__ = (
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
)


def request(
    method: MethodTypes,
    url: URLTypes,
    *,
    params: URLParamTypes = None,
    data: Optional[RequestData] = None,
    files: Optional[RequestFiles] = None,
    json: Any = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierArgTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
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

    import tls_requests
                >>> with tls_requests.Client() as sync_client:
                        r = sync_client.request('GET', 'https://httpbin.org/get')
                >>> r
                <Response [200]>
            ```
    """

    with Client(
        cookies=cookies,
        proxy=proxy,
        http2=http2,
        timeout=timeout,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    ) as client:
        return client.request(
            method=method,
            url=url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            auth=auth,
            follow_redirects=follow_redirects,
            timeout=timeout,
            protocol_racing=protocol_racing,
            allow_http=allow_http,
            stream_id=stream_id,
        )


def get(
    url: URLTypes,
    *,
    params: URLParamTypes = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
    """
    Sends a `GET` request.

    **Parameters**: See `tls_requests.request`.

    Note that the `data`, `files`, `json` and `content` parameters are not available
    on this function, as `GET` requests should not include a request body.
    """
    return request(
        "GET",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        http2=http2,
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    )


def options(
    url: URLTypes,
    *,
    params: URLParamTypes = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
    """
    Sends an `OPTIONS` request.

    **Parameters**: See `tls_requests.request`.

    Note that the `data`, `files`, `json` and `content` parameters are not available
    on this function, as `OPTIONS` requests should not include a request body.
    """
    return request(
        "OPTIONS",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        http2=http2,
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    )


def head(
    url: URLTypes,
    *,
    params: URLParamTypes = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
    """
    Sends a `HEAD` request.

    **Parameters**: See `tls_requests.request`.

    Note that the `data`, `files`, `json` and `content` parameters are not available
    on this function, as `HEAD` requests should not include a request body.
    """
    return request(
        "HEAD",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        http2=http2,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    )


def post(
    url: URLTypes,
    *,
    data: Optional[RequestData] = None,
    files: Optional[RequestFiles] = None,
    json: Optional[Any] = None,
    params: URLParamTypes = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
    """
    Sends a `POST` request.

    **Parameters**: See `tls_requests.request`.
    """
    return request(
        "POST",
        url,
        data=data,
        files=files,
        json=json,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        http2=http2,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    )


def put(
    url: URLTypes,
    *,
    data: Optional[RequestData] = None,
    files: Optional[RequestFiles] = None,
    json: Optional[Any] = None,
    params: URLParamTypes = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
    """
    Sends a `PUT` request.

    **Parameters**: See `tls_requests.request`.
    """
    return request(
        "PUT",
        url,
        data=data,
        files=files,
        json=json,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        http2=http2,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    )


def patch(
    url: URLTypes,
    *,
    data: Optional[RequestData] = None,
    files: Optional[RequestFiles] = None,
    json: Optional[Any] = None,
    params: URLParamTypes = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
    """
    Sends a `PATCH` request.

    **Parameters**: See `tls_requests.request`.
    """
    return request(
        "PATCH",
        url,
        data=data,
        files=files,
        json=json,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        http2=http2,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    )


def delete(
    url: URLTypes,
    *,
    params: URLParamTypes = None,
    headers: HeaderTypes = None,
    cookies: CookieTypes = None,
    auth: AuthTypes = None,
    proxy: ProxyTypes = None,
    http2: ProtocolTypes = DEFAULT_HTTP2,
    timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
    verify: bool = True,
    client_identifier: IdentifierTypes = DEFAULT_CLIENT_IDENTIFIER,
    debug: bool = DEFAULT_DEBUG,
    protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
    allow_http: bool = DEFAULT_ALLOW_HTTP,
    stream_id: Optional[int] = None,
    **config,
) -> Response:
    """
    Sends a `DELETE` request.

    **Parameters**: See `tls_requests.request`.

    Note that the `data`, `files`, `json` and `content` parameters are not available
    on this function, as `DELETE` requests should not include a request body.
    """
    return request(
        "DELETE",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        http2=http2,
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        client_identifier=client_identifier,
        debug=debug,
        protocol_racing=protocol_racing,
        allow_http=allow_http,
        stream_id=stream_id,
        **config,
    )
