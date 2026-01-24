from __future__ import annotations

import ctypes
import re
import uuid
from dataclasses import asdict, dataclass, field
from dataclasses import fields as get_fields
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, TypeVar, Union

from ..settings import (
    BROWSER_HEADERS,
    DEFAULT_ALLOW_HTTP,
    DEFAULT_CLIENT_IDENTIFIER,
    DEFAULT_DEBUG,
    DEFAULT_HTTP2,
    DEFAULT_PROTOCOL_RACING,
    DEFAULT_TIMEOUT,
)
from ..types import CookiesTypes, IdentifierTypes, MethodTypes, SessionId, URLTypes
from ..utils import to_base64, to_bytes, to_json
from .encoders import StreamEncoder
from .libraries import TLSLibrary
from .status_codes import StatusCodes

__all__ = (
    "TLSClient",
    "TLSResponse",
    "TLSConfig",
    "CustomTLSClientConfig",
    "TLSRequestCookiesConfig",
)


T = TypeVar("T", bound="_BaseConfig")


class TLSClient:
    """TLSClient

    The `TLSClient` class provides a high-level interface for performing secure TLS-based HTTP operations. It encapsulates
    interactions with a custom TLS library, offering functionality for managing sessions, cookies, and HTTP requests.
    This class is designed to be extensible and integrates seamlessly with the `TLSResponse` and `TLSConfig` classes
    for handling responses and configuring requests.

    Attributes:
        _library (Optional): Reference to the loaded TLS library.
        _getCookiesFromSession (Optional): Function for retrieving cookies from a session.
        _addCookiesToSession (Optional): Function for adding cookies to a session.
        _destroySession (Optional): Function for destroying a specific session.
        _destroyAll (Optional): Function for destroying all active sessions.
        _request (Optional): Function for performing a TLS-based HTTP request.
        _freeMemory (Optional): Function for freeing allocated memory for responses.

    Methods:
        setup(cls):
            Loads and sets up the TLS library and initializes function bindings.

        get_cookies(cls, session_id: TLSSessionId, url: str) -> TLSResponse:
            Retrieves cookies from a session for the given URL.

        add_cookies(cls, session_id: TLSSessionId, payload: dict):
            Adds cookies to a specific session.

        destroy_all(cls) -> bool:
            Destroys all active TLS sessions. Returns `True` if successful.

        destroy_session(cls, session_id: TLSSessionId) -> bool:
            Destroys a specific TLS session. Returns `True` if successful.

        request(cls, payload):
            Performs a TLS-based HTTP request with the provided payload.

        free_memory(cls, response_id: str) -> None:
            Frees the memory allocated for a specific response.

        response(cls, raw: bytes) -> TLSResponse:
            Processes a raw byte response and returns a `TLSResponse` object.

        _make_request(cls, fn: callable, payload: dict):
            Helper method to handle request processing and response generation.

    Example:
        Initialize the client and perform operations:

        >>> from tls_requests.tls import TLSClient
        >>> client = TLSClient.initialize()
        >>> session_id = "my-session-id"
        >>> url = "https://example.com"
        >>> response = client.get_cookies(session_id, url)
        >>> print(response)
    """

    _library: Optional[Any] = None
    _getCookiesFromSession: Optional[Callable] = None
    _addCookiesToSession: Optional[Callable] = None
    _destroySession: Optional[Callable] = None
    _destroyAll: Optional[Callable] = None
    _request: Optional[Callable] = None
    _freeMemory: Optional[Callable] = None

    def __init__(self) -> None:
        if self._library is None:
            self.initialize()

    @classmethod
    def initialize(cls):
        cls._library = TLSLibrary.load()
        for name in [
            "getCookiesFromSession",
            "addCookiesToSession",
            "destroySession",
            "freeMemory",
            "request",
        ]:
            fn_name = "_%s" % name
            setattr(cls, fn_name, getattr(cls._library, name, None))
            fn = getattr(cls, fn_name, None)
            if fn and callable(fn):
                fn.argtypes = [ctypes.c_char_p]  # type: ignore
                fn.restype = ctypes.c_char_p  # type: ignore

        cls._destroyAll = cls._library.destroyAll
        cls._destroyAll.restype = ctypes.c_char_p  # type: ignore
        return cls()

    @classmethod
    def get_cookies(cls, session_id: SessionId, url: str) -> "TLSResponse":
        if cls._getCookiesFromSession is None:
            cls.initialize()
        response = cls._send(cls._getCookiesFromSession, {"sessionId": session_id, "url": url})  # type: ignore[arg-type]
        return response

    @classmethod
    def add_cookies(cls, session_id: SessionId, payload: dict):
        if cls._addCookiesToSession is None:
            cls.initialize()
        payload["sessionId"] = session_id
        return cls._send(
            cls._addCookiesToSession,  # type: ignore[arg-type]
            payload,
        )

    @classmethod
    def destroy_all(cls) -> bool:
        if cls._destroyAll is None:
            cls.initialize()
        response = TLSResponse.from_bytes(cls._destroyAll())  # type: ignore[misc]
        if response.success:
            return True
        return False

    @classmethod
    def destroy_session(cls, session_id: SessionId) -> bool:
        if cls._destroySession is None:
            cls.initialize()
        response = cls._send(cls._destroySession, {"sessionId": session_id})  # type: ignore[arg-type]
        return response.success or False

    @classmethod
    def request(cls, payload):
        if cls._request is None:
            cls.initialize()
        return cls._send(cls._request, payload)  # type: ignore[arg-type]

    @classmethod
    def free_memory(cls, response_id: str) -> None:
        if cls._freeMemory is None:
            cls.initialize()
        cls._freeMemory(to_bytes(response_id))  # type: ignore[misc]

    @classmethod
    def response(cls, raw: bytes) -> "TLSResponse":
        response = TLSResponse.from_bytes(raw)
        if response.id:
            cls.free_memory(response.id)
        return response

    @classmethod
    async def aresponse(cls, raw: bytes):
        with StreamEncoder.from_bytes(raw) as stream:
            content = b"".join([chunk async for chunk in stream])
            return TLSResponse.from_kwargs(**to_json(content))

    @classmethod
    async def arequest(cls, payload):
        if cls._request is None:
            cls.initialize()
        return await cls._aread(cls._request, payload)  # type: ignore[arg-type]

    @classmethod
    def _send(cls, fn: Callable, payload: dict):
        return cls.response(fn(to_bytes(payload)))

    @classmethod
    async def _aread(cls, fn: Callable, payload: dict):
        return await cls.aresponse(fn(to_bytes(payload)))


@dataclass
class _BaseConfig:
    """Base configuration for TLSSession"""

    _extra_config: dict = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def model_fields_set(cls) -> Set[str]:
        return {model_field.name for model_field in get_fields(cls) if not model_field.name.startswith("_")}

    @classmethod
    def from_kwargs(cls: type[T], **kwargs: Any) -> T:
        model_fields_set = cls.model_fields_set()
        known_kwargs = {cls.to_camel_case(k): v for k, v in kwargs.items() if k in model_fields_set}
        extra_kwargs = {cls.to_camel_case(k): v for k, v in kwargs.items() if k not in model_fields_set}
        instance = cls(**known_kwargs)
        instance._extra_config = extra_kwargs
        return instance

    def to_dict(self) -> dict:
        data = asdict(self)
        if hasattr(self, "_extra_config"):
            data.update(self._extra_config)
        return {k: v for k, v in data.items() if not k.startswith("_") and v is not None}

    def to_payload(self) -> dict:
        return self.to_dict()

    @classmethod
    def to_camel_case(cls, name: str) -> str:
        """Convert a string to camelCase."""
        return "".join(word.capitalize() if i > 0 else word for i, word in enumerate(name.split("_")))


@dataclass
class TLSResponse(_BaseConfig):
    """TLS Response

    Attributes:
        id (Optional[str]): A unique identifier for the response. Defaults to `None`.
        sessionId (Optional[str]): The session ID associated with the response. Defaults to `None`.
        status (Optional[int]): The HTTP status code of the response. Defaults to `0`.
        target (Optional[str]): The target URL or endpoint of the response. Defaults to `None`.
        body (Optional[str]): The body content of the response. Defaults to `None`.
        headers (Optional[dict]): A dictionary containing the headers of the response. Defaults to an empty dictionary.
        cookies (Optional[dict]): A dictionary containing the cookies of the response. Defaults to an empty dictionary.
        success (Optional[bool]): Indicates if the response was successful. Defaults to `False`.
        usedProtocol (Optional[str]): The protocol used in the response. Defaults to `"HTTP/1.1"`.

    Methods:
        from_bytes(cls, raw: bytes) -> TLSResponse:
            Parses a raw byte stream and constructs a `TLSResponse` object.

        reason_phrase -> str:
            A property that provides the reason phrase associated with the HTTP status code.
            If the status code is `0`, it returns `"Bad Request"`.
    """

    id: Optional[str] = None
    sessionId: Optional[str] = None
    status: int = 0
    target: Optional[str] = None
    body: Optional[str] = None
    headers: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    usedProtocol: str = "HTTP/1.1"

    @classmethod
    def from_bytes(cls, raw: bytes) -> "TLSResponse":
        with StreamEncoder.from_bytes(raw) as stream:
            payload = b"".join(stream)
            return cls.from_kwargs(**to_json(payload))

    @property
    def reason(self) -> str:
        return StatusCodes.get_reason(self.status)

    def __repr__(self):
        return "<Response [%d]>" % self.status


@dataclass
class TLSRequestCookiesConfig(_BaseConfig):
    """
    Request Cookies Configuration

    Represents a single request cookie with a _name and value.

    Attributes:
        name (str): The _name of the cookie.
        value (str): The value of the cookie.

    Example:
        Create a `TLSRequestCookiesConfig` object:

        >>> from tls_requests.tls import TLSRequestCookiesConfig
        >>> kwargs = {
        ...     "_name": "foo2",
        ...     "value": "bar2",
        ... }
        >>> obj = TLSRequestCookiesConfig(**kwargs)
    """

    name: str
    value: str


@dataclass
class CustomTLSClientConfig(_BaseConfig):
    """
    Custom TLS Client Configuration

    The `CustomTLSClientConfig` class defines advanced configuration options for customizing TLS client behavior.
    It includes support for ALPN, ALPS protocols, certificate compression, HTTP/2 settings, JA3 fingerprints, and
    other TLS-related settings.

    Attributes:
        alpnProtocols (list[str], optional): ALPN protocols. Defaults to `None`.
        alpsProtocols (list[str], optional): ALPS protocols. Defaults to `None`.
        certCompressionAlgo (str, optional): Certificate compression algorithm. Defaults to `None`.
        connectionFlow (int, optional): Connection flow. Defaults to `None`.
        h2Settings (list[str], optional): HTTP/2 settings. Defaults to `None`.
        h2SettingsOrder (list[str], optional): Order of HTTP/2 settings. Defaults to `None`.
        headerPriority (list[str], optional): Priority of headers. Defaults to `None`.
        ja3String (str, optional): JA3 string. Defaults to `None`.
        keyShareCurves (list[str], optional): Key share curves. Defaults to `None`.
        priorityFrames (list[str], optional): Priority of frames. Defaults to `None`.
        pseudoHeaderOrder (list[str], optional): Order of pseudo headers. Defaults to `None`.
        supportedSignatureAlgorithms (list[str], optional): Supported signature algorithms. Defaults to `None`.
        supportedVersions (list[str], optional): Supported versions. Defaults to `None`.

    Example:
        Create a `CustomTLSClientConfig` instance with specific settings:

        >>> from tls_requests.tls import CustomTLSClientConfig
        >>> kwargs = {
        ...     "alpnProtocols": ["h2", "http/1.1"],
        ...     "alpsProtocols": ["h2"],
        ...     "certCompressionAlgo": "brotli",
        ...     "connectionFlow": 15663105,
        ...     "h2Settings": {
        ...         "HEADER_TABLE_SIZE": 65536,
        ...         "MAX_CONCURRENT_STREAMS": 1000,
        ...         "INITIAL_WINDOW_SIZE": 6291456,
        ...         "MAX_HEADER_LIST_SIZE": 262144
        ...     },
        ...     "h2SettingsOrder": [
        ...         "HEADER_TABLE_SIZE",
        ...         "MAX_CONCURRENT_STREAMS",
        ...         "INITIAL_WINDOW_SIZE",
        ...         "MAX_HEADER_LIST_SIZE"
        ...     ],
        ...     "headerPriority": None,
        ...     "ja3String": "771,2570-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,2570-0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-2570-21,2570-29-23-24,0",
        ...     "keyShareCurves": ["GREASE", "X25519"],
        ...     "priorityFrames": [],
        ...     "pseudoHeaderOrder": [
        ...         ":method",
        ...         ":authority",
        ...         ":scheme",
        ...         ":path"
        ...     ],
        ...     "supportedSignatureAlgorithms": [
        ...         "ECDSAWithP256AndSHA256",
        ...         "PSSWithSHA256",
        ...         "PKCS1WithSHA256",
        ...         "ECDSAWithP384AndSHA384",
        ...         "PSSWithSHA384",
        ...         "PKCS1WithSHA384",
        ...         "PSSWithSHA512",
        ...         "PKCS1WithSHA512"
        ...     ],
        ...     "supportedVersions": ["GREASE", "1.3", "1.2"]
        ... }
        >>> obj = CustomTLSClientConfig.from_kwargs(**kwargs)

    """

    alpnProtocols: Optional[List[str]] = None
    alpsProtocols: Optional[List[str]] = None
    certCompressionAlgo: Optional[str] = None
    connectionFlow: Optional[int] = None
    h2Settings: Optional[Dict[str, int]] = None
    h2SettingsOrder: Optional[List[str]] = None
    headerPriority: Optional[List[str]] = None
    ja3String: Optional[str] = None
    keyShareCurves: Optional[List[str]] = None
    priorityFrames: Optional[List[str]] = None
    pseudoHeaderOrder: Optional[List[str]] = None
    supportedSignatureAlgorithms: Optional[List[str]] = None
    supportedVersions: Optional[List[str]] = None


@dataclass
class TLSConfig(_BaseConfig):
    """TLS Configuration

    The `TLSConfig` class provides a structured and flexible way to configure TLS-specific settings for HTTP requests.
    It supports features like custom headers, cookie handling, proxy configuration, and advanced TLS options.

    Methods:
        to_dict(self) -> dict
            Converts the TLS configuration object into a dictionary.

        copy_with(self, **kwargs) -> "TLSConfig"
            Creates a new `TLSConfig` object with updated properties.

        from_kwargs(cls, **kwargs) -> "TLSConfig"
            Creates a `TLSConfig` instance from keyword arguments.

    Example:
        Initialize a `TLSConfig` object using predefined or custom settings:

        >>> from tls_requests.tls import TLSConfig
        >>> kwargs = {
        ...    "catchPanics": false,
        ...    "certificatePinningHosts": {},
        ...    "customTlsClient": {},
        ...    "followRedirects": false,
        ...    "forceHttp1": false,
        ...    "headerOrder": [
        ...        "accept",
        ...        "user-agent",
        ...        "accept-encoding",
        ...        "accept-language"
        ...    ],
        ...    "headers": {
        ...        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        ...        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        ...        "accept-encoding": "gzip, deflate, br",
        ...        "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"
        ...    },
        ...    "insecureSkipVerify": false,
        ...    "isByteRequest": false,
        ...    "isRotatingProxy": false,
        ...    "proxyUrl": "",
        ...    "requestBody": "",
        ...    "requestCookies": [
        ...        {
        ...            "_name": "foo",
        ...            "value": "bar",
        ...        },
        ...        {
        ...            "_name": "bar",
        ...            "value": "foo",
        ...        },
        ...    ],
        ...    "requestMethod": "GET",
        ...    "requestUrl": "https://microsoft.com",
        ...    "sessionId": "2my-session-id",
        ...    "timeoutSeconds": 30,
        ...    "tlsClientIdentifier": "chrome_120",
        ...    "withDebug": false,
        ...    "withDefaultCookieJar": false,
        ...    "withRandomTLSExtensionOrder": false,
        ...    "withoutCookieJar": false
        ... }
        ... >>> obj = TLSConfig.from_kwargs(**kwargs)
    """

    catchPanics: bool = False
    certificatePinningHosts: Mapping[str, str] = field(default_factory=dict)
    customTlsClient: Optional[CustomTLSClientConfig] = None
    followRedirects: bool = False
    forceHttp1: bool = False
    headerOrder: List[str] = field(default_factory=list)
    headers: Mapping[str, str] = field(default_factory=dict)
    insecureSkipVerify: bool = False
    isByteRequest: bool = False
    isByteResponse: bool = True
    isRotatingProxy: bool = False
    proxyUrl: str = ""
    requestBody: Union[str, bytes, bytearray, Optional[None]] = None
    requestCookies: List[TLSRequestCookiesConfig] = field(default_factory=list)
    requestMethod: Optional[MethodTypes] = None
    requestUrl: Optional[str] = None
    sessionId: str = field(default_factory=lambda: str(uuid.uuid4()))
    streamID: Optional[int] = None
    timeoutSeconds: int = 30
    tlsClientIdentifier: Optional[IdentifierTypes] = DEFAULT_CLIENT_IDENTIFIER
    withAllowHTTP: bool = DEFAULT_ALLOW_HTTP
    withDebug: bool = DEFAULT_DEBUG
    withDefaultCookieJar: bool = False
    withProtocolRacing: bool = DEFAULT_PROTOCOL_RACING
    withRandomTLSExtensionOrder: bool = True
    withoutCookieJar: bool = False

    def to_dict(self) -> dict:
        """Converts the TLS configuration object into a dictionary."""

        if self.customTlsClient:
            self.tlsClientIdentifier = None

        self.followRedirects = False
        if self.requestBody and isinstance(self.requestBody, (bytes, bytearray)):
            self.isByteRequest = True
            self.requestBody = to_base64(self.requestBody)
        elif self.requestBody:
            self.isByteRequest = False
        else:
            self.isByteRequest = False
            self.requestBody = None

        self.timeoutSeconds = (
            int(self.timeoutSeconds) if isinstance(self.timeoutSeconds, (float, int)) else DEFAULT_TIMEOUT
        )
        return super().to_dict()

    def copy_with(
        self,
        session_id: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: Optional[CookiesTypes] = None,
        method: Optional[MethodTypes] = None,
        url: Optional[URLTypes] = None,
        body: Optional[Union[str, bytes, bytearray]] = None,
        is_byte_request: Optional[bool] = None,
        proxy: Optional[str] = None,
        http2: Optional[bool] = None,
        timeout: Optional[Union[float, int]] = None,
        verify: Optional[bool] = None,
        client_identifier: Optional[IdentifierTypes] = None,
        debug: Optional[bool] = None,
        protocol_racing: Optional[bool] = None,
        allow_http: Optional[bool] = None,
        stream_id: Optional[int] = None,
        **kwargs: Any,
    ) -> "TLSConfig":
        """Creates a new `TLSConfig` object with updated properties."""

        mapping = {
            "sessionId": session_id,
            "headers": headers,
            "requestCookies": cookies,
            "requestMethod": method,
            "requestUrl": url,
            "requestBody": body,
            "isByteRequest": is_byte_request,
            "proxyUrl": proxy,
            "timeoutSeconds": timeout,
            "insecureSkipVerify": None if verify is None else not verify,
            "tlsClientIdentifier": client_identifier,
            "withDebug": debug,
            "withProtocolRacing": protocol_racing,
            "withAllowHTTP": allow_http,
            "streamID": stream_id,
        }
        if http2 is not None:
            mapping["forceHttp1"] = not http2

        # Filter out None values to avoid overwriting existing config with defaults
        filtered_mapping = {k: v for k, v in mapping.items() if v is not None}
        kwargs.update(filtered_mapping)

        current_kwargs = asdict(self)
        if hasattr(self, "_extra_config"):
            current_kwargs.update(self._extra_config)

        for k, v in kwargs.items():
            current_kwargs[k] = v

        return super().from_kwargs(**current_kwargs)

    @classmethod
    def from_kwargs(
        cls,
        session_id: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: Optional[CookiesTypes] = None,
        method: Optional[MethodTypes] = None,
        url: Optional[URLTypes] = None,
        body: Optional[Union[str, bytes, bytearray]] = None,
        is_byte_request: bool = False,
        proxy: Optional[str] = None,
        http2: Optional[Union[bool, str]] = DEFAULT_HTTP2,
        timeout: Union[float, int] = DEFAULT_TIMEOUT,
        verify: bool = True,
        client_identifier: Optional[IdentifierTypes] = None,
        debug: bool = DEFAULT_DEBUG,
        protocol_racing: bool = DEFAULT_PROTOCOL_RACING,
        allow_http: bool = DEFAULT_ALLOW_HTTP,
        stream_id: Optional[int] = None,
        **kwargs: Any,
    ) -> "TLSConfig":
        """Creates a `TLSConfig` instance from keyword arguments."""

        # 1. Handle Snake Case Aliases
        if client_identifier is not None:
            kwargs.setdefault("tlsClientIdentifier", client_identifier)
        if debug is not None:
            kwargs.setdefault("withDebug", debug)
        if protocol_racing is not None:
            kwargs.setdefault("withProtocolRacing", protocol_racing)
        if allow_http is not None:
            kwargs.setdefault("withAllowHTTP", allow_http)
        if stream_id is not None:
            kwargs.setdefault("streamID", stream_id)

        # 2. Resolve Identifier (Prioritize explicit arg, then kwargs, then default)
        identifier = client_identifier or kwargs.get("tlsClientIdentifier") or DEFAULT_CLIENT_IDENTIFIER
        identifier_str = str(identifier).lower()

        # 3. Dynamic Header Mapping based on identifier
        # Resolve Headers (Prioritize explicit arg, then kwargs)
        resolved_headers = headers if headers is not None else kwargs.get("headers")

        injected_headers = {}
        if not resolved_headers:  # Only inject if headers are missing or empty
            for browser, browser_headers in BROWSER_HEADERS.items():
                if browser in identifier_str:
                    injected_headers = browser_headers.copy()

                    # 4. Dynamic Version Replacement
                    if browser == "chrome":
                        match = re.search(r"chrome_(\d+)", identifier_str)
                        if match:
                            version = match.group(1)
                            ua = injected_headers.get("user-agent", "")
                            injected_headers["user-agent"] = re.sub(r"Chrome/\d+", f"Chrome/{version}", ua)
                            if "sec-ch-ua" in injected_headers:
                                val = injected_headers["sec-ch-ua"]
                                injected_headers["sec-ch-ua"] = val.replace("133", version)
                    elif browser == "firefox":
                        match = re.search(r"firefox_(\d+)", identifier_str)
                        if match:
                            version = match.group(1)
                            ua = injected_headers.get("user-agent", "")
                            # Firefox has version in two places: rv:XX and Firefox/XX
                            ua = re.sub(r"rv:\d+", f"rv:{version}", ua)
                            injected_headers["user-agent"] = re.sub(r"Firefox/\d+", f"Firefox/{version}", ua)
                    elif browser == "safari":
                        match = re.search(r"safari_ios_(\d+)", identifier_str) or re.search(
                            r"safari_(\d+)", identifier_str
                        )
                        if match:
                            version = match.group(1)
                            ua = injected_headers.get("user-agent", "")
                            injected_headers["user-agent"] = re.sub(r"Version/\d+", f"Version/{version}", ua)
                    break

        defaults = {
            "sessionId": session_id,
            "headers": dict(resolved_headers) if resolved_headers else injected_headers,
            "requestCookies": cookies or [],
            "requestMethod": method,
            "requestUrl": url,
            "requestBody": body,
            "isByteRequest": is_byte_request,
            "proxyUrl": proxy,
            "forceHttp1": bool(not http2),
            "timeoutSeconds": (int(timeout) if isinstance(timeout, (float, int)) else DEFAULT_TIMEOUT),
            "insecureSkipVerify": not verify,
            "tlsClientIdentifier": identifier,
            "withDebug": debug,
            "withProtocolRacing": protocol_racing,
            "withAllowHTTP": allow_http,
            "streamID": stream_id,
        }

        for key, value in defaults.items():
            kwargs.setdefault(key, value)

        return super().from_kwargs(**kwargs)
