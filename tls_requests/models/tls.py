import ctypes
import uuid
from dataclasses import asdict, dataclass, field
from dataclasses import fields as get_fields
from typing import Any, List, Mapping, Optional, Set, TypeVar, Union

from ..settings import (DEFAULT_HEADERS, DEFAULT_TIMEOUT, DEFAULT_TLS_DEBUG,
                        DEFAULT_TLS_HTTP2, DEFAULT_TLS_IDENTIFIER)
from ..types import (MethodTypes, TLSCookiesTypes, TLSIdentifierTypes,
                     TLSSessionId, URLTypes)
from ..utils import to_base64, to_bytes, to_json
from .encoders import StreamEncoder
from .libraries import TLSLibrary
from .status_codes import StatusCodes

__all__ = [
    "TLSClient",
    "TLSResponse",
    "TLSConfig",
    "CustomTLSClientConfig",
]

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

    _library = None
    _getCookiesFromSession = None
    _addCookiesToSession = None
    _destroySession = None
    _destroyAll = None
    _request = None
    _freeMemory = None

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
                fn.argtypes = [ctypes.c_char_p]
                fn.restype = ctypes.c_char_p

        cls._destroyAll = cls._library.destroyAll
        cls._destroyAll.restype = ctypes.c_char_p
        return cls()

    @classmethod
    def get_cookies(cls, session_id: TLSSessionId, url: str) -> "TLSResponse":
        response = cls._send(cls._getCookiesFromSession, {"sessionId": session_id, "url": url})
        return response

    @classmethod
    def add_cookies(cls, session_id: TLSSessionId, payload: dict):
        payload["sessionId"] = session_id
        return cls._send(
            cls._addCookiesToSession,
            payload,
        )

    @classmethod
    def destroy_all(cls) -> bool:
        response = TLSResponse.from_bytes(cls._destroyAll())
        if response.success:
            return True
        return False

    @classmethod
    def destroy_session(cls, session_id: TLSSessionId) -> bool:
        response = cls._send(cls._destroySession, {"sessionId": session_id})
        return response.success or False

    @classmethod
    def request(cls, payload):
        return cls._send(cls._request, payload)

    @classmethod
    def free_memory(cls, response_id: str) -> None:
        cls._freeMemory(to_bytes(response_id))

    @classmethod
    def response(cls, raw: bytes) -> "TLSResponse":
        response = TLSResponse.from_bytes(raw)
        cls.free_memory(response.id)
        return response

    @classmethod
    async def aresponse(cls, raw: bytes):
        with StreamEncoder.from_bytes(raw) as stream:
            content = b"".join([chunk async for chunk in stream])
            return TLSResponse.from_kwargs(**to_json(content))

    @classmethod
    async def arequest(cls, payload):
        return await cls._aread(cls._request, payload)

    @classmethod
    def _send(cls, fn: callable, payload: dict):
        return cls.response(fn(to_bytes(payload)))

    @classmethod
    async def _aread(cls, fn: callable, payload: dict):
        return await cls.aresponse(fn(to_bytes(payload)))


@dataclass
class _BaseConfig:
    """Base configuration for TLSSession"""

    @classmethod
    def model_fields_set(cls) -> Set[str]:
        return {model_field.name for model_field in get_fields(cls) if not model_field.name.startswith("_")}

    @classmethod
    def from_kwargs(cls, **kwargs: Any) -> T:
        model_fields_set = cls.model_fields_set()
        return cls(**{k: v for k, v in kwargs.items() if k in model_fields_set and v})  # noqa

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if not k.startswith("_")}

    def to_payload(self) -> dict:
        return self.to_dict()


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
    status: Optional[int] = 0
    target: Optional[str] = None
    body: Optional[str] = None
    headers: Optional[dict] = field(default_factory=dict)
    cookies: Optional[dict] = field(default_factory=dict)
    success: Optional[bool] = False
    usedProtocol: Optional[str] = "HTTP/1.1"

    @classmethod
    def from_bytes(cls, raw: bytes) -> "TLSResponse":
        with StreamEncoder.from_bytes(raw) as stream:
            return cls.from_kwargs(**to_json(b"".join(stream)))

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

    alpnProtocols: List[str] = None
    alpsProtocols: List[str] = None
    certCompressionAlgo: str = None
    connectionFlow: int = None
    h2Settings: List[str] = None
    h2SettingsOrder: List[str] = None
    headerPriority: List[str] = None
    ja3String: str = None
    keyShareCurves: List[str] = None
    priorityFrames: List[str] = None
    pseudoHeaderOrder: List[str] = None
    supportedSignatureAlgorithms: List[str] = None
    supportedVersions: List[str] = None


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
    requestBody: Union[str, bytes, bytearray, None] = None
    requestCookies: List[TLSRequestCookiesConfig] = field(default_factory=list)
    requestMethod: MethodTypes = None
    requestUrl: Optional[str] = None
    sessionId: str = field(default_factory=lambda: str(uuid.uuid4()))
    timeoutSeconds: int = 30
    tlsClientIdentifier: Optional[TLSIdentifierTypes] = DEFAULT_TLS_IDENTIFIER
    withDebug: bool = False
    withDefaultCookieJar: bool = False
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
        else:
            self.isByteRequest = False
            self.requestBody = None

        self.timeoutSeconds = (
            int(self.timeoutSeconds) if isinstance(self.timeoutSeconds, (float, int)) else DEFAULT_TIMEOUT
        )
        return asdict(self)

    def copy_with(
        self,
        session_id: str = None,
        headers: Mapping[str, str] = None,
        cookies: TLSCookiesTypes = None,
        method: MethodTypes = None,
        url: URLTypes = None,
        body: Union[str, bytes, bytearray] = None,
        is_byte_request: bool = None,
        proxy: str = None,
        http2: bool = None,
        timeout: Union[float, int] = None,
        verify: bool = None,
        tls_identifier: Optional[TLSIdentifierTypes] = None,
        tls_debug: bool = None,
        **kwargs,
    ) -> "TLSConfig":
        """Creates a new `TLSConfig` object with updated properties."""

        kwargs.update(
            dict(
                sessionId=session_id,
                headers=headers,
                requestCookies=cookies,
                requestMethod=method,
                requestUrl=url,
                requestBody=body,
                isByteRequest=is_byte_request,
                proxyUrl=proxy,
                forceHttp1=not http2,
                timeoutSeconds=timeout,
                insecureSkipVerify=not verify,
                tlsClientIdentifier=tls_identifier,
                withDebug=tls_debug,
            )
        )
        current_kwargs = asdict(self)
        for k, v in current_kwargs.items():
            if kwargs.get(k) is not None:
                current_kwargs[k] = kwargs[k]

        return self.__class__(**current_kwargs)  # noqa

    @classmethod
    def from_kwargs(
        cls,
        session_id: str = None,
        headers: Mapping[str, str] = None,
        cookies: TLSCookiesTypes = None,
        method: MethodTypes = None,
        url: URLTypes = None,
        body: Union[str, bytes, bytearray] = None,
        is_byte_request: bool = False,
        proxy: str = None,
        http2: bool = DEFAULT_TLS_HTTP2,
        timeout: Union[float, int] = DEFAULT_TIMEOUT,
        verify: bool = True,
        tls_identifier: Optional[TLSIdentifierTypes] = DEFAULT_TLS_IDENTIFIER,
        tls_debug: bool = DEFAULT_TLS_DEBUG,
        **kwargs: Any,
    ) -> "TLSConfig":
        """Creates a `TLSConfig` instance from keyword arguments."""

        kwargs.update(
            dict(
                sessionId=session_id,
                headers=dict(headers) if headers else DEFAULT_HEADERS,
                requestCookies=cookies or [],
                requestMethod=method,
                requestUrl=url,
                requestBody=body,
                isByteRequest=is_byte_request,
                proxyUrl=proxy,
                forceHttp1=bool(not http2),
                timeoutSeconds=(int(timeout) if isinstance(timeout, (float, int)) else DEFAULT_TIMEOUT),
                insecureSkipVerify=not verify,
                tlsClientIdentifier=tls_identifier,
                withDebug=tls_debug,
            )
        )
        return super().from_kwargs(**kwargs)
