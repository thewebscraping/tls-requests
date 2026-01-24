"""
Type definitions for type checking purposes.
"""

from __future__ import annotations

from http.cookiejar import CookieJar
from io import BufferedReader, BytesIO
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)
from uuid import UUID

if TYPE_CHECKING:  # pragma: no cover
    from .models import (
        URL,
        Auth,
        BasicAuth,
        Cookies,
        HeaderRotator,
        Headers,  # noqa: F401
        Proxy,
        ProxyRotator,
        Response,
        TLSIdentifierRotator,
        URLParams,
    )

AuthTypes = Optional[
    Union[
        Tuple[Union[str, bytes], Union[str, bytes]],
        Callable,
        "Auth",
        "BasicAuth",
    ]
]
URLTypes = Union["URL", str, bytes]
ProxyTypes = Optional[Union[str, bytes, "Proxy", "URL", "ProxyRotator"]]
URL_ALLOWED_PARAMS = Union[str, bytes, int, float, bool]
URLParamTypes = Optional[
    Union[
        "URLParams",
        Mapping[
            Union[str, bytes],
            Union[
                URL_ALLOWED_PARAMS,
                List[URL_ALLOWED_PARAMS],
                Tuple[URL_ALLOWED_PARAMS],
                Set[URL_ALLOWED_PARAMS],
            ],
        ],
    ]
]
MethodTypes = Union[str, Literal["GET", "OPTIONS", "HEAD", "POST", "PUT", "PATCH", "DELETE"]]
ProtocolTypes = Optional[Union[Literal["auto", "http1", "http2"], bool]]
HookTypes = Optional[Mapping[Literal["request", "response"], Sequence[Callable]]]
Session = Optional[Any]
SessionId = Union[str, UUID]
Payload = Union[dict, str, bytes, bytearray]
CookiesTypes = Optional[List[Dict[str, str]]]
IdentifierLiterals = Literal[
    "chrome_103",
    "chrome_104",
    "chrome_105",
    "chrome_106",
    "chrome_107",
    "chrome_108",
    "chrome_109",
    "chrome_110",
    "chrome_111",
    "chrome_112",
    "chrome_116_PSK",
    "chrome_116_PSK_PQ",
    "chrome_117",
    "chrome_120",
    "chrome_124",
    "chrome_130_PSK",
    "chrome_131",
    "chrome_131_PSK",
    "chrome_133",
    "chrome_133_PSK",
    "confirmed_android",
    "confirmed_android_2",
    "confirmed_ios",
    "firefox_102",
    "firefox_104",
    "firefox_105",
    "firefox_106",
    "firefox_108",
    "firefox_110",
    "firefox_117",
    "firefox_120",
    "firefox_123",
    "firefox_132",
    "firefox_133",
    "mesh_android",
    "mesh_android_1",
    "mesh_android_2",
    "mesh_ios",
    "mesh_ios_1",
    "mesh_ios_2",
    "mms_ios",
    "mms_ios_1",
    "mms_ios_2",
    "mms_ios_3",
    "nike_android_mobile",
    "nike_ios_mobile",
    "okhttp4_android_10",
    "okhttp4_android_11",
    "okhttp4_android_12",
    "okhttp4_android_13",
    "okhttp4_android_7",
    "okhttp4_android_8",
    "okhttp4_android_9",
    "opera_89",
    "opera_90",
    "opera_91",
    "safari_15_6_1",
    "safari_16_0",
    "safari_ipad_15_6",
    "safari_ios_15_5",
    "safari_ios_15_6",
    "safari_ios_16_0",
    "safari_ios_17_0",
    "safari_ios_18_0",
    "safari_ios_18_5",
    "zalando_android_mobile",
    "zalando_ios_mobile",
]
IdentifierTypes = Union[IdentifierLiterals, str]
IdentifierArgTypes = Optional[Union[IdentifierTypes, "TLSIdentifierRotator"]]

AnyList = List[
    Union[
        List[Union[str, int, float]],
        Tuple[Union[str, int, float], ...],
        Set[Union[str, int, float]],
        List[Union[str, bytes]],
        Tuple[Union[str, bytes], ...],
        Set[Union[str, bytes]],
    ]
]

HeaderTypes = Optional[
    Union[
        "Headers",
        "HeaderRotator",
        Mapping[str, Union[str, int, float]],
        Mapping[bytes, bytes],
        AnyList,
    ]
]

CookieTypes = Optional[
    Union[
        "Cookies",
        CookieJar,
        Mapping[str, Union[str, int, float]],
        Mapping[bytes, bytes],
        AnyList,
    ]
]

TimeoutTypes = Optional[Union[int, float]]
ByteOrStr = Union[bytes, str]
BufferTypes = Union[IO[bytes], "BytesIO", "BufferedReader"]
FileContent = Union[ByteOrStr, BinaryIO]
RequestFileValue = Union[
    FileContent,  # file (or file path, str and bytes)
    Tuple[ByteOrStr, FileContent],  # filename, file (or file path, str and bytes))
    Tuple[ByteOrStr, FileContent, ByteOrStr],  # filename, file (or file path, str and bytes)), content type
]
RequestData = Mapping[str, Any]
RequestJson = Mapping[str, Any]
RequestFiles = Mapping[ByteOrStr, RequestFileValue]
ResponseHistory = List["Response"]
