from __future__ import annotations

from enum import Enum

__all__ = ("StatusCodes",)


class StatusCodes(int, Enum):
    reason: str

    def __new__(cls, value: int, reason: str = ""):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.reason = reason
        return obj

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def get_reason(cls, value: int) -> str:
        if value in cls._value2member_map_:
            member = cls._value2member_map_[value]
            if isinstance(member, StatusCodes):
                return member.reason
        return "Unknown Error"

    CONTINUE = 100, "Continue"
    SWITCHING_PROTOCOLS = 101, "Switching Protocols"
    PROCESSING = 102, "Processing"
    CHECKPOINT = 103, "Checkpoint"
    URI_TOO_LONG = 122, "Uri Too Long"
    OK = 200, "OK"
    CREATED = 201, "Created"
    ACCEPTED = 202, "Accepted"
    NON_AUTHORITATIVE_INFO = 203, "Non Authoritative Info"
    NO_CONTENT = 204, "No Content"
    RESET_CONTENT = 205, "Reset Content"
    PARTIAL_CONTENT = 206, "Partial Content"
    MULTI_STATUS = 207, "Multi Status"
    ALREADY_REPORTED = 208, "Already Reported"
    IM_USED = 226, "Im Used"
    MULTIPLE_CHOICES = 300, "Multiple Choices"
    MOVED_PERMANENTLY = 301, "Moved Permanently"
    FOUND = 302, "Found"
    SEE_OTHER = 303, "See Other"
    NOT_MODIFIED = 304, "Not Modified"
    USE_PROXY = 305, "Use Proxy"
    SWITCH_PROXY = 306, "Switch Proxy"
    TEMPORARY_REDIRECT = 307, "Temporary Redirect"
    PERMANENT_REDIRECT = 308, "Permanent Redirect"
    BAD_REQUEST = 400, "Bad Request"
    UNAUTHORIZED = 401, "Unauthorized"
    PAYMENT_REQUIRED = 402, "Payment Required"
    FORBIDDEN = 403, "Forbidden"
    NOT_FOUND = 404, "Not Found"
    METHOD_NOT_ALLOWED = 405, "Method Not Allowed"
    NOT_ACCEPTABLE = 406, "Not Acceptable"
    PROXY_AUTHENTICATION_REQUIRED = 407, "Proxy Authentication Required"
    REQUEST_TIMEOUT = 408, "Request Timeout"
    CONFLICT = 409, "Conflict"
    GONE = 410, "Gone"
    LENGTH_REQUIRED = 411, "Length Required"
    PRECONDITION_FAILED = 412, "Precondition Failed"
    REQUEST_ENTITY_TOO_LARGE = 413, "Request Entity Too Large"
    REQUEST_URI_TOO_LARGE = 414, "Request Uri Too Large"
    UNSUPPORTED_MEDIA_TYPE = 415, "Unsupported Media Type"
    REQUESTED_RANGE_NOT_SATISFIABLE = 416, "Requested Range Not Satisfiable"
    EXPECTATION_FAILED = 417, "Expectation Failed"
    IM_A_TEAPOT = 418, "Im A Teapot"
    MISDIRECTED_REQUEST = 421, "Misdirected Request"
    UNPROCESSABLE_ENTITY = 422, "Unprocessable Entity"
    LOCKED = 423, "Locked"
    FAILED_DEPENDENCY = 424, "Failed Dependency"
    UNORDERED_COLLECTION = 425, "Unordered Collection"
    UPGRADE_REQUIRED = 426, "Upgrade Required"
    PRECONDITION_REQUIRED = 428, "Precondition Required"
    TOO_MANY_REQUESTS = 429, "Too Many Requests"
    HEADER_FIELDS_TOO_LARGE = 431, "Header Fields Too Large"
    NO_RESPONSE = 444, "No Response"
    RETRY_WITH = 449, "Retry With"
    BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450, "Blocked By Windows Parental Controls"
    UNAVAILABLE_FOR_LEGAL_REASONS = 451, "Unavailable For Legal Reasons"
    CLIENT_CLOSED_REQUEST = 499, "Client Closed Request"
    INTERNAL_SERVER_ERROR = 500, "Internal Server Error"
    NOT_IMPLEMENTED = 501, "Not Implemented"
    BAD_GATEWAY = 502, "Bad Gateway"
    SERVICE_UNAVAILABLE = 503, "Service Unavailable"
    GATEWAY_TIMEOUT = 504, "Gateway Timeout"
    HTTP_VERSION_NOT_SUPPORTED = 505, "Http Version Not Supported"
    VARIANT_ALSO_NEGOTIATES = 506, "Variant Also Negotiates"
    INSUFFICIENT_STORAGE = 507, "Insufficient Storage"
    BANDWIDTH_LIMIT_EXCEEDED = 509, "Bandwidth Limit Exceeded"
    NOT_EXTENDED = 510, "Not Extended"
    NETWORK_AUTHENTICATION_REQUIRED = 511, "Network Authentication Required"
