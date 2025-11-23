from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, ItemsView, KeysView, Union, ValuesView
from urllib.parse import ParseResult, quote, unquote, urlencode, urlparse

import idna

from ..exceptions import ProxyError, URLError, URLParamsError
from ..types import URL_ALLOWED_PARAMS, ProxyTypes, URLParamTypes, URLTypes

__all__ = ["URL", "URLParams", "Proxy"]


class URLParams(Mapping):
    """
    A mapping-like object for managing URL query parameters.

    This class provides a dictionary-like interface for URL parameters,
    handling the normalization of keys and values into the correct string format
    and encoding them into a query string. It supports multi-value parameters.

    Attributes:
        params (str): The URL-encoded query string representation of the parameters.

    Examples:
        >>> params = URLParams({'key1': 'value1', 'key2': ['value2', 'value3']})
        >>> print(str(params))
        'key1=value1&key2=value2&key2=value3'

        >>> params.update({'key3': 4, 'active': True})
        >>> print(params)
        'key1=value1&key2=value2&key2=value3&key3=4&active=true'

        >>> 'key1' in params
        True
    """

    def __init__(self, params: URLParamTypes = None, **kwargs):
        """
        Initializes the URLParams object.

        Args:
            params: A dictionary, another URLParams instance, or a list of tuples
                    to initialize the parameters.
            **kwargs: Additional key-value pairs to add or overwrite parameters.

        Raises:
            URLParamsError: If `params` is not a valid mapping type.
        """
        self._data = self._prepare(params, **kwargs)

    @property
    def params(self) -> str:
        """Returns the encoded URL parameters as a query string."""
        return str(self)

    def update(self, params: URLParamTypes = None, **kwargs):
        """
        Updates the current parameters with new ones from a mapping or keyword args.

        Args:
            params: A dictionary-like object of parameters to add.
            **kwargs: Additional key-value pairs to add.
        """
        self._data.update(self._prepare(params, **kwargs))
        return self

    def keys(self) -> KeysView:
        """Returns a view of the parameter keys."""
        return self._data.keys()

    def values(self) -> ValuesView:
        """Returns a view of the parameter values."""
        return self._data.values()

    def items(self) -> ItemsView:
        """Returns a view of the parameter key-value pairs."""
        return self._data.items()

    def copy(self) -> URLParams:
        """Returns a shallow copy of the current instance."""
        return self.__class__(self._data.copy())

    def __str__(self):
        """Returns the URL-encoded string representation of the parameters."""
        return urlencode(self._data, doseq=True)

    def __repr__(self):
        """Returns the official string representation of the object."""
        return "<%s: %s>" % (self.__class__.__name__, self.items())

    def __contains__(self, key: Any) -> bool:
        """Checks if a key exists in the parameters."""
        return key in self._data

    def __setitem__(self, key, value):
        """Sets a parameter key-value pair, normalizing the input."""
        self._data.update(self._prepare({key: value}))

    def __getitem__(self, key):
        """Retrieves a parameter value by its key."""
        return self._data[key]

    def __delitem__(self, key):
        """Deletes a parameter by its key."""
        del self._data[key]

    def __iter__(self):
        """Returns an iterator over the parameter keys."""
        return (k for k in self.keys())

    def __len__(self) -> int:
        """Returns the number of unique parameter keys."""
        return len(self._data)

    def __hash__(self) -> int:
        """Returns the hash of the encoded parameter string."""
        return hash(str(self))

    def __eq__(self, other) -> bool:
        """Checks for equality based on the encoded parameter string."""
        if not isinstance(other, self.__class__):
            if isinstance(other, Mapping):
                other = self.__class__(other)
            else:
                return False
        return bool(self.params == other.params)

    def _prepare(self, params: URLParamTypes = None, **kwargs) -> Mapping:
        """
        Normalizes and prepares the input parameters.

        Args:
            params: A dictionary-like object of parameters.
            **kwargs: Additional keyword arguments.

        Returns:
            A mapping with normalized keys and values.

        Raises:
            URLParamsError: If keys or values are of an invalid type.
        """
        params = params or {}
        if not isinstance(params, (dict, self.__class__)):
            raise URLParamsError("Invalid parameters.")

        params.update(kwargs)
        for k, v in params.items():
            if not isinstance(k, (str, bytes)):
                raise URLParamsError("Invalid parameters key type.")

            if isinstance(v, (list, tuple, set)):
                v = [self.normalize(s) for s in v]
            else:
                v = self.normalize(v)

            params[self.normalize(k)] = v
        return params

    def normalize(self, s: URL_ALLOWED_PARAMS):
        """
        Converts a supported type into a string.

        Args:
            s: The value to normalize (str, bytes, int, float, bool).

        Returns:
            The normalized string value.

        Raises:
            URLParamsError: If the value type is not supported.
        """
        if not isinstance(s, (str, bytes, int, float, bool)):
            raise URLParamsError("Invalid parameters value type.")

        if isinstance(s, bool):
            return str(s).lower()

        if isinstance(s, bytes):
            return s.decode("utf-8")

        return str(s)


class URL:
    """
    A class for parsing, manipulating, and constructing URLs.

    This class provides a structured way to interact with URL components,
    integrating with `URLParams` for easy query string management. It handles
    IDNA encoding for hostnames and ensures proper URL construction.

    Attributes:
        url (str): The full URL string. Can be set to re-parse.
        params (URLParams): An object managing the URL's query parameters.
        parsed (ParseResult): The result from `urllib.parse.urlparse`.
        scheme (str): The URL scheme (e.g., "https").
        netloc (str): The network location part (e.g., "user:pass@host:port").
        host (str): The hostname, IDNA-encoded.
        port (str): The port number as a string, if present.
        path (str): The hierarchical path.
        query (str): The complete query string, combining original and added params.
        fragment (str): The fragment identifier.
        username (str): The username for authentication.
        password (str): The password for authentication.
        auth (tuple): A (username, password) tuple.

    Examples:
        >>> url = URL("https://example.com/path?q=1#fragment", params={"key": "value"})
        >>> print(url.scheme)
        'https'
        >>> print(url.host)
        'example.com'
        >>> print(url.query)
        'q=1&key=value'

        >>> url.params.update({'key2': 'value2'})
        >>> print(unquote(url.url))
        'https://example.com/path?q=1&key=value&key2=value2#fragment'

        >>> url.url = 'https://httpbin.org/get'
        >>> print(unquote(url.url))
        'https://httpbin.org/get?key=value&key2=value2'
    """

    __attrs__ = (
        "auth",
        "scheme",
        "host",
        "port",
        "path",
        "fragment",
        "username",
        "password",
    )

    def __init__(self, url: URLTypes, params: URLParamTypes = None, **kwargs):
        """
        Initializes the URL object.

        Args:
            url: The URL string, bytes, or another URL object.
            params: A dictionary-like object to be used as query parameters.
            **kwargs: Additional keyword arguments for URLParams.

        Raises:
            URLError: If the provided URL is invalid.
        """
        self._parsed = self._prepare(url)
        self._url = None
        self._params = URLParams(params)

    @property
    def url(self):
        """The full, reconstructed URL string."""
        if self._url is None:
            self._url = self._build(False)
        return self._url

    @url.setter
    def url(self, value):
        """Allows setting a new URL, which will be parsed."""
        self._parsed = self._prepare(value)
        self._url = self._build(False)

    @property
    def params(self):
        """The `URLParams` object for managing query parameters."""
        return self._params

    @params.setter
    def params(self, value):
        """Sets a new `URLParams` object."""
        self._url = None
        self._params = URLParams(value)

    @property
    def parsed(self) -> ParseResult:
        """The `ParseResult` object from the standard library."""
        return self._parsed

    @property
    def netloc(self) -> str:
        """The network location, including host and port."""
        return ":".join([self.host, self.port]) if self.port else self.host

    @property
    def query(self) -> str:
        """The combined query string from the original URL and the `params`."""
        query = ""
        if self.parsed.query and self.params.params:
            query = "&".join([quote(self.parsed.query), self.params.params])
        elif self.params.params:
            query = self.params.params
        elif self.parsed.query:
            query = self.parsed.query
        return query

    def __str__(self):
        """Returns the full URL string with the real password."""
        return self._build()

    def __repr__(self):
        """Returns a representation of the URL with a secured password."""
        return "<%s: %s>" % (self.__class__.__name__, unquote(self._build(True)))

    def _prepare(self, url: Union[T, str, bytes]) -> ParseResult:
        """
        Validates, decodes, and parses the input URL.

        Args:
            url: The URL to prepare.

        Returns:
            A `ParseResult` object.

        Raises:
            URLError: For invalid URL types or formats.
        """
        if isinstance(url, bytes):
            url = url.decode("utf-8")
        elif isinstance(url, self.__class__) or issubclass(self.__class__, url.__class__):
            url = str(url)

        if not isinstance(url, str):
            raise URLError("Invalid URL: %s" % url)

        for attr in self.__attrs__:
            setattr(self, attr, None)

        parsed = urlparse(url.lstrip())

        self.auth = parsed.username, parsed.password
        self.scheme = parsed.scheme

        try:
            self.host = idna.encode(parsed.hostname.lower()).decode("ascii")
        except AttributeError:
            self.host = ""
        except idna.IDNAError:
            raise URLError("Invalid IDNA hostname.")

        self.port = ""
        try:
            if parsed.port:
                self.port = str(parsed.port)
        except ValueError as e:
            raise URLError("%s. port range must be 0 - 65535." % e.args[0])

        self.path = parsed.path
        self.fragment = parsed.fragment
        self.username = parsed.username or ""
        self.password = parsed.password or ""
        return parsed

    def _build(self, secure: bool = False) -> str:
        """
        Constructs the URL string from its components.

        Args:
            secure: If True, masks the password in the output.

        Returns:
            The final URL string.
        """
        urls = [self.scheme, "://"]
        authority = self.netloc
        if self.username or self.password:
            password = self.password or ""
            if secure:
                password = "[secure]"

            authority = "@".join(
                [
                    ":".join([self.username, password]),
                    self.netloc,
                ]
            )

        urls.append(authority)
        if self.query:
            urls.append("?".join([self.path, self.query]))
        else:
            urls.append(self.path)

        if self.fragment:
            urls.append("#" + self.fragment)

        return "".join(urls)


class Proxy(URL):
    """
    A specialized URL class for managing proxy configurations and performance.

    This class inherits from `URL` and extends it with features for proxy
    rotation strategies, such as weighting, success/failure tracking, and
    metadata. It restricts the allowed URL schemes to those common for proxies.

    Attributes:
        ALLOWED_SCHEMES (tuple): Allowed proxy schemes ('http', 'https', 'socks5', 'socks5h').
        weight (float): The weight of the proxy, used in selection algorithms.
        region (Optional[str]): A geographical or logical region identifier.
        latency (Optional[float]): The last recorded latency in seconds.
        success_rate (Optional[float]): A score indicating reliability (0.0 to 1.0).
        meta (Dict[str, Any]): A dictionary for arbitrary user-defined data.
        failures (int): A counter for consecutive connection failures.
        last_used (Optional[float]): A timestamp of the last time the proxy was used.

    Examples:
        >>> proxy = Proxy("http://user:pass@127.0.0.1:8080", weight=5.0, region="us-east")
        >>> proxy.mark_failed()
        >>> print(proxy.failures)
        1
        >>> print(proxy.weight)
        4.25
        >>> proxy.mark_success()
        >>> data = proxy.to_dict()
        >>> print(data['url'])
        'http://user:pass@127.0.0.1:8080'
    """

    ALLOWED_SCHEMES = ("http", "https", "socks5", "socks5h")

    def __init__(
        self,
        url: URLTypes,
        params: URLParamTypes = None,
        *,
        weight: float = 1.0,
        region: Optional[str] = None,
        latency: Optional[float] = None,
        success_rate: Optional[float] = None,
        meta: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        """
        Initializes the Proxy object.

        Args:
            url: The proxy URL string, bytes, or another URL object.
            params: URL parameters (rarely used for proxies).
            weight: The initial weight for proxy selection (higher is more likely).
            region: An identifier for the proxy's region.
            latency: The initial or last known latency in seconds.
            success_rate: A score from 0.0 to 1.0 indicating reliability.
            meta: A dictionary for storing arbitrary user data.
            **kwargs: Additional keyword arguments passed to the parent `URL` class.

        Raises:
            ProxyError: If the URL is invalid or the scheme is not supported.
        """
        self._weight = weight or 1.0
        self.region = region
        self.latency = latency
        self.success_rate = success_rate
        self.meta = meta or {}
        self.failures: int = 0
        self.last_used: Optional[float] = None
        super().__init__(url, **kwargs)

    def __repr__(self):
        """Returns a secure representation of the proxy with its weight."""
        return "<%s: %s, weight=%s>" % (
            self.__class__.__name__,
            unquote(self._build(True)),
            getattr(self, "weight", "unset"),
        )

    @property
    def weight(self) -> float:
        return self._weight or 1.0

    @weight.setter
    def weight(self, weight: float) -> None:
        try:
            self._weight = float(weight)
        except ValueError:
            raise ProxyError("Weight must be an integer or float.")

    def _prepare(self, url: ProxyTypes) -> ParseResult:
        """
        Parses the proxy URL, ensuring it has a valid scheme and format.

        Overrides the parent `_prepare` to enforce proxy-specific rules.

        Args:
            url: The proxy URL to prepare.

        Returns:
            A `ParseResult` object containing only scheme and netloc.

        Raises:
            ProxyError: If the URL is invalid or the scheme is not allowed.
        """
        try:
            if isinstance(url, bytes):
                url = url.decode("utf-8")

            if isinstance(url, str):
                url = url.strip()

            if "://" not in str(url):
                url = f"http://{url}"

            parsed = super(Proxy, self)._prepare(url)
            if str(parsed.scheme).lower() not in self.ALLOWED_SCHEMES:
                raise ProxyError(
                    "Invalid proxy scheme `%s`. The allowed schemes are ('http', 'https', 'socks5', 'socks5h')."
                    % parsed.scheme
                )

            # Re-parse to create a clean object with only scheme and netloc
            return urlparse("%s://%s" % (parsed.scheme, parsed.netloc))
        except URLError:
            raise ProxyError("Invalid proxy: %s" % url)

    def _build(self, secure: bool = False) -> str:
        """
        Constructs the proxy URL string.

        Overrides the parent `_build` to exclude path, query, and fragment.

        Args:
            secure: If True, masks the password.

        Returns:
            The proxy URL string.
        """
        urls = [self.scheme or "http", "://"]
        authority = self.netloc
        if self.username or self.password:
            userinfo = ":".join([self.username, self.password])
            if secure:
                userinfo = "[secure]"

            authority = "@".join(
                [
                    userinfo,
                    self.netloc,
                ]
            )

        urls.append(authority)
        return "".join(urls)

    def mark_used(self):
        """Sets the `last_used` timestamp to the current time."""
        self.last_used = time.time()

    def mark_failed(self):
        """
        Records a connection failure.

        Increments the failure count and applies a decay factor to the weight.
        """
        self.failures += 1
        self.weight = max(0.1, self.weight * 0.85)

    def mark_success(self, latency: Optional[float] = None):
        """
        Records a connection success.

        Resets failure count, updates latency, and improves success rate and weight.

        Args:
            latency: The observed connection latency in seconds for this success.
        """
        if latency:
            self.latency = latency

        self.failures = max(0, self.failures - 1)
        self.success_rate = (self.success_rate or 1.0) * 0.95 + 0.05
        self.weight = min(10.0, self.weight * 1.05)

    def to_dict(self):
        """
        Serializes the proxy's state to a dictionary.

        Returns:
            A dictionary containing the proxy's URL and performance metrics.
        """
        return {
            "url": self.url,
            "weight": self.weight,
            "region": self.region,
            "latency": self.latency,
            "success_rate": self.success_rate,
            "last_used": self.last_used,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Proxy":
        """
        Creates a Proxy object from a dictionary.

        Args:
            data: A dictionary containing a 'url' key and other optional
                  proxy attributes (`weight`, `region`, etc.).

        Returns:
            A new `Proxy` instance.

        Raises:
            ProxyError: If the 'url' key is missing from the dictionary.
        """
        if "url" not in data:
            raise ProxyError("Missing required key: 'url'. The proxy configuration dictionary must include a 'url'.")

        url = data.pop("url")
        return cls(
            url=url,
            **data,
        )

    @classmethod
    def from_string(cls, raw: str, separator: str = "|") -> "Proxy":
        """
        Parses a proxy from a string with optional attributes.

        Handles various common formats for representing proxies in text files.
        Comments (#) and blank lines should be handled by the calling code.

        Supported Formats:
          - `http://user:pass@host:port`
          - `socks5://host:port`
          - `host:port` (defaults to http)
          - `host:port|weight`
          - `host:port|weight|region`
          - `http://user:pass@host:port|weight|region`

        Args:
            raw: The raw proxy string.
            separator: The character used to separate attributes (default: '|').

        Returns:
            A new `Proxy` instance.

        Raises:
            ProxyError: If the proxy string is empty or malformed.
        """
        raw = raw.strip()
        if not raw:
            raise ProxyError("Empty proxy string.")

        parts = [p.strip() for p in raw.split(separator)]
        url = parts[0]
        weight = 1.0
        region = None
        if len(parts) >= 2 and parts[1]:
            try:
                weight = float(parts[1])
            except Exception:
                pass
        if len(parts) >= 3 and parts[2]:
            region = parts[2]

        if "://" not in url:
            url = "http://" + url

        return cls(url, weight=weight, region=region)
