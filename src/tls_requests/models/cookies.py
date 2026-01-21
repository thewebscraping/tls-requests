# Origin: requests library (https://github.com/psf/requests)

from __future__ import annotations

import calendar
import copy
import time
from email.message import Message
from http import cookiejar as cookielib
from http.cookiejar import Cookie
from http.cookies import Morsel
from typing import TYPE_CHECKING, Any, Dict, Iterator, MutableMapping, Optional
from urllib.parse import urlparse, urlunparse

from ..exceptions import CookieConflictError, CookieError
from ..types import CookieTypes

if TYPE_CHECKING:
    from .request import Request
    from .response import Response


__all__ = ("Cookies",)


class MockResponse:
    def __init__(self, response: Response):
        self._original_response = response

    def info(self):
        info = Message()
        for k, v in self._original_response.headers.items():
            info[k] = v
        return info


class MockRequest:
    def __init__(self, request: Request):
        self._new_headers: Dict[str, str] = {}
        self._request = request
        self._headers = request.headers
        self.type = urlparse(str(request.url)).scheme

    def get_type(self):
        return self.type

    def get_host(self):
        return urlparse(str(self._request.url)).netloc

    def get_origin_req_host(self):
        return self.get_host()

    def get_full_url(self):
        # Only return the response's URL if the user hadn't set the Host
        # header
        if not self._headers.get("Host"):
            return str(self._request.url)

        # If they did set it, retrieve it and reconstruct the expected domain
        host = self._headers["Host"]
        parsed = urlparse(str(self._request.url))
        # Reconstruct the URL as we expect it
        return urlunparse(
            [
                parsed.scheme,
                host,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ]
        )

    def is_unverifiable(self):
        return True

    def has_header(self, name):
        return name in self._headers or name in self._new_headers

    def get_header(self, name, default=None):
        return self._headers.get(name, self._new_headers.get(name, default))

    def add_unredirected_header(self, name, value):
        self._new_headers[name] = value

    def get_new_headers(self):
        return self._new_headers

    @property
    def unverifiable(self):
        return self.is_unverifiable()

    @property
    def origin_req_host(self):
        return self.get_origin_req_host()

    @property
    def host(self):
        return self.get_host()


class RequestsCookieJar(cookielib.CookieJar, MutableMapping):
    """Compatibility class; is a http.cookiejar.CookieJar, but exposes a dict
    interface.

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.

    Requests does not use the dict interface internally; it's just for
    compatibility with external client code. All requests code should work
    out of the box with externally provided instances of ``CookieJar``, e.g.
    ``LWPCookieJar`` and ``FileCookieJar``.

    Unlike a regular CookieJar, this class is pickleable.

    .. warning:: dictionary operations that are normally O(1) may be O(n).
    """

    def get(self, name, default=None, domain=None, path=None):
        """Dict-like get() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.

        .. warning:: operation is O(n), not O(1).
        """
        try:
            value = self._find_no_duplicates(name, domain, path)
            return value
        except KeyError:
            return default

    def set(self, name, value, **kwargs):
        """Dict-like set() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.
        """
        # support client code that unsets cookies by assignment of a None value:
        if value is None:
            remove_cookie_by_name(self, name, domain=kwargs.get("domain"), path=kwargs.get("path"))
            return None

        if isinstance(value, Morsel):
            c = morsel_to_cookie(value)
        else:
            c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self):
        """Dict-like iterkeys() that returns an iterator of names of cookies
        from the jar.

        .. seealso:: itervalues() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.name

    def keys(self):
        """Dict-like keys() that returns a list of names of cookies from the
        jar.

        .. seealso:: values() and items().
        """
        return list(self.iterkeys())

    def itervalues(self):
        """Dict-like itervalues() that returns an iterator of values of cookies
        from the jar.

        .. seealso:: iterkeys() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.value

    def values(self):
        """Dict-like values() that returns a list of values of cookies from the
        jar.

        .. seealso:: keys() and items().
        """
        return list(self.itervalues())

    def iteritems(self):
        """Dict-like iteritems() that returns an iterator of name-value tuples
        from the jar.

        .. seealso:: iterkeys() and itervalues().
        """
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self):
        """Dict-like items() that returns a list of name-value tuples from the
        jar. Allows client-code to call ``dict(RequestsCookieJar)`` and get a
        vanilla python dict of key value pairs.

        .. seealso:: keys() and values().
        """
        return list(self.iteritems())

    def list_domains(self):
        """Utility method to list all the domains in the jar."""
        domains = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self):
        """Utility method to list all the paths in the jar."""
        paths = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self):
        """Returns True if there are multiple domains in the jar.
        Returns False otherwise.

        :rtype: bool
        """
        domains = []
        for cookie in iter(self):
            if cookie.domain is not None and cookie.domain in domains:
                return True
            domains.append(cookie.domain)
        return False  # there is only one domain in jar

    def get_dict(self, domain=None, path=None):
        """Takes as an argument an optional domain and path and returns a plain
        old Python dict of name-value pairs of cookies that meet the
        requirements.

        :rtype: dict
        """
        dictionary = {}
        for cookie in iter(self):
            if (domain is None or cookie.domain == domain) and (path is None or cookie.path == path):
                dictionary[cookie.name] = cookie.value
        return dictionary

    def __contains__(self, name):
        try:
            return super().__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name):
        """Dict-like __getitem__() for compatibility with client code. Throws
        exception if there are more than one cookie with name. In that case,
        use the more explicit get() method instead.

        .. warning:: operation is O(n), not O(1).
        """
        return self._find_no_duplicates(name)

    def __setitem__(self, name, value):
        """Dict-like __setitem__ for compatibility with client code. Throws
        exception if there is already a cookie of that name in the jar. In that
        case, use the more explicit set() method instead.
        """
        self.set(name, value)

    def __delitem__(self, name):
        """Deletes a cookie given a name. Wraps ``http.cookiejar.CookieJar``'s
        ``remove_cookie_by_name()``.
        """
        remove_cookie_by_name(self, name)

    def set_cookie(self, cookie, *args, **kwargs):
        if hasattr(cookie.value, "startswith") and cookie.value.startswith('"') and cookie.value.endswith('"'):
            cookie.value = cookie.value.replace('\\"', "")
        return super().set_cookie(cookie, *args, **kwargs)  # type: ignore

    def update(self, other: Any = None, **kwargs: Any) -> None:  # type: ignore[override]
        """Updates this jar with cookies from another CookieJar or dict-like"""
        if other is not None:
            if isinstance(other, cookielib.CookieJar):
                for cookie in other:
                    self.set_cookie(copy.copy(cookie))
            else:
                super().update(other)
        if kwargs:
            super().update(**kwargs)

    def _find(self, name, domain=None, path=None):
        """Requests uses this method internally to get cookie values.

        If there are conflicting cookies, _find arbitrarily chooses one.
        See _find_no_duplicates if you want an exception thrown if there are
        conflicting cookies.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :return: cookie.value
        """
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        return cookie.value

        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def _find_no_duplicates(self, name, domain=None, path=None):
        """Both ``__get_item__`` and ``get`` call this function: it's never
        used elsewhere in Requests.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :raises KeyError: if cookie is not found
        :raises CookieConflictError: if there are multiple cookies
            that match name and optionally domain and path
        :return: cookie.value
        """
        toReturn = None
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        if toReturn is not None:
                            # if there are multiple cookies that meet passed in criteria
                            raise CookieConflictError(f"There are multiple cookies with name, {name!r}")
                        # we will eventually return this as long as no cookie conflict
                        toReturn = cookie.value

        if toReturn is not None:
            return toReturn
        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def __getstate__(self):
        """Unlike a normal CookieJar, this class is pickleable."""
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop("_cookies_lock")
        return state

    def __setstate__(self, state):
        """Unlike a normal CookieJar, this class is pickleable."""
        self.__dict__.update(state)
        if "_cookies_lock" not in self.__dict__:
            import threading

            self._cookies_lock = threading.RLock()

    def copy(self):
        """Return a copy of this RequestsCookieJar."""
        new_cj = RequestsCookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self):
        """Return the CookiePolicy instance used."""
        return getattr(self, "_policy", None)


def extract_cookies_to_jar(cookiejar, response, request):
    """Extract the cookies from the response into a CookieJar.

    :param cookiejar: http.cookiejar.CookieJar (not necessarily a RequestsCookieJar)
    :param request: our own requests.Request object
    :param response: tls_requests.Response object
    """
    request = MockRequest(request)
    response = MockResponse(response)
    cookiejar.extract_cookies(response, request)


def get_cookie_header(jar, request):
    """
    Produce an appropriate Cookie header string to be sent with `request`, or None.

    :rtype: str
    """
    r = MockRequest(request)
    jar.add_cookie_header(r)
    return r.get_new_headers().get("Cookie")


def remove_cookie_by_name(cookiejar, name, domain=None, path=None):
    """Unsets a cookie by key, by default over all domains and paths.

    Wraps CookieJar.clear(), is O(n).
    """
    clearables = []
    for cookie in cookiejar:
        if cookie.name != name:
            continue
        if domain is not None and domain != cookie.domain:
            continue
        if path is not None and path != cookie.path:
            continue
        clearables.append((cookie.domain, cookie.path, cookie.name))

    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)


def _copy_cookie_jar(jar):
    if jar is None:
        return None

    if hasattr(jar, "copy"):
        # We're dealing with an instance of RequestsCookieJar
        return jar.copy()
    # We're dealing with a generic CookieJar instance
    new_jar = copy.copy(jar)
    new_jar.clear()
    for cookie in jar:
        new_jar.set_cookie(copy.copy(cookie))
    return new_jar


def create_cookie(name, value, **kwargs):
    """Make a cookie from underspecified parameters.

    By default, the pair of `key` and `value` will be set for the domain ''
    and sent on every request (this is sometimes called a "supercookie").
    """
    result = {
        "version": 0,
        # "key": name, # remove unexpected arg
        "name": name,  # fix unexpected arg
        "value": value,
        "port": None,
        "domain": "",
        "path": "/",
        "secure": False,
        "expires": None,
        "discard": True,
        "comment": None,
        "comment_url": None,
        "rest": {"HttpOnly": None},
        "rfc2109": False,
    }

    badargs = set(kwargs) - set(result)
    if badargs:
        raise CookieError(f"create_cookie() got unexpected keyword arguments: {list(badargs)}")

    result.update(kwargs)
    result["port_specified"] = bool(result["port"])
    result["domain_specified"] = bool(result["domain"])
    result["domain_initial_dot"] = result["domain"].startswith(".")
    result["path_specified"] = bool(result["path"])

    return cookielib.Cookie(**result)


def morsel_to_cookie(morsel):
    """Convert a Morsel object into a Cookie containing the one k/v pair."""

    expires = None
    if morsel["max-age"]:
        try:
            expires = int(time.time() + int(morsel["max-age"]))
        except ValueError:
            raise CookieError(f"max-age: {morsel['max-age']} must be integer")
    elif morsel["expires"]:
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"
        expires = calendar.timegm(time.strptime(morsel["expires"], time_template))
    return create_cookie(
        comment=morsel["comment"],
        comment_url=bool(morsel["comment"]),
        discard=False,
        domain=morsel["domain"],
        expires=expires,
        name=morsel.key,
        path=morsel["path"],
        port=None,
        rest={"HttpOnly": morsel["httponly"]},
        rfc2109=False,
        secure=bool(morsel["secure"]),
        value=morsel.value,
        version=morsel["version"] or 0,
    )


def cookiejar_from_dict(cookie_dict, cookiejar=None, overwrite=True):
    """Returns a CookieJar from a key/value dictionary.

    :param cookie_dict: Dict of key/values to insert into CookieJar.
    :param cookiejar: (optional) A cookiejar to add the cookies to.
    :param overwrite: (optional) If False, will not replace cookies
        already in the jar with new ones.
    :rtype: CookieJar
    """
    if cookiejar is None:
        cookiejar = RequestsCookieJar()

    if cookie_dict is not None:
        names_from_jar = [cookie.name for cookie in cookiejar]
        for name in cookie_dict:
            if overwrite or (name not in names_from_jar):
                cookiejar.set_cookie(create_cookie(name, cookie_dict[name]))

    return cookiejar


def merge_cookies(cookiejar, cookies):
    """Add cookies to cookiejar and returns a merged CookieJar.

    :param cookiejar: CookieJar object to add the cookies to.
    :param cookies: Dictionary or CookieJar object to be added.
    :rtype: CookieJar
    """
    if not isinstance(cookiejar, cookielib.CookieJar):
        raise ValueError("You can only merge into CookieJar")

    if isinstance(cookies, dict):
        cookiejar = cookiejar_from_dict(cookies, cookiejar=cookiejar, overwrite=False)
    elif isinstance(cookies, cookielib.CookieJar):
        try:
            cookiejar.update(cookies)  # type: ignore
        except AttributeError:
            for cookie_in_jar in cookies:
                cookiejar.set_cookie(cookie_in_jar)

    return cookiejar


class Cookies(MutableMapping[str, str]):
    def __init__(self, cookies: Optional[CookieTypes] = None) -> None:
        self.cookiejar = self._prepare_cookiejar(cookies)

    def _prepare_cookiejar(self, cookies: Optional[CookieTypes] = None) -> RequestsCookieJar:
        if isinstance(cookies, self.__class__):
            return cookies.cookiejar

        if isinstance(cookies, (dict, tuple, list, set)):
            cookiejar = RequestsCookieJar()
            cookie_items = cookies.items() if isinstance(cookies, dict) else cookies

            for item in cookie_items:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    k, v = item[0], item[1]
                    if isinstance(v, (float, int)):
                        v = str(v)
                    cookiejar.set(str(k), str(v))
            return cookiejar

        return RequestsCookieJar()

    def extract_cookies(self, response: Response, request: Request) -> None:
        extract_cookies_to_jar(self.cookiejar, response, request)

    def get_cookie_header(self, request: Request) -> str:
        return get_cookie_header(self.cookiejar, request)

    def set(self, name, value, **kwargs) -> Optional[Cookie]:
        if value is None:
            remove_cookie_by_name(self.cookiejar, name, domain=kwargs.get("domain"), path=kwargs.get("path"))
            return None

        if isinstance(value, Morsel):
            cookie = morsel_to_cookie(value)
        else:
            cookie = create_cookie(name, value, **kwargs)

        self.cookiejar.set_cookie(cookie)
        return cookie

    def get(self, name, default=None, domain=None, path=None) -> Any:
        return self.cookiejar.get(name, default, domain, path)

    def delete(self, name: str, domain: Optional[str] = None, path: Optional[str] = None) -> None:
        return remove_cookie_by_name(self.cookiejar, name, domain=domain, path=path)

    def clear(self, domain: Optional[str] = None, path: Optional[str] = None):
        args = []
        if domain:
            args.append(domain)
        if domain and path:
            args.append(path)

        self.cookiejar.clear(*args)

    def update(self, cookies: Optional[CookieTypes] = None) -> None:  # type: ignore[override]
        self.cookiejar.update(self._prepare_cookiejar(cookies))

    def copy(self) -> "Cookies":
        ret = self.__class__()
        ret.cookiejar = _copy_cookie_jar(self.cookiejar)
        return ret

    def __setitem__(self, name: str, value: str) -> None:  # type: ignore[override]
        self.set(name, value)

    def __getitem__(self, name: str) -> str:
        return self.cookiejar.get(name) or ""

    def __delitem__(self, name: str) -> None:
        self.delete(name)

    def __len__(self) -> int:
        return len(self.cookiejar)

    def __iter__(self) -> Iterator[str]:
        return (cookie.name for cookie in self.cookiejar)

    def __bool__(self) -> bool:
        for _ in self.cookiejar:
            return True
        return False

    def __repr__(self) -> str:
        cookiejar_repr = ", ".join([repr(cookie) for cookie in self.cookiejar])
        return "<%s[%s]>" % (self.__class__.__name__, cookiejar_repr)
