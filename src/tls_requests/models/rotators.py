from __future__ import annotations

import asyncio
import itertools
import json
import random
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Generic, Iterable, Iterator, List, Literal, Optional, TypeVar, Union

from ..exceptions import RotatorError
from ..types import HeaderTypes, IdentifierTypes
from .headers import Headers
from .urls import Proxy

__all__ = [
    "BaseRotator",
    "ProxyRotator",
    "TLSIdentifierRotator",
    "HeaderRotator",
]

T = TypeVar("T")
R = TypeVar("R", bound="BaseRotator")

CLIENT_IDENTIFIER_TEMPLATES = [
    "chrome_120",
    "chrome_124",
    "chrome_131",
    "chrome_133",
    "firefox_120",
    "firefox_123",
    "firefox_132",
    "firefox_133",
    "safari_16_0",
    "safari_ios_16_0",
    "safari_ios_17_0",
    "safari_ios_18_0",
    "safari_ios_18_5",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
        " Safari/537.36"
    ),
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2"
        " Safari/605.1.15"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2"
        " Safari/605.1.15"
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2"
        " Mobile/15E148 Safari/604.1"
    ),
    (
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2"
        " Mobile/15E148 Safari/604.1"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
        " Safari/537.36 Edg/120.0.0.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
        " Safari/537.36 Edg/120.0.0.0"
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1"
        " Mobile/15E148 Safari/604.1"
    ),
    (
        "Mozilla/5.0 (Linux; Android 15; SM-S931B Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/127.0.6533.103 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; SM-S928B/DS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230"
        " Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; SM-F956U) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0"
        " Chrome/80.0.3987.119 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; SM-S911U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; SM-S908U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 9 Pro Build/AD1A.240418.003; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/124.0.6367.54 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 9 Build/AD1A.240411.003.A5; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/124.0.6367.54 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 15; Pixel 8 Pro Build/AP4A.250105.002; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 15; Pixel 8 Build/AP4A.250105.002; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 15; moto g - 2025 Build/V1VK35.22-13-2; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; 23129RAA4G Build/TKQ1.221114.001; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 15; 24129RT7CC Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like"
        " Gecko) Version/4.0 Chrome/130.0.6723.86 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 12; HBP-LX9 Build/HUAWEIHBP-L29; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/99.0.4844.88 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; U; Android 12; zh-Hans-CN; ADA-AL00 Build/HUAWEIADA-AL00) AppleWebKit/537.36 (KHTML, like"
        " Gecko) Version/4.0 Chrome/100.0.4896.58 Quark/6.11.2.531 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 12; PSD-AL00 Build/HUAWEIPSD-AL00; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/99.0.4844.88 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; 24030PN60G Build/UKQ1.231003.002; wv) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Version/4.0 Chrome/122.0.6261.119 Mobile Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 10; VOG-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile"
        " Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Linux; Android 10; MAR-LX1A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile"
        " Safari/537.36"
    ),
]

HEADER_TEMPLATES = [
    {
        "accept": "*/*",
        "connection": "keep-alive",
        "accept-encoding": "gzip, deflate, br, zstd",
        "User-Agent": ua,
    }
    for ua in USER_AGENTS
]


class BaseRotator(ABC, Generic[T]):
    """
    A unified, thread-safe and coroutine-safe abstract base class for a
    generic rotating data source.

    This class provides a dual API for both synchronous and asynchronous contexts.
    - For synchronous, thread-safe operations, use methods like `next()`, `add()`.
    - For asynchronous, coroutine-safe operations, use methods prefixed with 'a',
      like `anext()`, `aadd()`.

    It uses a `threading.Lock` for thread safety and an `asyncio.Lock` for
    coroutine safety.

    Attributes:
        items (List[T]): The list of items to rotate through.
        strategy (str): The rotation strategy in use.
    """

    def __init__(
        self,
        items: Optional[Iterable[T]] = None,
        strategy: Literal["round_robin", "random", "weighted"] = "random",
    ) -> None:
        """
        Initializes the BaseRotator.

        Args:
            items: An iterable of initial items.
            strategy: The rotation strategy to use.
        """
        self.items: List[T] = list(items or [])
        self.strategy = strategy
        self._iterator: Optional[Iterator[T]] = None
        self._lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None
        self._rebuild_iterator()

    @property
    def async_lock(self) -> asyncio.Lock:
        """
        Lazily creates and returns an `asyncio.Lock`. This ensures that the lock
        is created within the correct event loop and avoids issues in
        synchronous contexts or older Python versions (like 3.9).
        """
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    @classmethod
    def from_file(
        cls: type[R],
        source: Union[str, Path, list],
        strategy: Literal["round_robin", "random", "weighted"] = "random",
    ) -> R:
        """
        Factory method to create a rotator from a file or a list. This method
        is synchronous as it's typically used during setup.
        """

        items = []
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise FileNotFoundError(f"Source file not found: {path}")

            if path.suffix == ".json":
                data = json.loads(path.read_text())
                items = [cls.rebuild_item(item) for item in data]
            else:
                lines = path.read_text().splitlines()
                for line in lines:
                    line_content = line.split("#", 1)[0].strip()
                    if not line_content:
                        continue
                    items.append(cls.rebuild_item(line_content))
        elif isinstance(source, list):
            items = [cls.rebuild_item(item) for item in source]
        else:
            raise RotatorError(f"Unsupported source type: {type(source)}")

        valid_items = [item for item in items if item is not None]
        return cls(valid_items, strategy)

    @classmethod
    @abstractmethod
    def rebuild_item(cls, item: Any) -> Optional[T]:
        """
        Abstract method to convert a raw item into a typed object. Must be
        implemented by subclasses.
        """
        raise NotImplementedError

    def _rebuild_iterator(self) -> None:
        """
        Reconstructs the internal iterator. This is a core logic method and
        should be called only after acquiring a lock.
        """
        if not self.items:
            self._iterator = None
            return

        if self.strategy == "round_robin":
            self._iterator = itertools.cycle(self.items)
        elif self.strategy == "random":
            self._iterator = None
        elif self.strategy == "weighted":
            weights = [getattr(item, "weight", 1.0) for item in self.items]
            self._iterator = self._weighted_cycle(self.items, weights)
        else:
            raise ValueError(f"Unsupported strategy: {self.strategy}")

    def _weighted_cycle(self, items: List[T], weights: List[float]) -> Iterator[T]:
        """Creates an infinite iterator that yields items based on weights."""
        while True:
            yield random.choices(items, weights=weights, k=1)[0]

    def next(self, *args, **kwargs) -> T:
        """
        Retrieves the next item using a thread-safe mechanism.

        Returns:
            The next item from the collection.

        Raises:
            ValueError: If the rotator contains no items.
        """
        with self._lock:
            if not self.items:
                raise ValueError("Rotator is empty.")
            if self.strategy == "random":
                return random.choice(self.items)
            if self._iterator is None:
                self._rebuild_iterator()
            assert self._iterator is not None
            return next(self._iterator)

    def add(self, item: T) -> None:
        """
        Adds a new item to the rotator in a thread-safe manner.
        """
        with self._lock:
            self.items.append(item)
            self._rebuild_iterator()

    def remove(self, item: T) -> None:
        """
        Removes an item from the rotator in a thread-safe manner.
        """
        with self._lock:
            self.items = [i for i in self.items if i != item]
            self._rebuild_iterator()

    async def anext(self, *args, **kwargs) -> T:
        """
        Retrieves the next item using a coroutine-safe mechanism.

        Returns:
            The next item from the collection.

        Raises:
            ValueError: If the rotator contains no items.
        """
        async with self.async_lock:
            if not self.items:
                raise ValueError("Rotator is empty.")
            if self.strategy == "random":
                return random.choice(self.items)
            if self._iterator is None:
                self._rebuild_iterator()
            assert self._iterator is not None
            return next(self._iterator)

    async def aadd(self, item: T) -> None:
        """
        Adds a new item to the rotator in a coroutine-safe manner.
        """
        async with self.async_lock:
            self.items.append(item)
            self._rebuild_iterator()

    async def aremove(self, item: T) -> None:
        """
        Removes an item from the rotator in a coroutine-safe manner.
        """
        async with self.async_lock:
            self.items = [i for i in self.items if i != item]
            self._rebuild_iterator()

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)


class ProxyRotator(BaseRotator[Proxy]):
    """
    A unified rotator for managing `Proxy` objects, supporting both sync and
    async operations.
    """

    @classmethod
    def rebuild_item(cls, item: Any) -> Optional[Proxy]:
        """Constructs a `Proxy` object from various input types."""
        try:
            if isinstance(item, Proxy):
                return item
            if isinstance(item, dict):
                return Proxy.from_dict(item)
            if isinstance(item, str):
                return Proxy.from_string(item)
        except Exception:
            return None
        return None

    def mark_result(self, proxy: Proxy, success: bool, latency: Optional[float] = None) -> None:
        """
        Thread-safely updates a proxy's performance statistics.
        """
        with self._lock:
            self._update_proxy_stats(proxy, success, latency)

    async def amark_result(self, proxy: Proxy, success: bool, latency: Optional[float] = None) -> None:
        """
        Coroutine-safely updates a proxy's performance statistics.
        """
        async with self.async_lock:
            self._update_proxy_stats(proxy, success, latency)

    def _update_proxy_stats(self, proxy: Proxy, success: bool, latency: Optional[float] = None):
        """Internal logic for updating proxy stats. Must be called from a locked context."""
        if success:
            proxy.mark_success(latency)
        else:
            proxy.mark_failed()

        if self.strategy == "weighted":
            self._rebuild_iterator()


class TLSIdentifierRotator(BaseRotator[IdentifierTypes]):
    """
    A unified rotator for TLS Identifiers, supporting both sync and async operations.
    """

    def __init__(
        self,
        items: Optional[Iterable[IdentifierTypes]] = None,
        strategy: Literal["round_robin", "random", "weighted"] = "round_robin",
    ) -> None:
        super().__init__(items or CLIENT_IDENTIFIER_TEMPLATES, strategy)  # type: ignore[arg-type]

    @classmethod
    def rebuild_item(cls, item: Any) -> Optional[IdentifierTypes]:
        """Processes a raw item to be used as a TLS identifier."""
        if isinstance(item, str):
            return item
        return None


class HeaderRotator(BaseRotator[Headers]):
    """
    A unified rotator for managing `Headers` objects, supporting both sync and
    async operations.

    This rotator can dynamically update the 'User-Agent' header for each request
    without modifying the original header templates.

    Examples:
        >>> common_headers = {
        ...     "Accept": "application/json",
        ...     "Accept-Language": "en-US,en;q=0.9",
        ...     "User-Agent": "Default-Bot/1.0"
        ... }
        >>> mobile_headers = {
        ...     "Accept": "*/*",
        ...     "User-Agent": "Default-Mobile/1.0",
        ...     "X-Custom-Header": "mobile"
        ... }
        >>>
        >>> rotator = HeaderRotator.from_file([common_headers, mobile_headers])
        >>>
        >>> # Get headers without modification
        >>> h1 = rotator.next()
        >>> print(h1['User-Agent'])
        Default-Bot/1.0
        >>>
        >>> # Get headers with a new, dynamic User-Agent
        >>> h2 = rotator.next(user_agent="My-Custom-UA/2.0")
        >>> print(h2['User-Agent'])
        My-Custom-UA/2.0
        >>>
        >>> # The original header set remains unchanged
        >>> h3 = rotator.next()
        >>> print(h3['User-Agent'])
        Default-Mobile/1.0
    """

    def __init__(
        self,
        items: Optional[Iterable[HeaderTypes]] = None,
        strategy: Literal["round_robin", "random", "weighted"] = "random",
    ) -> None:
        super().__init__(items or HEADER_TEMPLATES, strategy)  # type: ignore[arg-type]

    @classmethod
    def rebuild_item(cls, item: HeaderTypes) -> Optional[Headers]:
        """
        Constructs a `Headers` object from various input types.

        It can process existing `Headers` objects, dictionaries, or lists of tuples.

        Args:
            item: The raw data to convert into a `Headers` object.

        Returns:
            A `Headers` instance, or None if the input is invalid.
        """
        try:
            if isinstance(item, Headers):
                return item
            return Headers(item)
        except Exception:
            return None

    def next(self, user_agent: Optional[str] = None, **kwargs) -> Headers:
        """
        Retrieves the next `Headers` object in a thread-safe manner and
        optionally updates its User-Agent.

        Args:
            user_agent: If provided, this string will replace the 'User-Agent'
                        header in the returned object.

        Returns:
            A copy of the next `Headers` object, potentially with a modified User-Agent.
        """
        headers = super().next()
        headers_copy = headers.copy()
        if not isinstance(headers_copy, Headers):
            headers_copy = Headers(headers_copy)
        if user_agent:
            headers_copy["User-Agent"] = user_agent
        return headers_copy

    async def anext(self, user_agent: Optional[str] = None, **kwargs) -> Headers:
        """
        Retrieves the next `Headers` object in a coroutine-safe manner and
        optionally updates its User-Agent.

        Args:
            user_agent: If provided, this string will replace the 'User-Agent'
                        header in the returned object.

        Returns:
            A copy of the next `Headers` object, potentially with a modified User-Agent.
        """
        headers = await super().anext()
        headers_copy = headers.copy()
        if not isinstance(headers_copy, Headers):
            headers_copy = Headers(headers_copy)
        if user_agent:
            headers_copy["User-Agent"] = user_agent
        return headers_copy
