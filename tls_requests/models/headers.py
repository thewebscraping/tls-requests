from collections.abc import Mapping, MutableMapping
from enum import Enum
from typing import Any, ItemsView, KeysView, List, Literal, Tuple, ValuesView

from ..exceptions import HeaderError
from ..types import ByteOrStr, HeaderTypes
from ..utils import to_str

__all__ = ["Headers"]

HeaderAliasTypes = Literal["*", "lower", "capitalize"]


class HeaderAlias(str, Enum):
    LOWER = "lower"
    CAPITALIZE = "capitalize"
    ALL = "*"

    def __contains__(self, key: str) -> bool:
        for item in self:
            if item == key:
                return True
        return False


class Headers(MutableMapping):
    def __init__(self, headers: HeaderTypes = None, *, alias: HeaderAliasTypes = HeaderAlias.LOWER):
        self.alias = alias if alias in HeaderAlias._value2member_map_ else HeaderAlias.LOWER
        self._items = self._prepare_items(headers)

    def get(self, key: str, default: Any = None) -> Any:
        key = self._normalize_key(key)
        for k, v in self._items:
            if k == key:
                return ",".join(v)
        return default

    def items(self) -> ItemsView:
        return {k: ",".join(v) for k, v in self._items}.items()

    def keys(self) -> KeysView:
        return {k: v for k, v in self.items()}.keys()

    def values(self) -> ValuesView:
        return {k: v for k, v in self.items()}.values()

    def update(self, headers: HeaderTypes) -> "Headers":  # noqa
        headers = self.__class__(headers, alias=self.alias)  # noqa
        for idx, (key, _) in enumerate(headers._items):
            if key in self:
                self.pop(key)

        self._items.extend(headers._items)
        return self

    def copy(self) -> "Headers":
        return self.__class__(self._items.copy(), alias=self.alias)  # noqa

    def _prepare_items(self, headers: HeaderTypes) -> List[Tuple[str, Any]]:
        if headers is None:
            return []
        if isinstance(headers, self.__class__):
            return [self._normalize(k, v) for k, v in headers._items]
        if isinstance(headers, Mapping):
            return [self._normalize(k, v) for k, v in headers.items()]
        if isinstance(headers, (list, tuple, set)):
            try:
                items = [self._normalize(k, args[0]) for k, *args in headers]
                return items
            except IndexError:
                pass
        raise HeaderError

    def _normalize_key(self, key: ByteOrStr) -> str:
        key = to_str(key, encoding="ascii")
        if self.alias == HeaderAlias.ALL:
            return key

        if self.alias == HeaderAlias.CAPITALIZE:
            return "-".join([s.capitalize() for s in key.split("-")])

        return key.lower()

    def _normalize_value(self, value) -> List[str]:
        if isinstance(value, dict):
            raise HeaderError

        if isinstance(value, (list, tuple, set)):
            items = []
            for item in value:
                if isinstance(item, dict):
                    raise HeaderError
                items.append(to_str(item))
            return items

        return [to_str(value)]

    def _normalize(self, key, value) -> Tuple[str, List[str]]:
        return self._normalize_key(key), self._normalize_value(value)

    def __setitem__(self, key, value) -> None:
        found = False
        key, value = self._normalize(key, value)
        for idx, (k, _) in enumerate(self._items):
            if k == key:
                self._items[idx] = (k, value)
                found = True
                break

        if not found:
            self._items.append((key, value))

    def __getitem__(self, key):
        return self.get(key)

    def __delitem__(self, key):
        key = self._normalize_key(key)
        pop_idx = None
        for idx, (k, _) in enumerate(self._items):
            if key == k:
                pop_idx = idx
                break

        if pop_idx is not None:
            self._items.pop(pop_idx)

    def __contains__(self, key: Any) -> bool:
        key = self._normalize_key(key)
        for k, _ in self._items:
            if key == k:
                return True
        return False

    def __iter__(self):
        return (k for k, _ in self._items)

    def __len__(self):
        return len(self._headers)

    def __eq__(self, other: HeaderTypes):
        items = sorted(self._items)
        other = sorted(self._prepare_items(other))
        return items == other

    def __repr__(self):
        SECURE = [self._normalize_key(key) for key in ["Authorization", "Proxy-Authorization"]]
        return "<%s: %s>" % (
            self.__class__.__name__,
            {k: "[secure]" if k in SECURE else ",".join(v) for k, v in self._items},
        )
