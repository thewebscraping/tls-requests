from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from enum import Enum
from typing import Any, ItemsView, KeysView, List, Literal, Optional, Tuple, ValuesView

from ..exceptions import HeaderError
from ..types import ByteOrStr, HeaderTypes
from ..utils import to_str

__all__ = (
    "Headers",
    "HeaderAlias",
)

HeaderAliasTypes = Literal["*", "lower", "capitalize"]


class HeaderAlias(str, Enum):
    LOWER = "lower"
    CAPITALIZE = "capitalize"
    ALL = "*"

    @classmethod
    def contains(cls, key: Any) -> bool:
        return any(item.value == key for item in cls)


class Headers(MutableMapping):
    def __init__(self, headers: Optional[HeaderTypes] = None, *, alias: HeaderAliasTypes = "lower"):
        self.alias: HeaderAliasTypes = alias if HeaderAlias.contains(alias) else "lower"
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

    def update(self, headers: Optional[HeaderTypes]) -> None:  # type: ignore[override]
        if headers is None:
            return
        new_headers = self.__class__(headers, alias=self.alias)
        for key, _ in new_headers._items:
            if key in self:
                self.pop(key)

        self._items.extend(new_headers._items)

    def copy(self) -> "Headers":
        return self.__class__(self._items.copy(), alias=self.alias)  # type: ignore[arg-type]

    def _prepare_items(self, headers: Optional[HeaderTypes]) -> List[Tuple[str, List[str]]]:
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
            except (IndexError, ValueError):
                pass
        raise HeaderError("Invalid headers format")

    def _normalize_key(self, key: ByteOrStr) -> str:
        key = to_str(key, encoding="ascii")
        if self.alias == HeaderAlias.ALL:
            return key

        if self.alias == HeaderAlias.CAPITALIZE:
            return "-".join([s.capitalize() for s in key.split("-")])

        return key.lower()

    def _normalize_value(self, value) -> List[str]:
        if isinstance(value, dict):
            raise HeaderError("Header value cannot be a dictionary.")

        if isinstance(value, (list, tuple, set)):
            items = []
            for item in value:
                if isinstance(item, dict):
                    raise HeaderError("Header value items cannot be a dictionary.")
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
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

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
        return len(self._items)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (Mapping, list, tuple, set, self.__class__)):
            return False

        try:
            items = sorted(self._items)
            other_prepared = sorted(self._prepare_items(other))  # type: ignore
            return items == other_prepared
        except (HeaderError, TypeError):
            return False

    def __repr__(self):
        SECURE = [self._normalize_key(key) for key in ["Authorization", "Proxy-Authorization"]]
        return "<%s: %s>" % (
            self.__class__.__name__,
            {k: "[secure]" if k in SECURE else ",".join(v) for k, v in self._items},
        )
