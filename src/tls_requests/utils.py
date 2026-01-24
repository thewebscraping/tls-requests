from __future__ import annotations

import base64
import importlib
import logging
from typing import Any, AnyStr, Union

FORMAT = "[%(asctime)s] %(levelname)-8s %(name)s:%(funcName)s:%(lineno)d - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def import_module(name: Union[str, list[str]]) -> Any:
    modules = name if isinstance(name, list) else [name]
    for module_name in modules:
        if isinstance(module_name, str):
            try:
                module = importlib.import_module(module_name)
                return module
            except ImportError:
                pass
    return None


chardet = import_module(["charset_normalizer", "chardet"])
orjson = import_module(["orjson"])
if orjson:
    jsonlib = orjson
else:
    import json

    jsonlib = json


def get_logger(name: str = "TLSRequests", level: Union[int, str] = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(FORMAT, datefmt=DATE_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def to_bytes(value: Any, encoding: str = "utf-8", *, lower: bool = False) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return value
    return to_str(value, encoding).encode(encoding)


def to_str(
    value: Any,
    encoding: str = "utf-8",
    *,
    lower: bool = False,
) -> str:
    if value is None:
        return ""

    value = value.decode(encoding) if isinstance(value, (bytes, bytearray)) else value
    if isinstance(value, (dict, list, tuple, set)):
        value = json_dumps(
            value if isinstance(value, dict) else list(value),
            **dict(
                ensure_ascii=True if str(encoding).lower() == "ascii" else False,
                default=str,
            ),
        )

    if isinstance(value, bool):
        lower = True

    if lower:
        return str(value).lower()

    return str(value)


def to_base64(value: Union[dict, str, bytes], encoding: str = "utf-8") -> str:
    return base64.b64encode(to_bytes(value, encoding)).decode(encoding)


def b64decode(value: AnyStr) -> bytes:
    return base64.b64decode(value)


def to_json(value: Union[str, bytes], **kwargs) -> dict:
    if isinstance(value, dict):
        return value
    try:
        json_data = jsonlib.loads(value, **kwargs)
        return json_data
    except jsonlib.JSONDecodeError:
        raise jsonlib.JSONDecodeError


def json_dumps(value, **kwargs) -> str:
    try:
        if orjson:
            kwargs = {"default": kwargs.pop("default", None)}

        json_data = jsonlib.dumps(value, **kwargs)
        if isinstance(json_data, bytes):
            json_data = json_data.decode("utf-8")
        return json_data
    except jsonlib.JSONDecodeError:
        raise jsonlib.JSONDecodeError
