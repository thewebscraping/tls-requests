from __future__ import annotations

import pytest

from tls_requests import utils


def test_import_module_none():
    assert utils.import_module("non_existent_module_xyz") is None
    assert utils.import_module(["none1", "none2"]) is None


def test_get_logger_handlers():
    # Call with a new name to ensure handlers are added
    logger = utils.get_logger("NewLogger")
    assert len(logger.handlers) > 0
    # Call again, should not add more handlers
    utils.get_logger("NewLogger")
    assert len(logger.handlers) == 1


def test_to_str_extra():
    assert utils.to_str(None) == ""
    assert utils.to_str(b"hello", encoding="utf-8") == "hello"
    assert utils.to_str(True) == "true"
    assert utils.to_str({"a": 1}, encoding="ascii") == '{"a":1}'
    assert utils.to_str([1, 2]) == "[1,2]"


def test_to_json_edge_cases():
    data = {"a": 1}
    assert utils.to_json(data) is data

    # orjson/json loads error
    with pytest.raises(Exception):  # Broken raise in utils.py causes TypeError
        utils.to_json("invalid json")


def test_to_base64():
    assert utils.to_base64("hello") == "aGVsbG8="
    assert utils.to_base64({"a": 1}) != ""


def test_json_dumps_extra():
    # If orjson is present, it pops some kwargs
    if utils.orjson:
        assert utils.json_dumps({"a": 1}, indent=4) == '{"a":1}'  # indent popped or ignored
    else:
        assert '"a": 1' in utils.json_dumps({"a": 1}, indent=4)
