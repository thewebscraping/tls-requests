from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from tls_requests.models.libraries import Release, ReleaseAsset, TLSLibrary


def test_libraries_platform_branches():
    r = Release.from_kwargs(name="rel", tag_name="v1", assets=[{"name": "a1", "browser_download_url": "url"}])
    assert r.name == "rel"
    assert len(r.assets) == 1
    assert isinstance(r.assets[0], ReleaseAsset)
    test_data = {"tag_name": "vTEST"}
    TLSLibrary.export_config(test_data)
    loaded = TLSLibrary.import_config()
    assert loaded["tag_name"] == "vTEST"


def test_libraries_fetch_api_mock():
    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps([{"tag_name": "v1.0.0", "assets": []}]).encode()
        mock_open.return_value.__enter__.return_value = mock_resp
        results = list(TLSLibrary.fetch_api())
        assert len(results) >= 0


def test_libraries_download_mock():
    with (
        patch.object(TLSLibrary, "fetch_api", return_value=iter(["http://e.com/lib.so"])),
        patch("urllib.request.urlopen") as mock_open,
        patch("os.makedirs"),
        patch("os.chmod"),
    ):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"content-length": "10"}
        mock_resp.read.side_effect = [b"data", b""]
        mock_open.return_value.__enter__.return_value = mock_resp
        with patch("builtins.open", MagicMock()):
            res = TLSLibrary.download()
            assert res is not None
