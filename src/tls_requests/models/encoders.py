from __future__ import annotations

import binascii
import os
from io import BufferedReader, BytesIO, TextIOWrapper
from mimetypes import guess_type
from typing import Any, AsyncIterator, Dict, Iterator, List, Mapping, Optional, Tuple, TypeVar, cast
from urllib.parse import urlencode

from ..types import BufferTypes, ByteOrStr, RequestData, RequestFiles, RequestFileValue, RequestJson
from ..utils import to_bytes, to_str

__all__ = (
    "JsonEncoder",
    "UrlencodedEncoder",
    "MultipartEncoder",
    "StreamEncoder",
)

T = TypeVar("T", bound="BaseEncoder")


def guess_content_type(fp: str) -> str:
    content_type, _ = guess_type(fp)
    return content_type or "application/octet-stream"


def format_header(name: str, value: ByteOrStr, encoding: str = "ascii") -> bytes:
    if isinstance(value, bytes):
        value = value.decode("utf-8")

    value = value.translate({10: "%0A", 13: "%0D", 34: "%22"})
    return ('%s="%s"' % (name, value)).encode(encoding)


def get_boundary():
    return binascii.hexlify(os.urandom(16))


def iter_buffer(buffer: BufferTypes, chunk_size: int = 65_536):
    buffer.seek(0)
    while chunk := buffer.read(chunk_size):
        yield chunk


class BaseField:
    def __init__(self, name: str, value: Any):
        self._name = name
        self._headers: Dict[bytes, bytes] = {}

    @property
    def headers(self):
        return self.render_headers()

    def render_parts(self) -> bytes:
        parts = [
            b"form-data",
            format_header("name", self._name),
        ]
        filename = getattr(self, "filename", None)
        if filename:
            parts.append(format_header("filename", filename))

        return b"; ".join(parts)

    def render_headers(self) -> bytes:
        headers = self.get_headers()
        return b"\r\n".join(b"%s: %s" % (k, v) for k, v in headers.items()) + b"\r\n\r\n"

    def render_data(self, chunk_size: int = 65_536) -> Iterator[bytes]:
        yield b""

    def render(self, chunk_size: int = 65_536) -> Iterator[bytes]:
        yield self.render_headers()
        yield from self.render_data(chunk_size)

    def get_headers(self) -> Dict[bytes, bytes]:
        self._headers[b"Content-Disposition"] = self.render_parts()
        content_type = getattr(self, "content_type", None)
        if content_type:
            self._headers[b"Content-Type"] = (
                content_type.encode("ascii") if isinstance(content_type, str) else content_type
            )
        return self._headers


class DataField(BaseField):
    def __init__(self, name: str, value: Any) -> None:
        super(DataField, self).__init__(name, value)
        self.value = to_str(value)

    def render_data(self, chunk_size: int = 65_536) -> Iterator[bytes]:
        yield self.value.encode("utf-8")


class FileField(BaseField):
    def __init__(self, name: str, value: RequestFileValue):
        super(FileField, self).__init__(name, value)
        self.filename, self._buffer, self.content_type = self.unpack(value)

    def unpack(self, value: RequestFileValue) -> Tuple[str, BufferTypes, str]:
        filename, content_type = None, None
        if isinstance(value, tuple):
            if len(value) > 1:
                filename, buffer, *args = value
                if args:
                    content_type = args[0]
            else:
                buffer = value[0]

        elif isinstance(value, str):
            buffer = value.encode("utf-8")
        else:
            buffer = value

        if isinstance(buffer, (TextIOWrapper, BufferedReader)):
            if not filename:
                _, filename = os.path.split(str(buffer.name))

            if not content_type:
                content_type = guess_content_type(str(buffer.name))

            if buffer.mode != "rb":
                buffer.close()
                buffer = open(buffer.name, "rb")

        elif isinstance(buffer, bytes):
            buffer = BytesIO(buffer)
        elif not hasattr(buffer, "read"):
            raise ValueError

        return str(filename or "upload"), cast(BufferTypes, buffer), str(content_type or "application/octet-stream")

    def render_data(self, chunk_size: int = 65_536) -> Iterator[bytes]:
        yield from iter_buffer(self._buffer, chunk_size)


class BaseEncoder:
    _chunk_size = 65_536

    @property
    def headers(self) -> dict:
        return self.get_headers()

    @property
    def closed(self):
        return bool(getattr(self, "_is_closed", False))

    def get_headers(self) -> dict:
        return {}

    def render(self) -> Iterator[bytes]:
        buffer = getattr(self, "_buffer", None)
        if buffer:
            yield from iter_buffer(buffer, self._chunk_size)
        yield b""

    def close(self) -> None:
        if not self.closed:
            setattr(self, "_is_closed", True)
            buffer = getattr(self, "_buffer", None)
            if buffer:
                buffer.flush()
                buffer.close()

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self.render():
            yield chunk

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.render():
            yield chunk

    def __enter__(self: T) -> T:
        return self

    def __exit__(self, *args, **kwargs):
        self.close()


class MultipartEncoder(BaseEncoder):
    def __init__(
        self,
        data: Optional[RequestData] = None,
        files: Optional[RequestFiles] = None,
        boundary: Optional[bytes] = None,
        *,
        chunk_size: int = 65_536,
        **kwargs,
    ) -> None:
        self._chunk_size = chunk_size
        self._is_closed = False
        self.fields = self._prepare_fields(data, files)
        self.boundary = boundary if boundary and isinstance(boundary, bytes) else get_boundary()

    @property
    def headers(self) -> dict:
        if self.fields:
            return self.get_headers()
        return {}

    def get_headers(self):
        return {b"Content-Type": b"multipart/form-data; boundary=%s" % self.boundary}

    def render(self) -> Iterator[bytes]:
        if self.fields:
            for field in self.fields:
                yield b"--%s\r\n" % self.boundary
                yield b"".join(field.render(self._chunk_size))
                yield b"\r\n"
            yield b"--%s--\r\n" % self.boundary
        yield b""

    def _prepare_fields(self, data: Optional[RequestData], files: Optional[RequestFiles]):
        fields: List[BaseField] = []
        if isinstance(data, Mapping):
            for name, value in data.items():
                if isinstance(value, (bytes, str, int, float, bool)):
                    fields.append(DataField(name=to_str(name), value=value))
                else:
                    for item in value:
                        fields.append(DataField(name=to_str(name), value=item))

        if isinstance(files, Mapping):
            for file_name, file_value in files.items():
                fields.append(FileField(name=to_str(file_name), value=file_value))
        return fields


class JsonEncoder(BaseEncoder):
    def __init__(self, data: Optional[RequestData], *, chunk_size: int = 65_536, **kwargs):
        self._buffer = self._prepare_fields(data)
        self._chunk_size = chunk_size
        self._is_closed = False

    def get_headers(self):
        return {b"Content-Type": b"application/json"}

    def _prepare_fields(self, data: Optional[RequestData]):
        if data is not None:
            return BytesIO(to_bytes(data))
        return None


class UrlencodedEncoder(BaseEncoder):
    def __init__(self, data: Optional[RequestData], *, chunk_size: int = 65_536, **kwargs):
        self._buffer = self._prepare_fields(data)
        self._chunk_size = chunk_size
        self._is_closed = False

    def get_headers(self):
        return {b"Content-Type": b"application/x-www-form-urlencoded"}

    def _prepare_fields(self, data: Optional[RequestData]):
        fields = []
        if isinstance(data, Mapping):
            for name, value in data.items():
                if isinstance(value, (bytes, str, int, float, bool)):
                    fields.append((name, to_str(value)))
                else:
                    for item in value:
                        fields.append((name, to_str(item)))

            return BytesIO(urlencode(fields, doseq=True).encode("utf-8"))
        return None


class StreamEncoder(BaseEncoder):
    def __init__(
        self,
        data: Optional[RequestData] = None,
        files: Optional[RequestFiles] = None,
        json: Optional[RequestJson] = None,
        *,
        chunk_size: Optional[int] = 65_536,
        **kwargs,
    ):
        self._chunk_size = chunk_size if isinstance(chunk_size, int) else 65_536
        self._is_closed = False
        if files is not None:
            self._stream: BaseEncoder = MultipartEncoder(data, files)
        elif data is not None:
            self._stream = UrlencodedEncoder(data)
        elif json is not None:
            self._stream = JsonEncoder(json)
        else:
            self._stream = BaseEncoder()

    def render(self) -> Iterator[bytes]:
        yield from self._stream
        self._is_closed = True

    def get_headers(self) -> dict:
        return self._stream.get_headers()

    @classmethod
    def from_bytes(cls, raw: bytes, *, chunk_size: Optional[int] = None) -> "StreamEncoder":
        ret = cls(chunk_size=chunk_size)
        setattr(ret._stream, "_buffer", BytesIO(raw))
        return ret

    def close(self):
        super().close()
        self._stream.close()

    def __exit__(self, *args, **kwargs):
        self.close()
