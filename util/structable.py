import abc
import base64
import enum
import inspect
from collections.abc import Collection, Iterable, Iterator
from enum import Enum, IntEnum
from string import printable
from typing import ForwardRef, TypeVar, Union

PRINATBLE_BYTES = set(bytes(printable, "ascii"))


def isprintable(bytestring):
    return all(b in PRINATBLE_BYTES for b in bytestring)


Packable = ForwardRef("Packable")
T = TypeVar("T")

PackableData = Union[Packable, bytearray, bytes, Iterable[int], Iterator[int], str, int]
UnpackableData = Union[bytes, bytearray, Collection[int]]
Data = PackableData


class Packable:
    @abc.abstractmethod
    def to_bytes(self) -> Union[bytearray, bytes]:
        raise NotImplementedError()


class Unpackable:
    @classmethod
    def from_bytes(cls, data: UnpackableData) -> T:
        raise NotImplementedError()


def int_to_bytes(i: int, *, byteorder="big", signed: bool = False) -> bytes:
    length = max(1, (i.bit_length() + 7 + signed) // 8)
    return i.to_bytes(length, byteorder=byteorder, signed=i < 0 or signed)


def to_bytes(data: PackableData, *, byteorder="big", signed=False) -> bytes:
    if isinstance(data, Packable):
        return data.to_bytes()
    elif hasattr(data, "to_bytes") and inspect.getfullargspec(data.to_bytes).args == ["self"]:
        return data.to_bytes()
    elif isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        return data.encode()
    elif isinstance(data, bytearray):
        return bytes(data)
    elif isinstance(data, Iterable):
        return b"".join(to_bytes(element, byteorder=byteorder, signed=signed) for element in data)
    elif isinstance(data, int):
        return int_to_bytes(data, byteorder=byteorder, signed=signed)
    elif data is None:
        return b""
    elif isinstance(data, enum.Enum):
        return to_bytes(data.value)
    raise ValueError(f"Cannot pack data {type(data)} {data}")


def represent(data: PackableData):
    if isinstance(data, Packable):
        return f"{data}"
    elif isinstance(data, (bytes, bytearray)):
        if isprintable(data):
            return f"{data}"
        else:
            return f"h'{data.hex()}'"
    elif isinstance(data, str):
        return f"'{data}'"
    elif isinstance(data, Iterable):
        return "[" + ", ".join(represent(element) for element in data) + "]"
    elif isinstance(data, IntEnum):
        return f"{data.name.upper()}({int_to_bytes(data.value).hex()})"
    elif isinstance(data, int):
        return f"0x{int_to_bytes(data).hex()}"
    raise ValueError(f"Cannot pack data {type(data)} {data}")


def from_bytes(signature: Union[T, Iterator[T]], data: UnpackableData) -> T:
    raise NotImplementedError()


# Utility functions


def chunked(source, size):
    for i in range(0, len(source), size):
        yield source[i : i + size]


def bits_to_bytes(bits):
    return bytes([int("".join(["01"[i] for i in a]), 2) for a in chunked(bits, 8)])


def unwrap_if_enum(data):
    return data.value if isinstance(data, Enum) else data


def bits(data):
    if isinstance(data, int):
        data = int_to_bytes(data)
    return [int(bit) for byte in data for bit in f"{bin(byte)[2:]:0>8}"]


def pack_into_base64_string(objects: Union[Collection[PackableData], PackableData]):
    if not isinstance(objects, tuple) and not isinstance(objects, list):
        objects = [objects]
    byte_string = b"".join((obj.to_bytes() if isinstance(obj, Packable) else bytes(obj)) for obj in objects)
    return base64.b64encode(byte_string).decode("ASCII")


def unpack_from_base64_string(string: Union[str, bytes]) -> bytes:
    if isinstance(string, str):
        string = string.encode("ASCII")
    return base64.b64decode(string)
