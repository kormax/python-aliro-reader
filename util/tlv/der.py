from typing import Union

from util.structable import to_bytes

from .ber import BerTLV
from .tlv import TLVMessage


class DerTLV(BerTLV):
    MESSAGE_CLASS = None

    @classmethod
    def primitive(cls, tag: int, value=b"") -> "DerTLV":
        return cls(tag, to_bytes(value))

    @classmethod
    def sequence(cls, *items) -> "DerTLV":
        return cls.primitive(0x30, b"".join(to_bytes(item) for item in items))

    @classmethod
    def set(cls, *items) -> "DerTLV":
        return cls.primitive(0x31, b"".join(to_bytes(item) for item in items))

    @classmethod
    def integer(cls, value: int | bytes) -> "DerTLV":
        if isinstance(value, int):
            if value < 0:
                raise ValueError("negative DER INTEGER values are not supported")
            encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), byteorder="big")
        else:
            encoded = bytes(value)

        if len(encoded) == 0:
            raise ValueError("INTEGER value is empty")
        normalized = encoded.lstrip(b"\x00") or b"\x00"
        if normalized[0] & 0x80:
            normalized = b"\x00" + normalized
        return cls.primitive(0x02, normalized)

    @classmethod
    def oid(cls, value: bytes) -> "DerTLV":
        return cls.primitive(0x06, value)

    @classmethod
    def utf8_string(cls, value: str | bytes) -> "DerTLV":
        if isinstance(value, str):
            value = value.encode("utf-8")
        return cls.primitive(0x0C, value)

    @classmethod
    def octet_string(cls, value: bytes) -> "DerTLV":
        return cls.primitive(0x04, value)

    @classmethod
    def bit_string(cls, value: bytes) -> "DerTLV":
        return cls.primitive(0x03, value)

    @classmethod
    def time(cls, value: str | bytes) -> "DerTLV":
        if isinstance(value, str):
            value = value.encode("ascii")
        if len(value) == 13:
            return cls.primitive(0x17, value)
        if len(value) == 15:
            return cls.primitive(0x18, value)
        raise ValueError(f"invalid time encoding length {len(value)}")

    @classmethod
    def boolean(cls, value: bool) -> "DerTLV":
        return cls.primitive(0x01, b"\xff" if value else b"\x00")

    @classmethod
    def context_primitive(cls, tag_number: int, value=b"") -> "DerTLV":
        if not 0 <= tag_number <= 30:
            raise ValueError("context-specific tag number out of range")
        return cls.primitive(0x80 | tag_number, value)

    @classmethod
    def context_constructed(cls, tag_number: int, value=b"") -> "DerTLV":
        if not 0 <= tag_number <= 30:
            raise ValueError("context-specific tag number out of range")
        return cls.primitive(0xA0 | tag_number, value)

    @classmethod
    def parse_tag(cls, data: Union[list, bytes]):
        tag = super().parse_tag(data)
        # DER requires minimal high-tag-number encoding.
        if (tag[0] & 0x1F) == 0x1F and len(tag) > 1 and tag[1] == 0x80:
            raise ValueError("non-canonical DER tag encoding")
        return tag

    @classmethod
    def parse_length(cls, data: Union[list, bytes]):
        try:
            length = super().parse_length(data)
        except NotImplementedError as exc:
            raise ValueError("indefinite DER length is not supported") from exc
        first = length[0]

        # DER forbids indefinite form.
        if first == 0x80:
            raise ValueError("indefinite DER length is not supported")

        if (first & 0x80) == 0:
            return length

        length_of_length = first & 0x7F
        if length_of_length == 0:
            raise ValueError("indefinite DER length is not supported")

        if len(length) != 1 + length_of_length:
            raise ValueError("truncated DER length")

        # DER requires shortest length encoding.
        if length[1] == 0x00:
            raise ValueError("non-canonical DER length encoding")

        if length_of_length == 1 and length[1] < 0x80:
            raise ValueError("non-canonical DER length encoding")

        return length

    def to_bytes(self):
        value = to_bytes(self.value)
        length_value = len(value)

        if length_value < 0x80:
            length = bytes([length_value])
        else:
            length_bytes = length_value.to_bytes((length_value.bit_length() + 7) // 8, byteorder="big")
            if len(length_bytes) > 0x7F:
                raise ValueError(f"Value size is too big {len(length_bytes)} > 127")
            length = bytes([0x80 | len(length_bytes)]) + length_bytes

        return self.tag + length + value


class DerTLVMessage(TLVMessage):
    CLASS = DerTLV


DerTLV.MESSAGE_CLASS = DerTLVMessage
