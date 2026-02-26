from enum import Enum
from typing import Union

from util.structable import to_bytes

from .tlv import TLV, TLVMessage


class BerTLVTagClass(Enum):
    UNIVERSAL = 0b00
    APPLICATION = 0b01
    CONTEXT_SPECIFIC = 0b10
    PRIVATE = 0b11

    @staticmethod
    def from_value(value):
        for tag_class in BerTLVTagClass:
            if tag_class.value == value:
                return tag_class
        return None


class BerTLV(TLV):
    MESSAGE_CLASS = None

    @classmethod
    def parse_tag(cls, data: Union[list, bytes]):
        index = 0
        tag = [data[index]]

        # Process the tag
        tag_extension_left = (tag[-1] & 0b00011111) == 0b00011111
        index += 1
        while tag_extension_left:
            tag.append(data[index])
            tag_extension_left = (tag[-1] & 0b10000000) > 0
            index += 1
        return bytes(tag)

    @classmethod
    def parse_length(cls, data: Union[list, bytes]):
        index = 0
        # Process the length
        length = [data[index]]
        index += 1
        if (length[0] & 0b10000000) != 0:
            length_length = length[0] & 0b01111111
            if length_length > 0:
                length += data[index : index + length_length]
            else:
                raise NotImplementedError("Indefinite long form is not supported")
        index += len(length) - 1
        return length

    @classmethod
    def parse_tag_length_value(cls, array):
        index = 0
        tag = cls.parse_tag(array[index:])
        index += len(tag)

        length = cls.parse_length(array[index:])
        index += len(length)

        # Process the value
        if (length[0] & 0b10000000) == 0:
            length_value = length[0]
        else:
            length_value = int.from_bytes(bytes(length[1:]), byteorder="big")

        data = array[index : index + length_value]

        if len(data) < length_value:
            raise ValueError(f"Could not parse {cls.__name__} from {bytes(array).hex()}")

        return bytes(tag), bytes(length), data

    @property
    def tag_is_constructed(self):
        return (self.tag[0] & 0b00100000) != 0

    @property
    def tag_class(self):
        return BerTLVTagClass.from_value((self.tag[0] & 0b11000000) >> 6)

    def to_bytes(self):
        value = to_bytes(self.value)
        if len(value) <= 127:
            length = bytes([len(value)])
        else:
            size = len(value)
            length_bytes = []
            while size > 0xFF:
                length_bytes.append(size & 0xFF)
                size = size >> 8
            if len(length_bytes) > 127:
                raise ValueError(f"Value size is too big {len(length_bytes)} > 127")
            length = bytes([len(length_bytes)] + length_bytes)

        return self.tag + length + value


class BerTLVMessage(TLVMessage):
    CLASS = BerTLV


BerTLV.MESSAGE_CLASS = BerTLVMessage
