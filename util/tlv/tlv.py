from typing import Union

from util.exceptions import NotFoundError
from util.structable import Packable, Unpackable, int_to_bytes, to_bytes


class TLV(Packable, Unpackable):
    MESSAGE_CLASS = None

    tag: bytes
    value: bytes

    def __init__(self, tag, value=None):
        if isinstance(tag, int):
            tag = int_to_bytes(tag)
        if isinstance(value, Packable):
            value = value.to_bytes()
        if isinstance(tag, bytes) and isinstance(value, (bytes, bytearray, tuple, list)):
            self.tag = tag
            self.value = to_bytes(value)
        elif isinstance(tag, bytes) and isinstance(value, int):
            self.tag = tag
            self.value = int_to_bytes(value)
        elif isinstance(tag, bytes):
            self.tag = tag
            self.value = value or b""
        else:
            raise TypeError("Invalid argument types")

    @classmethod
    def parse_tag(cls, data: Union[list, bytes]):
        raise NotImplementedError

    @classmethod
    def parse_length(cls, data: Union[list, bytes]):
        raise NotImplementedError

    @classmethod
    def parse_tag_length_value(cls, data: Union[list, bytes]) -> (bytes, bytes, bytes):
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, array):
        tag, _, value = cls.parse_tag_length_value(array)
        return cls(tag, value)

    def to_bytes(self):
        raise NotImplementedError

    def to_message(self):
        return self.MESSAGE_CLASS.from_bytes(self.value)

    def contains_any_tags(self, *tags):
        return self.to_message().contains_any_tags(*tags)

    def contains_all_tags(self, *tags):
        return self.to_message().contains_all_tags(*tags)

    def find_all_by_tag(self, tag):
        return self.to_message().find_all_by_tag(tag)

    def find_by_tag_else_throw(self, tag, error=None):
        return self.to_message().find_by_tag_else_throw(tag, error)

    def find_by_tag_else(self, tag, fallback=None):
        return self.to_message().find_by_tag_else(tag, fallback)

    def __repr__(self):
        return f"{self.__class__.__name__}(tag={self.tag.hex()}, value={self.value.hex()})"


def parse_tag(tag):
    if isinstance(tag, int):
        return int_to_bytes(tag, byteorder="big")
    elif isinstance(tag, (bytes, bytearray, list, tuple)):
        return bytes(tag)
    elif isinstance(tag, str):
        return bytes.fromhex(tag)
    else:
        raise TypeError(f"Invalid argument type for tag {tag}")


class EmptyTag:
    def __init__(self):
        pass

    @property
    def value(self):
        return


class TLVMessage(Packable, Unpackable):
    CLASS = TLV

    def __init__(self, data=()):
        if isinstance(data, (bytes, bytearray)):
            self.tags = self.get_tags_from_bytes(data)
        elif isinstance(data, (list, tuple)):
            self.tags = [tag for tag in data if tag is not None]
        else:
            raise TypeError("Invalid argument type for tags")

    @property
    def value(self):
        return self.tags

    @classmethod
    def from_bytes(cls, array):
        tags = cls.get_tags_from_bytes(array)
        return cls(tags)

    @classmethod
    def get_tags_from_bytes(cls, array):
        tags = []
        index = 0
        while index < len(array):
            tag, length, data = cls.CLASS.parse_tag_length_value(array[index:])
            tags.append(cls.CLASS(tag, data))
            index += len(tag) + len(length) + len(data)
        return tags

    def to_bytes(self):
        return to_bytes(self.tags)

    def __repr__(self):
        return f"{self.__class__.__name__}(tags={self.tags})"

    def find(self, predicate):
        return next((tag for tag in self.tags if predicate(tag)), None)

    def to_ber_tlv_message(self):
        return self

    def contains_any_tags(self, *tag):
        values = {tag.tag for tag in self.tags}
        return any(parse_tag(tag) in values for tag in tag)

    def contains_all_tags(self, *tag):
        values = {tag.tag for tag in self.tags}
        return all(parse_tag(tag) in values for tag in tag)

    def find_all_by_tag(self, tag):
        tag_bytes = parse_tag(tag)
        return self.__class__([tag for tag in self.tags if tag.tag == tag_bytes])

    def find_by_tag_else_throw(self, tag, error=None):
        result = self.find_by_tag_else(tag, fallback=...)

        if result is ...:
            if isinstance(error, Exception):
                raise error
            raise NotFoundError(error or f"Tag {tag} not found")

        return result

    def find_by_tag_else(self, tag, fallback=None):
        tag_bytes = parse_tag(tag)
        return next((tag for tag in self.tags if tag.tag == tag_bytes), fallback)

    def find_by_tag_else_empty(self, tag):
        return self.find_by_tag_else(tag, EmptyTag())
