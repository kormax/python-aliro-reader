import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import List

from aliro.signaling_bitmask import SignalingBitmask
from util.structable import represent


class KeyType(str, Enum):
    SECP256R1 = "secp256r1"


# Map legacy integer key_type values to the new string enum
_LEGACY_KEY_TYPE_MAP = {
    2: KeyType.SECP256R1,
}


def _parse_key_type(value) -> KeyType:
    """Parse key type from string or legacy integer."""
    if isinstance(value, int):
        return _LEGACY_KEY_TYPE_MAP.get(value, KeyType.SECP256R1)
    return KeyType(value)


def _parse_hex_value(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return bytes.fromhex(str(value))


@dataclass
class Endpoint:
    last_used_at: int
    counter: int
    key_type: KeyType
    public_key: bytes
    persistent_key: bytes
    identifier: bytes | None = None
    issued_at: bytes | None = None
    expires_at: bytes | None = None
    last_fci_template: bytes | None = None
    last_protocol_version: bytes | None = None
    last_auth_flow: str | None = None
    last_signaling_bitmask: SignalingBitmask | None = None

    @property
    def id(self):
        return hashlib.sha1(self.public_key).digest()[:6]

    @classmethod
    def from_dict(cls, endpoint: dict):
        identifier = endpoint.get("identifier")
        if isinstance(identifier, (bytes, bytearray)):
            identifier = identifier.hex()
        issued_at = _parse_hex_value(endpoint.get("issued_at"))
        expires_at = _parse_hex_value(endpoint.get("expires_at"))
        last_fci_template = _parse_hex_value(endpoint.get("last_fci_template") or endpoint.get("fci_template"))
        last_protocol_version = _parse_hex_value(
            endpoint.get("last_protocol_version") or endpoint.get("protocol_version")
        )
        last_auth_flow = endpoint.get("last_auth_flow")
        signaling_bitmask = SignalingBitmask.parse(endpoint.get("last_signaling_bitmask"))
        return Endpoint(
            endpoint.get("last_used_at", 0),
            endpoint.get("counter", 0),
            _parse_key_type(endpoint.get("key_type", "secp256r1")),
            bytes.fromhex(endpoint.get("public_key", "04" + ("00" * 32))),
            bytes.fromhex(endpoint.get("persistent_key", "00" * 32)),
            identifier=bytes.fromhex(identifier) if identifier else None,
            issued_at=issued_at,
            expires_at=expires_at,
            last_fci_template=last_fci_template,
            last_protocol_version=last_protocol_version,
            last_auth_flow=last_auth_flow,
            last_signaling_bitmask=signaling_bitmask,
        )

    def to_dict(self):
        result = {
            "last_used_at": self.last_used_at,
            "counter": self.counter,
            "identifier": self.identifier.hex() if self.identifier else None,
            "key_type": self.key_type.value,
            "public_key": self.public_key.hex(),
            "persistent_key": self.persistent_key.hex(),
            "issued_at": self.issued_at.hex() if self.issued_at else None,
            "expires_at": self.expires_at.hex() if self.expires_at else None,
            "last_fci_template": self.last_fci_template.hex() if self.last_fci_template else None,
            "last_protocol_version": self.last_protocol_version.hex() if self.last_protocol_version else None,
            "last_auth_flow": self.last_auth_flow,
            "last_signaling_bitmask": self.last_signaling_bitmask.to_names()
            if self.last_signaling_bitmask is not None
            else None,
        }
        return result

    def __repr__(self) -> str:
        return (
            f"Endpoint(last_used_at={self.last_used_at}, counter={self.counter}"
            + f", identifier={self.identifier.hex() if self.identifier else None} key_type={represent(self.key_type)}"
            + f", public_key={self.public_key.hex()}; persistent_key={self.persistent_key.hex()}"
            + f", issued_at={self.issued_at.hex() if self.issued_at else None}"
            + f", expires_at={self.expires_at.hex() if self.expires_at else None}"
            + f", last_fci_template={self.last_fci_template.hex() if self.last_fci_template else None}"
            + f", last_protocol_version={self.last_protocol_version.hex() if self.last_protocol_version else None}"
            + f", last_auth_flow={self.last_auth_flow}"
            + f", last_signaling_bitmask={self.last_signaling_bitmask!r}"
            + ")"
        )


@dataclass
class Issuer:
    public_key: bytes
    endpoints: List[Endpoint]

    @property
    def id(self):
        return hashlib.sha256(b"key-identifier" + self.public_key).digest()[:8]

    @classmethod
    def from_dict(cls, issuer: dict):
        return Issuer(
            public_key=bytes.fromhex(issuer.get("public_key", "00" * 32)),
            endpoints=[Endpoint.from_dict(endpoint) for _, endpoint in issuer.get("endpoints", {}).items()],
        )

    def to_dict(self):
        return {
            "public_key": self.public_key.hex(),
            "endpoints": {endpoint.id.hex(): endpoint.to_dict() for endpoint in self.endpoints},
        }

    def __repr__(self) -> str:
        return f"Issuer(public_key={self.public_key.hex()}, endpoints={self.endpoints})"
