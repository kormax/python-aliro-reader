import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import List

from aliro.document import ACCESS_DOCUMENT_TYPE, REVOCATION_DOCUMENT_TYPE, Document
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


def _parse_saved_documents(value):
    if not isinstance(value, list):
        return []
    parsed_documents = []
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            parsed_documents.append(Document.from_dict(item))
        except (TypeError, ValueError):
            continue
    return parsed_documents


@dataclass
class Endpoint:
    used_at: int
    counter: int
    key_type: KeyType
    public_key: bytes
    persistent_key: bytes
    key_slot: bytes | None = None
    credential_signed_timestamp: bytes | None = None
    revocation_signed_timestamp: bytes | None = None
    fci_template: bytes | None = None
    protocol_version: bytes | None = None
    auth_flow: str | None = None
    signaling_bitmask: SignalingBitmask | None = None
    documents: List[Document] = field(default_factory=list)

    @property
    def access_documents(self) -> List[Document]:
        return [document for document in self.documents if document.doc_type == ACCESS_DOCUMENT_TYPE]

    @property
    def revocation_documents(self) -> List[Document]:
        return [document for document in self.documents if document.doc_type == REVOCATION_DOCUMENT_TYPE]

    @property
    def last_access_documents(self) -> List[Document]:
        return self.access_documents

    @property
    def last_revocation_documents(self) -> List[Document]:
        return self.revocation_documents

    @property
    def id(self):
        return hashlib.sha1(self.public_key).digest()[:6]

    @classmethod
    def from_dict(cls, endpoint: dict):
        key_slot = _parse_hex_value(endpoint.get("key_slot"))
        credential_signed_timestamp = _parse_hex_value(endpoint.get("credential_signed_timestamp"))
        revocation_signed_timestamp = _parse_hex_value(endpoint.get("revocation_signed_timestamp"))
        fci_template = _parse_hex_value(endpoint.get("fci_template") or endpoint.get("last_fci_template"))
        protocol_version = _parse_hex_value(endpoint.get("protocol_version") or endpoint.get("last_protocol_version"))
        auth_flow = endpoint.get("auth_flow") or endpoint.get("last_auth_flow")
        signaling_bitmask = SignalingBitmask.parse(
            endpoint.get("signaling_bitmask") or endpoint.get("last_signaling_bitmask")
        )
        documents = _parse_saved_documents(endpoint.get("documents") or endpoint.get("last_documents"))
        if not documents:
            legacy_access_documents = _parse_saved_documents(endpoint.get("last_access_documents"))
            legacy_revocation_documents = _parse_saved_documents(endpoint.get("last_revocation_documents"))
            documents = legacy_access_documents + legacy_revocation_documents
        return Endpoint(
            endpoint.get("used_at", endpoint.get("last_used_at", 0)),
            endpoint.get("counter", 0),
            _parse_key_type(endpoint.get("key_type", "secp256r1")),
            bytes.fromhex(endpoint.get("public_key", "04" + ("00" * 32))),
            bytes.fromhex(endpoint.get("persistent_key", "00" * 32)),
            key_slot=key_slot,
            credential_signed_timestamp=credential_signed_timestamp,
            revocation_signed_timestamp=revocation_signed_timestamp,
            fci_template=fci_template,
            protocol_version=protocol_version,
            auth_flow=auth_flow,
            signaling_bitmask=signaling_bitmask,
            documents=documents,
        )

    def to_dict(self):
        result = {
            "used_at": self.used_at,
            "counter": self.counter,
            "key_slot": self.key_slot.hex() if self.key_slot else None,
            "key_type": self.key_type.value,
            "public_key": self.public_key.hex(),
            "persistent_key": self.persistent_key.hex(),
            "credential_signed_timestamp": (
                self.credential_signed_timestamp.hex() if self.credential_signed_timestamp else None
            ),
            "revocation_signed_timestamp": (
                self.revocation_signed_timestamp.hex() if self.revocation_signed_timestamp else None
            ),
            "fci_template": self.fci_template.hex() if self.fci_template else None,
            "protocol_version": self.protocol_version.hex() if self.protocol_version else None,
            "auth_flow": self.auth_flow,
            "signaling_bitmask": self.signaling_bitmask.to_names() if self.signaling_bitmask is not None else None,
            "documents": [document.to_dict() for document in self.documents],
        }
        return result

    def __repr__(self) -> str:
        return (
            f"Endpoint(used_at={self.used_at}, counter={self.counter}"
            + f", key_slot={self.key_slot.hex() if self.key_slot else None} key_type={represent(self.key_type)}"
            + f", public_key={self.public_key.hex()}; persistent_key={self.persistent_key.hex()}"
            + (
                f", credential_signed_timestamp={self.credential_signed_timestamp.hex()}"
                if self.credential_signed_timestamp
                else ", credential_signed_timestamp=None"
            )
            + (
                f", revocation_signed_timestamp={self.revocation_signed_timestamp.hex()}"
                if self.revocation_signed_timestamp
                else ", revocation_signed_timestamp=None"
            )
            + f", fci_template={self.fci_template.hex() if self.fci_template else None}"
            + f", protocol_version={self.protocol_version.hex() if self.protocol_version else None}"
            + f", auth_flow={self.auth_flow}"
            + f", signaling_bitmask={self.signaling_bitmask!r}"
            + f", documents={len(self.documents)}"
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
