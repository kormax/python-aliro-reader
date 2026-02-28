from dataclasses import dataclass
from datetime import datetime
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from util.structable import Packable

ACCESS_DOCUMENT_TYPE = "aliro-a"
REVOCATION_DOCUMENT_TYPE = "aliro-r"


ISSUER_SIGNED_ITEM_SCHEMA = {
    1: "digest_id",
    2: "random",
    3: "element_identifier",
    4: "element_value",
}
ACCESS_DATA_SCHEMA = {
    0: "version",
    1: "id",
    2: "access_rules",
    3: "schedules",
    4: "reader_rule_ids",
    5: "non_access_extensions",
    6: "access_extensions",
}
MSO_SCHEMA = {
    1: "version",
    2: "digest_algorithm",
    3: "value_digests",
    4: "device_key_info",
    5: "doc_type",
    6: "validity_info",
    7: "time_verification_required",
}
VALIDITY_INFO_SCHEMA = {
    1: "signed",
    2: "valid_from",
    3: "valid_until",
    4: "expected_update",
}
COSE_EC2_KEY_SCHEMA = {
    1: "kty",
    3: "alg",
    -1: "crv",
    -2: "x",
    -3: "y",
}


def _field(map_value: Any, key: int | str, default=None):
    if not isinstance(map_value, dict):
        return default
    if key in map_value:
        return map_value[key]
    key_as_text = str(key)
    if key_as_text in map_value:
        return map_value[key_as_text]
    return default


def _decode_cbor_value(value: Any) -> Any:
    if isinstance(value, cbor2.CBORTag):
        if value.tag != 24:
            return value
        try:
            return cbor2.loads(value.value)
        except Exception:
            return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return cbor2.loads(bytes(value))
        except Exception:
            return value
    return value


def _as_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _normalize_public_key(public_key: ec.EllipticCurvePublicKey | bytes | bytearray) -> ec.EllipticCurvePublicKey:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key
    if isinstance(public_key, (bytes, bytearray)):
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(public_key))
        except ValueError as exc:
            raise ValueError("public_key bytes must encode a secp256r1 point") from exc
    raise TypeError("public_key must be an EllipticCurvePublicKey or SEC1-encoded bytes")


def _project_cbor_map(map_value: Any, schema: dict[int | str, str]) -> dict[str, Any]:
    if not isinstance(map_value, dict):
        return {}
    projected: dict[str, Any] = {}
    for raw_key, field_name in schema.items():
        field_value = _field(map_value, raw_key)
        if field_value is not None:
            projected[field_name] = field_value
    return projected


def _bytes_to_hex(value: bytes | bytearray | None) -> str | None:
    if value is None:
        return None
    return bytes(value).hex()


def _bytes_from_hex(value: str | None) -> bytes | None:
    if value in (None, ""):
        return None
    return bytes.fromhex(value)


def _is_json_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float, str))


def _is_json_friendly(value: Any) -> bool:
    if _is_json_scalar(value):
        return True
    if isinstance(value, list):
        return all(_is_json_friendly(element) for element in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_friendly(item) for key, item in value.items())
    return False


def _serialize_dynamic(value: Any, *, field_name: str, output: dict[str, Any]) -> None:
    if value is None:
        output[field_name] = None
        return
    if _is_json_friendly(value):
        output[field_name] = value
        return
    output[f"{field_name}_hex"] = cbor2.dumps(value).hex()


def _deserialize_dynamic(value: dict[str, Any], field_name: str) -> Any:
    direct = value.get(field_name)
    if direct is not None:
        return direct
    encoded = value.get(f"{field_name}_hex")
    if encoded is not None:
        return cbor2.loads(bytes.fromhex(encoded))
    return None


def _datetime_to_str(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _datetime_from_str(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return value
    return value


@dataclass
class DocumentRequest(Packable):
    doc_type: str
    scopes: dict[str, bool]

    def to_cbor_map(self) -> dict[str, Any]:
        return {
            "1": cbor2.CBORTag(
                24,
                cbor2.dumps(
                    {
                        "1": {
                            self.doc_type: self.scopes,
                        },
                        "5": self.doc_type,
                    }
                ),
            )
        }

    def to_bytes(self) -> bytes:
        return cbor2.dumps(self.to_cbor_map())

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_type": self.doc_type,
            "scopes": {str(scope): bool(keep) for scope, keep in self.scopes.items()},
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DocumentRequest":
        if not isinstance(value, dict):
            raise TypeError("DocumentRequest must be deserialized from a dict")
        scopes = value.get("scopes", {})
        if not isinstance(scopes, dict):
            raise ValueError("DocumentRequest.scopes must deserialize to a dict")
        return cls(
            doc_type=str(value.get("doc_type")),
            scopes={str(scope): bool(keep) for scope, keep in scopes.items()},
        )


@dataclass
class SessionData(Packable):
    data: bytes

    def __post_init__(self):
        if not isinstance(self.data, (bytes, bytearray)):
            raise TypeError("SessionData.data must be bytes")
        self.data = bytes(self.data)

    @classmethod
    def from_cbor(cls, value: Any) -> "SessionData":
        if isinstance(value, (bytes, bytearray)):
            value = cbor2.loads(value)
        if not isinstance(value, dict):
            raise ValueError("SessionData must be a CBOR map")
        data = value.get("data")
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("SessionData.data must be present and encoded as bstr")
        return cls(data=bytes(data))

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "SessionData":
        return cls.from_cbor(data)

    def to_cbor_map(self) -> dict[str, bytes]:
        return {"data": self.data}

    def to_bytes(self) -> bytes:
        return cbor2.dumps(self.to_cbor_map())

    def to_dict(self) -> dict[str, Any]:
        return {"data_hex": self.data.hex()}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SessionData":
        if not isinstance(value, dict):
            raise TypeError("SessionData must be deserialized from a dict")
        data = _bytes_from_hex(value.get("data_hex"))
        if data is None:
            raise ValueError("SessionData.data_hex is required")
        return cls(data=data)


@dataclass
class DeviceRequest(Packable):
    version: str
    document_requests: list[DocumentRequest]

    def to_cbor_map(self) -> dict[str, Any]:
        return {
            "1": self.version,
            "2": [document_request.to_cbor_map() for document_request in self.document_requests],
        }

    def to_cbor(self) -> bytes:
        return cbor2.dumps(self.to_cbor_map())

    def to_bytes(self) -> bytes:
        return self.to_cbor()

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "document_requests": [document_request.to_dict() for document_request in self.document_requests],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DeviceRequest":
        if not isinstance(value, dict):
            raise TypeError("DeviceRequest must be deserialized from a dict")
        serialized_requests = value.get("document_requests") or []
        if not isinstance(serialized_requests, list):
            raise ValueError("DeviceRequest.document_requests must be an array")
        return cls(
            version=str(value.get("version")),
            document_requests=[DocumentRequest.from_dict(item) for item in serialized_requests],
        )


@dataclass
class AccessDataElement:
    version: Any = None
    id: bytes | None = None
    access_rules: Any = None
    schedules: Any = None
    reader_rule_ids: Any = None
    non_access_extensions: Any = None
    access_extensions: Any = None

    @classmethod
    def from_cbor(cls, value: Any) -> "AccessDataElement | None":
        if not isinstance(value, dict):
            return None
        projected = _project_cbor_map(value, ACCESS_DATA_SCHEMA)
        return cls(
            version=projected.get("version"),
            id=_as_bytes(projected.get("id")),
            access_rules=projected.get("access_rules"),
            schedules=projected.get("schedules"),
            reader_rule_ids=projected.get("reader_rule_ids"),
            non_access_extensions=projected.get("non_access_extensions"),
            access_extensions=projected.get("access_extensions"),
        )

    def to_dict(self) -> dict[str, Any]:
        serialized = {
            "version": self.version,
            "id_hex": _bytes_to_hex(self.id),
        }
        _serialize_dynamic(self.access_rules, field_name="access_rules", output=serialized)
        _serialize_dynamic(self.schedules, field_name="schedules", output=serialized)
        _serialize_dynamic(self.reader_rule_ids, field_name="reader_rule_ids", output=serialized)
        _serialize_dynamic(self.non_access_extensions, field_name="non_access_extensions", output=serialized)
        _serialize_dynamic(self.access_extensions, field_name="access_extensions", output=serialized)
        return serialized

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AccessDataElement":
        if not isinstance(value, dict):
            raise TypeError("AccessDataElement must be deserialized from a dict")
        return cls(
            version=value.get("version"),
            id=_bytes_from_hex(value.get("id_hex")),
            access_rules=_deserialize_dynamic(value, "access_rules"),
            schedules=_deserialize_dynamic(value, "schedules"),
            reader_rule_ids=_deserialize_dynamic(value, "reader_rule_ids"),
            non_access_extensions=_deserialize_dynamic(value, "non_access_extensions"),
            access_extensions=_deserialize_dynamic(value, "access_extensions"),
        )


@dataclass
class IssuerSignedItem:
    digest_id: Any = None
    random: bytes | None = None
    element_identifier: Any = None
    element_value: Any = None

    @classmethod
    def from_cbor(cls, value: Any) -> "IssuerSignedItem":
        decoded_item = _decode_cbor_value(value)
        if not isinstance(decoded_item, dict):
            return cls(element_value=decoded_item)

        projected = _project_cbor_map(decoded_item, ISSUER_SIGNED_ITEM_SCHEMA)
        element_value = _decode_cbor_value(projected.get("element_value"))
        return cls(
            digest_id=projected.get("digest_id"),
            random=_as_bytes(projected.get("random")),
            element_identifier=projected.get("element_identifier"),
            element_value=element_value,
        )

    @property
    def access_data(self) -> AccessDataElement | None:
        return AccessDataElement.from_cbor(self.element_value)

    def to_dict(self) -> dict[str, Any]:
        serialized = {
            "digest_id": self.digest_id,
            "random_hex": _bytes_to_hex(self.random),
            "element_identifier": self.element_identifier,
        }
        _serialize_dynamic(self.element_value, field_name="element_value", output=serialized)
        return serialized

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IssuerSignedItem":
        if not isinstance(value, dict):
            raise TypeError("IssuerSignedItem must be deserialized from a dict")
        return cls(
            digest_id=value.get("digest_id"),
            random=_bytes_from_hex(value.get("random_hex")),
            element_identifier=value.get("element_identifier"),
            element_value=_deserialize_dynamic(value, "element_value"),
        )


@dataclass
class CoseEc2Key:
    kty: Any = None
    alg: Any = None
    crv: Any = None
    x: bytes | None = None
    y: bytes | None = None

    @classmethod
    def from_cbor(cls, value: Any) -> "CoseEc2Key | None":
        if not isinstance(value, dict):
            return None
        projected = _project_cbor_map(value, COSE_EC2_KEY_SCHEMA)
        x = _as_bytes(projected.get("x"))
        y = _as_bytes(projected.get("y"))
        return cls(
            kty=projected.get("kty"),
            alg=projected.get("alg"),
            crv=projected.get("crv"),
            x=x,
            y=y,
        )

    @property
    def endpoint_public_key(self) -> bytes | None:
        if self.x is None or self.y is None:
            return None
        return bytes([0x04, *self.x, *self.y])

    def to_dict(self) -> dict[str, Any]:
        return {
            "kty": self.kty,
            "alg": self.alg,
            "crv": self.crv,
            "x_hex": _bytes_to_hex(self.x),
            "y_hex": _bytes_to_hex(self.y),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CoseEc2Key":
        if not isinstance(value, dict):
            raise TypeError("CoseEc2Key must be deserialized from a dict")
        return cls(
            kty=value.get("kty"),
            alg=value.get("alg"),
            crv=value.get("crv"),
            x=_bytes_from_hex(value.get("x_hex")),
            y=_bytes_from_hex(value.get("y_hex")),
        )


@dataclass
class ValidityInfo:
    signed: Any = None
    valid_from: Any = None
    valid_until: Any = None
    expected_update: Any = None

    @classmethod
    def from_cbor(cls, value: Any) -> "ValidityInfo | None":
        if not isinstance(value, dict):
            return None
        projected = _project_cbor_map(value, VALIDITY_INFO_SCHEMA)
        return cls(
            signed=projected.get("signed"),
            valid_from=projected.get("valid_from"),
            valid_until=projected.get("valid_until"),
            expected_update=projected.get("expected_update"),
        )

    def to_dict(self) -> dict[str, Any]:
        serialized = {
            "signed": _datetime_to_str(self.signed),
            "valid_from": _datetime_to_str(self.valid_from),
            "valid_until": _datetime_to_str(self.valid_until),
            "expected_update": _datetime_to_str(self.expected_update),
        }
        return serialized

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ValidityInfo":
        if not isinstance(value, dict):
            raise TypeError("ValidityInfo must be deserialized from a dict")
        return cls(
            signed=_datetime_from_str(value.get("signed")),
            valid_from=_datetime_from_str(value.get("valid_from")),
            valid_until=_datetime_from_str(value.get("valid_until")),
            expected_update=_datetime_from_str(value.get("expected_update")),
        )


@dataclass
class MobileSecurityObject:
    version: Any = None
    digest_algorithm: Any = None
    value_digests: Any = None
    device_key_info: Any = None
    doc_type: Any = None
    validity_info: ValidityInfo | None = None
    time_verification_required: Any = None

    @classmethod
    def from_cbor(cls, value: Any) -> "MobileSecurityObject | None":
        if not isinstance(value, dict):
            return None

        projected = _project_cbor_map(value, MSO_SCHEMA)
        value_digests = projected.get("value_digests")

        return cls(
            version=projected.get("version"),
            digest_algorithm=projected.get("digest_algorithm"),
            value_digests=value_digests,
            device_key_info=projected.get("device_key_info"),
            doc_type=projected.get("doc_type"),
            validity_info=ValidityInfo.from_cbor(projected.get("validity_info")),
            time_verification_required=projected.get("time_verification_required"),
        )

    @property
    def value_digest_ids(self) -> dict[str, list[Any]] | None:
        if not isinstance(self.value_digests, dict):
            return None
        return {
            namespace: sorted(namespace_digests.keys(), key=str)
            for namespace, namespace_digests in self.value_digests.items()
            if isinstance(namespace_digests, dict)
        }

    @property
    def device_key(self) -> CoseEc2Key | None:
        return CoseEc2Key.from_cbor(_field(self.device_key_info, 1))

    def to_dict(self) -> dict[str, Any]:
        serialized = {
            "version": self.version,
            "digest_algorithm": self.digest_algorithm,
            "doc_type": self.doc_type,
            "validity_info": self.validity_info.to_dict() if self.validity_info is not None else None,
            "time_verification_required": self.time_verification_required,
        }
        _serialize_dynamic(self.value_digests, field_name="value_digests", output=serialized)
        _serialize_dynamic(self.device_key_info, field_name="device_key_info", output=serialized)
        return serialized

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "MobileSecurityObject":
        if not isinstance(value, dict):
            raise TypeError("MobileSecurityObject must be deserialized from a dict")
        validity_info_value = value.get("validity_info")
        return cls(
            version=value.get("version"),
            digest_algorithm=value.get("digest_algorithm"),
            value_digests=_deserialize_dynamic(value, "value_digests"),
            device_key_info=_deserialize_dynamic(value, "device_key_info"),
            doc_type=value.get("doc_type"),
            validity_info=(
                ValidityInfo.from_dict(validity_info_value) if isinstance(validity_info_value, dict) else None
            ),
            time_verification_required=value.get("time_verification_required"),
        )


@dataclass
class IssuerAuthCoseSign1:
    protected_headers_encoded: bytes | None = None
    unprotected_headers: dict[Any, Any] | None = None
    payload: bytes | None = None
    signature: bytes | None = None

    @classmethod
    def from_cbor(cls, value: Any) -> "IssuerAuthCoseSign1 | None":
        decoded = _decode_cbor_value(value)
        if not isinstance(decoded, list) or len(decoded) != 4:
            return None

        protected_headers_encoded, unprotected_headers, payload, signature = decoded
        unprotected_map = unprotected_headers if isinstance(unprotected_headers, dict) else {}
        return cls(
            protected_headers_encoded=_as_bytes(protected_headers_encoded),
            unprotected_headers=unprotected_map,
            payload=_as_bytes(payload),
            signature=_as_bytes(signature),
        )

    @property
    def issuer_id(self) -> bytes | None:
        return _as_bytes(_field(self.unprotected_headers, 4))

    @property
    def protected_headers(self) -> dict[Any, Any] | None:
        if self.protected_headers_encoded is None:
            return None
        decoded = _decode_cbor_value(self.protected_headers_encoded)
        if isinstance(decoded, dict):
            return decoded
        return None

    @property
    def data_cbor(self) -> dict[Any, Any] | None:
        if self.payload is None:
            return None
        try:
            payload_value = cbor2.loads(self.payload)
        except Exception:
            return None
        if not isinstance(payload_value, cbor2.CBORTag) or payload_value.tag != 24:
            return None
        try:
            decoded = cbor2.loads(payload_value.value)
        except Exception:
            return None
        if isinstance(decoded, dict):
            return decoded
        return None

    @property
    def mobile_security_object(self) -> MobileSecurityObject | None:
        return MobileSecurityObject.from_cbor(self.data_cbor)

    @property
    def algorithm(self) -> int | None:
        return _as_int(_field(self.protected_headers, 1))

    def build_sig_structure(self, external_aad: bytes = b"") -> bytes:
        protected_headers_encoded = self.protected_headers_encoded
        payload = self.payload
        if protected_headers_encoded is None:
            raise ValueError("issuerAuth is missing encoded protected headers")
        if payload is None:
            raise ValueError("issuerAuth is missing payload")
        if not isinstance(external_aad, (bytes, bytearray)):
            raise TypeError("external_aad must be bytes")
        return cbor2.dumps(["Signature1", protected_headers_encoded, bytes(external_aad), payload])

    def verify(
        self,
        public_key: ec.EllipticCurvePublicKey | bytes | bytearray,
        *,
        external_aad: bytes = b"",
    ) -> None:
        if self.signature is None:
            raise ValueError("issuerAuth is missing signature")

        algorithm = self.algorithm
        if algorithm != -7:
            raise ValueError(f"Unsupported issuerAuth COSE algorithm: {algorithm!r}")

        if len(self.signature) != 64:
            raise ValueError(f"issuerAuth ES256 signature must be 64 bytes, got {len(self.signature)}")

        verifier_key = _normalize_public_key(public_key)
        to_be_signed = self.build_sig_structure(external_aad=external_aad)
        r = int.from_bytes(self.signature[:32], "big")
        s = int.from_bytes(self.signature[32:], "big")
        der_signature = encode_dss_signature(r, s)
        verifier_key.verify(der_signature, to_be_signed, ec.ECDSA(hashes.SHA256()))

    def to_dict(self) -> dict[str, Any]:
        serialized = {
            "signature_hex": _bytes_to_hex(self.signature),
            "protected_headers_encoded_hex": _bytes_to_hex(self.protected_headers_encoded),
            "payload_hex": _bytes_to_hex(self.payload),
        }
        _serialize_dynamic(self.unprotected_headers, field_name="unprotected_headers", output=serialized)
        return serialized

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IssuerAuthCoseSign1":
        if not isinstance(value, dict):
            raise TypeError("IssuerAuthCoseSign1 must be deserialized from a dict")
        signature = _bytes_from_hex(value.get("signature_hex"))
        unprotected_headers = _deserialize_dynamic(value, "unprotected_headers")
        if unprotected_headers is not None and not isinstance(unprotected_headers, dict):
            raise ValueError("IssuerAuthCoseSign1.unprotected_headers must deserialize to a dict when present")
        payload = _bytes_from_hex(value.get("payload_hex"))
        protected_headers_encoded = _bytes_from_hex(value.get("protected_headers_encoded_hex"))
        return cls(
            unprotected_headers=unprotected_headers,
            signature=signature,
            protected_headers_encoded=protected_headers_encoded,
            payload=payload,
        )


@dataclass
class Document:
    doc_type: str | None
    issuer_signed_items: dict[str, list[IssuerSignedItem]]
    issuer_auth: IssuerAuthCoseSign1 | None = None

    @property
    def issuer_signed_name_spaces(self) -> dict[str, list[dict[int, Any]]]:
        return {
            namespace: [
                {
                    1: item.digest_id,
                    2: item.random,
                    3: item.element_identifier,
                    4: item.element_value,
                }
                for item in items
            ]
            for namespace, items in self.issuer_signed_items.items()
        }

    def verify(
        self,
        public_key: ec.EllipticCurvePublicKey | bytes | bytearray,
        *,
        external_aad: bytes = b"",
        require_doc_type_match: bool = True,
    ) -> None:
        if self.issuer_auth is None:
            raise ValueError("Document does not contain parseable issuerAuth")
        self.issuer_auth.verify(public_key, external_aad=external_aad)
        if require_doc_type_match:
            mso = self.issuer_auth.mobile_security_object
            if (
                self.doc_type is not None
                and mso is not None
                and mso.doc_type is not None
                and mso.doc_type != self.doc_type
            ):
                raise ValueError(
                    f"MSO docType mismatch: issuerAuth has {mso.doc_type!r}, document has {self.doc_type!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_type": self.doc_type,
            "issuer_signed_items": {
                namespace: [item.to_dict() for item in items] for namespace, items in self.issuer_signed_items.items()
            },
            "issuer_auth": self.issuer_auth.to_dict() if self.issuer_auth is not None else None,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Document":
        if not isinstance(value, dict):
            raise TypeError("Document must be deserialized from a dict")

        serialized_items = value.get("issuer_signed_items") or {}
        if not isinstance(serialized_items, dict):
            raise ValueError("Document.issuer_signed_items must deserialize to a dict")
        issuer_signed_items = {
            namespace: [IssuerSignedItem.from_dict(item) for item in items]
            for namespace, items in serialized_items.items()
        }

        serialized_issuer_auth = value.get("issuer_auth")
        return cls(
            doc_type=value.get("doc_type"),
            issuer_signed_items=issuer_signed_items,
            issuer_auth=(
                IssuerAuthCoseSign1.from_dict(serialized_issuer_auth)
                if isinstance(serialized_issuer_auth, dict)
                else None
            ),
        )


@dataclass
class DeviceResponse:
    version: Any
    status: Any
    documents: list[Document]

    @classmethod
    def from_cbor(cls, value: Any) -> "DeviceResponse":  # noqa: C901
        if isinstance(value, (bytes, bytearray)):
            value = cbor2.loads(value)

        if not isinstance(value, dict):
            raise ValueError("ENVELOPE DeviceResponse is not a CBOR map")

        documents: list[Document] = []

        raw_documents = _field(value, 2)
        if raw_documents is not None and not isinstance(raw_documents, list):
            raise ValueError("ENVELOPE DeviceResponse field '2' must be an array when present")

        for raw_document in raw_documents or []:
            if not isinstance(raw_document, dict):
                continue

            doc_type = _field(raw_document, 5)
            issuer_signed = _field(raw_document, 1)
            issuer_signed_items: dict[str, list[IssuerSignedItem]] = {}
            issuer_auth = None

            if isinstance(issuer_signed, dict):
                raw_name_spaces = _field(issuer_signed, 1) or {}
                issuer_auth = IssuerAuthCoseSign1.from_cbor(_field(issuer_signed, 2))
                if isinstance(raw_name_spaces, dict):
                    for namespace, namespace_values in raw_name_spaces.items():
                        if not isinstance(namespace_values, list):
                            continue
                        issuer_signed_items[namespace] = [IssuerSignedItem.from_cbor(item) for item in namespace_values]

            documents.append(
                Document(
                    doc_type=doc_type,
                    issuer_signed_items=issuer_signed_items,
                    issuer_auth=issuer_auth,
                )
            )

        return cls(
            version=_field(value, 1),
            status=_field(value, 3),
            documents=documents,
        )

    @property
    def access_documents(self) -> list[Document]:
        return [document for document in self.documents if document.doc_type == ACCESS_DOCUMENT_TYPE]

    @property
    def revocation_documents(self) -> list[Document]:
        return [document for document in self.documents if document.doc_type == REVOCATION_DOCUMENT_TYPE]

    def verify(
        self,
        public_key: ec.EllipticCurvePublicKey | bytes | bytearray,
        *,
        external_aad: bytes = b"",
        doc_types: set[str] | list[str] | tuple[str, ...] | None = None,
    ) -> list[Document]:
        allowed_doc_types = set(doc_types) if doc_types is not None else None
        documents_to_verify = [
            document
            for document in self.documents
            if allowed_doc_types is None or document.doc_type in allowed_doc_types
        ]
        if not documents_to_verify:
            raise ValueError("No documents matched verification filter")
        for document in documents_to_verify:
            document.verify(public_key, external_aad=external_aad)
        return documents_to_verify

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "status": self.status,
            "documents": [document.to_dict() for document in self.documents],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DeviceResponse":
        if not isinstance(value, dict):
            raise TypeError("DeviceResponse must be deserialized from a dict")
        serialized_documents = value.get("documents") or []
        if not isinstance(serialized_documents, list):
            raise ValueError("DeviceResponse.documents must deserialize to an array")
        return cls(
            version=value.get("version"),
            status=value.get("status"),
            documents=[Document.from_dict(document) for document in serialized_documents],
        )


def parse_step_up_device_response(device_response: Any) -> DeviceResponse:
    return DeviceResponse.from_cbor(device_response)


__all__ = [
    "ACCESS_DOCUMENT_TYPE",
    "REVOCATION_DOCUMENT_TYPE",
    "DocumentRequest",
    "SessionData",
    "DeviceRequest",
    "AccessDataElement",
    "IssuerSignedItem",
    "CoseEc2Key",
    "ValidityInfo",
    "MobileSecurityObject",
    "IssuerAuthCoseSign1",
    "Document",
    "DeviceResponse",
    "parse_step_up_device_response",
]
