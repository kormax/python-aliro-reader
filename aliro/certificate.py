import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import ClassVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from util.structable import Packable, Unpackable, UnpackableData
from util.tlv.der import DerTLV, DerTLVMessage

PROFILE0000_ID = b"\x00\x00"

OID_COMMON_NAME = bytes.fromhex("550403")
OID_EC_PUBLIC_KEY = bytes.fromhex("2A8648CE3D0201")
OID_SECP256R1 = bytes.fromhex("2A8648CE3D030107")
OID_ECDSA_WITH_SHA256 = bytes.fromhex("2A8648CE3D040302")
OID_AUTHORITY_KEY_IDENTIFIER = bytes.fromhex("551D23")
OID_BASIC_CONSTRAINTS = bytes.fromhex("551D13")
OID_KEY_USAGE = bytes.fromhex("551D0F")
KEY_USAGE_DIGITAL_SIGNATURE = b"\x07\x80"


def _normalize_serial_number(value: int | bytes | None) -> bytes:
    if value is None:
        return Profile0000Certificate.DEFAULT_SERIAL
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("serial_number must be positive")
        encoded = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    else:
        encoded = bytes(value)
        if len(encoded) == 0:
            raise ValueError("serial_number cannot be empty")
    normalized = encoded.lstrip(b"\x00")
    if len(normalized) == 0:
        raise ValueError("serial_number cannot be zero")
    return normalized


def _normalize_name(value: str | bytes | None, default: bytes) -> bytes:
    if value is None:
        return default
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        encoded = bytes(value)
    if len(encoded) == 0:
        raise ValueError("name cannot be empty")
    return encoded


def _datetime_to_profile_time(value: datetime) -> bytes:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    if 1950 <= value.year <= 2049:
        return value.strftime("%y%m%d%H%M%SZ").encode("ascii")
    return value.strftime("%Y%m%d%H%M%SZ").encode("ascii")


def _normalize_profile_time(value: datetime | str | bytes | None, default: bytes) -> bytes:
    if value is None:
        encoded = default
    elif isinstance(value, datetime):
        encoded = _datetime_to_profile_time(value)
    elif isinstance(value, str):
        encoded = value.encode("ascii")
    else:
        encoded = bytes(value)
    _ = DerTLV.time(encoded)
    return encoded


def _profile_time_to_datetime(value: bytes) -> datetime:
    text = value.decode("ascii")
    if len(value) == 13:
        if not text.endswith("Z"):
            raise ValueError("UTC time must end with Z")
        year_two_digits = int(text[0:2])
        year = 1900 + year_two_digits if year_two_digits >= 50 else 2000 + year_two_digits
        month = int(text[2:4])
        day = int(text[4:6])
        hour = int(text[6:8])
        minute = int(text[8:10])
        second = int(text[10:12])
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    if len(value) == 15:
        if not text.endswith("Z"):
            raise ValueError("Generalized time must end with Z")
        year = int(text[0:4])
        month = int(text[4:6])
        day = int(text[6:8])
        hour = int(text[8:10])
        minute = int(text[10:12])
        second = int(text[12:14])
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    raise ValueError("invalid profile time length")


def _name_common_name_bytes(name: x509.Name, field: str) -> bytes:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not values:
        raise ValueError(f"{field} name does not contain commonName")
    return values[0].value.encode("utf-8")


@dataclass(frozen=True)
class Profile0000Certificate(Packable, Unpackable):
    DEFAULT_SERIAL: ClassVar[bytes] = b"\x01"
    DEFAULT_ISSUER: ClassVar[bytes] = b"issuer"
    DEFAULT_SUBJECT: ClassVar[bytes] = b"subject"
    DEFAULT_NOT_BEFORE: ClassVar[bytes] = b"200101000000Z"
    DEFAULT_NOT_AFTER: ClassVar[bytes] = b"490101000000Z"

    serial: bytes
    issuer: bytes
    not_before: bytes
    not_after: bytes
    subject: bytes
    subject_public_key: ec.EllipticCurvePublicKey
    signature: bytes

    def __post_init__(self):
        if len(self.serial) == 0:
            raise ValueError("serial_number cannot be empty")
        if len(self.issuer) == 0:
            raise ValueError("issuer cannot be empty")
        if len(self.subject) == 0:
            raise ValueError("subject cannot be empty")
        if not isinstance(self.subject_public_key, ec.EllipticCurvePublicKey):
            raise TypeError("subject_public_key must be an EC public key")
        if not isinstance(self.subject_public_key.curve, ec.SECP256R1):
            raise ValueError("subject_public_key curve must be secp256r1")
        if len(self.signature) == 0:
            raise ValueError("signature cannot be empty")
        _ = DerTLV.time(self.not_before)
        _ = DerTLV.time(self.not_after)
        if _profile_time_to_datetime(self.not_before) >= _profile_time_to_datetime(self.not_after):
            raise ValueError("not_before must be earlier than not_after")

    @classmethod
    def from_profile_der(cls, reader_cert: bytes) -> "Profile0000Certificate":  # noqa: C901
        profile = {
            "serial": cls.DEFAULT_SERIAL,
            "issuer": cls.DEFAULT_ISSUER,
            "not_before": cls.DEFAULT_NOT_BEFORE,
            "not_after": cls.DEFAULT_NOT_AFTER,
            "subject": cls.DEFAULT_SUBJECT,
        }
        subject_public_key_bytes = None
        signature = None

        try:
            outer = DerTLVMessage.from_bytes(reader_cert).tags
            if len(outer) != 1 or outer[0].tag != b"\x30":
                raise ValueError("invalid profile0000 outer sequence")

            outer_fields = DerTLVMessage.from_bytes(outer[0].value).tags
            if len(outer_fields) < 2:
                raise ValueError("missing profile0000 data sequence")
            if len(outer_fields) != 2:
                raise ValueError("unexpected trailing profile0000 data")

            profile_tag = outer_fields[0]
            if profile_tag.tag != b"\x04":
                raise ValueError("missing profile field")
            if profile_tag.value != PROFILE0000_ID:
                raise ValueError(f"unsupported profile {profile_tag.value.hex()}")

            data_tag = outer_fields[1]
            if data_tag.tag != b"\x30":
                raise ValueError("missing profile0000 data sequence")

            for field in DerTLVMessage.from_bytes(data_tag.value).tags:
                field_tag = field.tag[0]
                field_value = field.value
                if field_tag == 0x80:
                    profile["serial"] = field_value
                elif field_tag == 0x81:
                    profile["issuer"] = field_value
                elif field_tag == 0x82:
                    profile["not_before"] = field_value
                elif field_tag == 0x83:
                    profile["not_after"] = field_value
                elif field_tag == 0x84:
                    profile["subject"] = field_value
                elif field_tag == 0x85:
                    if len(field_value) == 0 or field_value[0] != 0x00:
                        raise ValueError("invalid public_key bit-string prefix")
                    subject_public_key_bytes = field_value[1:]
                elif field_tag == 0x86:
                    if len(field_value) == 0 or field_value[0] != 0x00:
                        raise ValueError("invalid signature bit-string prefix")
                    signature = field_value[1:]
                else:
                    raise ValueError(f"unexpected profile0000 field tag 0x{field_tag:02x}")

            if subject_public_key_bytes is None or signature is None:
                raise ValueError("missing mandatory public_key/signature field")
            subject_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                subject_public_key_bytes,
            )
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Invalid reader_cert profile0000: {exc}") from exc

        return cls(
            serial=profile["serial"],
            issuer=profile["issuer"],
            not_before=profile["not_before"],
            not_after=profile["not_after"],
            subject=profile["subject"],
            subject_public_key=subject_public_key,
            signature=signature,
        )

    @classmethod
    def from_bytes(cls, data: UnpackableData) -> "Profile0000Certificate":
        return cls.from_profile_der(bytes(data))

    @classmethod
    def from_x509(cls, certificate: x509.Certificate | bytes | bytearray) -> "Profile0000Certificate":
        if isinstance(certificate, (bytes, bytearray)):
            parsed_certificate = x509.load_der_x509_certificate(bytes(certificate))
        elif isinstance(certificate, x509.Certificate):
            parsed_certificate = certificate
        else:
            raise TypeError("certificate must be x509.Certificate or DER bytes")

        serial = _normalize_serial_number(parsed_certificate.serial_number)
        issuer = _name_common_name_bytes(parsed_certificate.issuer, "issuer")
        subject = _name_common_name_bytes(parsed_certificate.subject, "subject")
        not_before = _datetime_to_profile_time(parsed_certificate.not_valid_before_utc)
        not_after = _datetime_to_profile_time(parsed_certificate.not_valid_after_utc)

        public_key = parsed_certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("certificate public key must be EC")
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("certificate public key curve must be secp256r1")

        return cls(
            serial=serial,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            subject=subject,
            subject_public_key=public_key,
            signature=parsed_certificate.signature,
        )

    @classmethod
    def generate(
        cls,
        issuer_private_key: ec.EllipticCurvePrivateKey,
        subject_public_key: ec.EllipticCurvePublicKey,
        serial_number: int | bytes | None = None,
        issuer_name: str | bytes | None = None,
        subject_name: str | bytes | None = None,
        not_before: datetime | str | bytes | None = None,
        not_after: datetime | str | bytes | None = None,
    ) -> "Profile0000Certificate":
        serial_bytes = _normalize_serial_number(serial_number)
        issuer_name_bytes = _normalize_name(issuer_name, cls.DEFAULT_ISSUER)
        subject_name_bytes = _normalize_name(subject_name, cls.DEFAULT_SUBJECT)
        not_before_bytes = _normalize_profile_time(not_before, cls.DEFAULT_NOT_BEFORE)
        not_after_bytes = _normalize_profile_time(not_after, cls.DEFAULT_NOT_AFTER)

        not_before_dt = _profile_time_to_datetime(not_before_bytes)
        not_after_dt = _profile_time_to_datetime(not_after_bytes)
        if not_before_dt >= not_after_dt:
            raise ValueError("not_before must be earlier than not_after")

        issuer_name_der = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name_bytes.decode("utf-8"))])
        subject_name_der = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name_bytes.decode("utf-8"))])

        certificate = (
            x509.CertificateBuilder()
            .serial_number(int.from_bytes(serial_bytes, byteorder="big"))
            .issuer_name(issuer_name_der)
            .subject_name(subject_name_der)
            .not_valid_before(not_before_dt)
            .not_valid_after(not_after_dt)
            .public_key(subject_public_key)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
        )
        return cls.from_x509(certificate)

    def to_profile_der(self) -> bytes:
        subject_public_key_bytes = self.subject_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        profile_field = DerTLV.primitive(0x04, PROFILE0000_ID)
        profile_data = []
        if self.serial != self.DEFAULT_SERIAL:
            profile_data.append(DerTLV.context_primitive(0, self.serial))
        if self.issuer != self.DEFAULT_ISSUER:
            profile_data.append(DerTLV.context_primitive(1, self.issuer))
        if self.not_before != self.DEFAULT_NOT_BEFORE:
            profile_data.append(DerTLV.context_primitive(2, self.not_before))
        if self.not_after != self.DEFAULT_NOT_AFTER:
            profile_data.append(DerTLV.context_primitive(3, self.not_after))
        if self.subject != self.DEFAULT_SUBJECT:
            profile_data.append(DerTLV.context_primitive(4, self.subject))
        profile_data.append(DerTLV.context_primitive(5, b"\x00" + subject_public_key_bytes))
        profile_data.append(DerTLV.context_primitive(6, b"\x00" + self.signature))
        data_field = DerTLV.sequence(*profile_data)
        return DerTLV.sequence(profile_field, data_field).to_bytes()

    def to_bytes(self) -> bytes:
        return self.to_profile_der()

    def to_x509_certificate(self, issuer_public_key: ec.EllipticCurvePublicKey):
        der_certificate = self.to_x509_der_bytes(issuer_public_key)
        return x509.load_der_x509_certificate(der_certificate)

    def to_x509_der_bytes(self, issuer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        subject_public_key_bytes = self.subject_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        issuer_public_key_bytes = issuer_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        authority_key_identifier = hashlib.sha1(issuer_public_key_bytes).digest()

        signature_algorithm = DerTLV.sequence(DerTLV.oid(OID_ECDSA_WITH_SHA256))
        issuer_name = DerTLV.sequence(
            DerTLV.set(
                DerTLV.sequence(
                    DerTLV.oid(OID_COMMON_NAME),
                    DerTLV.utf8_string(self.issuer),
                )
            )
        )
        subject_name = DerTLV.sequence(
            DerTLV.set(
                DerTLV.sequence(
                    DerTLV.oid(OID_COMMON_NAME),
                    DerTLV.utf8_string(self.subject),
                )
            )
        )
        validity = DerTLV.sequence(DerTLV.time(self.not_before), DerTLV.time(self.not_after))
        subject_public_key_info = DerTLV.sequence(
            DerTLV.sequence(DerTLV.oid(OID_EC_PUBLIC_KEY), DerTLV.oid(OID_SECP256R1)),
            DerTLV.bit_string(b"\x00" + subject_public_key_bytes),
        )
        extensions = DerTLV.context_constructed(
            3,
            DerTLV.sequence(
                DerTLV.sequence(
                    DerTLV.oid(OID_AUTHORITY_KEY_IDENTIFIER),
                    DerTLV.octet_string(DerTLV.sequence(DerTLV.context_primitive(0, authority_key_identifier))),
                ),
                DerTLV.sequence(
                    DerTLV.oid(OID_BASIC_CONSTRAINTS),
                    DerTLV.boolean(True),
                    DerTLV.octet_string(DerTLV.sequence()),
                ),
                DerTLV.sequence(
                    DerTLV.oid(OID_KEY_USAGE),
                    DerTLV.boolean(True),
                    DerTLV.octet_string(DerTLV.bit_string(KEY_USAGE_DIGITAL_SIGNATURE)),
                ),
            ),
        )
        tbs_certificate = DerTLV.sequence(
            DerTLV.context_constructed(0, DerTLV.integer(b"\x02")),
            DerTLV.integer(self.serial),
            signature_algorithm,
            issuer_name,
            validity,
            subject_name,
            subject_public_key_info,
            extensions,
        )
        return DerTLV.sequence(
            tbs_certificate,
            signature_algorithm,
            DerTLV.bit_string(b"\x00" + self.signature),
        ).to_bytes()

    def verify(self, issuer_public_key: ec.EllipticCurvePublicKey):
        certificate = self.to_x509_certificate(issuer_public_key)
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
