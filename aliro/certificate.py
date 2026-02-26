import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PROFILE0000_ID = b"\x00\x00"
PROFILE0000_DEFAULT_SERIAL = b"\x01"
PROFILE0000_DEFAULT_ISSUER = b"issuer"
PROFILE0000_DEFAULT_SUBJECT = b"subject"
PROFILE0000_DEFAULT_NOT_BEFORE = b"200101000000Z"
PROFILE0000_DEFAULT_NOT_AFTER = b"490101000000Z"
PROFILE0000_NOT_BEFORE = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
PROFILE0000_NOT_AFTER = datetime(2049, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

OID_COMMON_NAME = bytes.fromhex("550403")
OID_EC_PUBLIC_KEY = bytes.fromhex("2A8648CE3D0201")
OID_SECP256R1 = bytes.fromhex("2A8648CE3D030107")
OID_ECDSA_WITH_SHA256 = bytes.fromhex("2A8648CE3D040302")
OID_AUTHORITY_KEY_IDENTIFIER = bytes.fromhex("551D23")
OID_BASIC_CONSTRAINTS = bytes.fromhex("551D13")
OID_KEY_USAGE = bytes.fromhex("551D0F")
KEY_USAGE_DIGITAL_SIGNATURE = b"\x07\x80"


def _der_encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, byteorder="big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_encode_length(len(value)) + value


def _der_read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("missing DER length")
    first = data[offset]
    offset += 1
    if (first & 0x80) == 0:
        return first, offset

    length_len = first & 0x7F
    if length_len == 0:
        raise ValueError("indefinite DER length is not supported")
    end = offset + length_len
    if end > len(data):
        raise ValueError("truncated DER length")
    return int.from_bytes(data[offset:end], byteorder="big"), end


def _der_read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("missing DER tag")
    tag = data[offset]
    length, value_offset = _der_read_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[value_offset:end], end


def _der_sequence(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


def _der_set(*items: bytes) -> bytes:
    return _der_tlv(0x31, b"".join(items))


def _der_integer(value: bytes) -> bytes:
    if len(value) == 0:
        raise ValueError("INTEGER value is empty")
    normalized = value.lstrip(b"\x00") or b"\x00"
    if normalized[0] & 0x80:
        normalized = b"\x00" + normalized
    return _der_tlv(0x02, normalized)


def _der_oid(value: bytes) -> bytes:
    return _der_tlv(0x06, value)


def _der_utf8(value: bytes) -> bytes:
    return _der_tlv(0x0C, value)


def _der_octet_string(value: bytes) -> bytes:
    return _der_tlv(0x04, value)


def _der_bit_string(value: bytes) -> bytes:
    return _der_tlv(0x03, value)


def _der_time(value: bytes) -> bytes:
    if len(value) == 13:
        return _der_tlv(0x17, value)
    if len(value) == 15:
        return _der_tlv(0x18, value)
    raise ValueError(f"invalid time encoding length {len(value)}")


def _der_name_common_name(value: bytes) -> bytes:
    return _der_sequence(_der_set(_der_sequence(_der_oid(OID_COMMON_NAME), _der_utf8(value))))


def _normalize_serial_number(value: int | bytes | None) -> bytes:
    if value is None:
        return PROFILE0000_DEFAULT_SERIAL
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
    _ = _der_time(encoded)
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


def _parse_profile0000(reader_cert: bytes) -> dict[str, bytes]:  # noqa: C901
    profile = {
        "serial": PROFILE0000_DEFAULT_SERIAL,
        "issuer": PROFILE0000_DEFAULT_ISSUER,
        "not_before": PROFILE0000_DEFAULT_NOT_BEFORE,
        "not_after": PROFILE0000_DEFAULT_NOT_AFTER,
        "subject": PROFILE0000_DEFAULT_SUBJECT,
    }

    try:
        outer_tag, outer_value, outer_end = _der_read_tlv(reader_cert, 0)
        if outer_tag != 0x30 or outer_end != len(reader_cert):
            raise ValueError("invalid profile0000 outer sequence")

        profile_tag, profile_value, offset = _der_read_tlv(outer_value, 0)
        if profile_tag != 0x04:
            raise ValueError("missing profile field")
        if profile_value != PROFILE0000_ID:
            raise ValueError(f"unsupported profile {profile_value.hex()}")

        data_tag, data_value, offset = _der_read_tlv(outer_value, offset)
        if data_tag != 0x30:
            raise ValueError("missing profile0000 data sequence")
        if offset != len(outer_value):
            raise ValueError("unexpected trailing profile0000 data")

        data_offset = 0
        while data_offset < len(data_value):
            field_tag, field_value, data_offset = _der_read_tlv(data_value, data_offset)
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
                profile["public_key"] = field_value
            elif field_tag == 0x86:
                profile["signature"] = field_value
            else:
                raise ValueError(f"unexpected profile0000 field tag 0x{field_tag:02x}")

        if "public_key" not in profile or "signature" not in profile:
            raise ValueError("missing mandatory public_key/signature field")
        if profile["public_key"][0] != 0x00:
            raise ValueError("invalid public_key bit-string prefix")
        if profile["signature"][0] != 0x00:
            raise ValueError("invalid signature bit-string prefix")
        _ = _der_time(profile["not_before"])
        _ = _der_time(profile["not_after"])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Invalid reader_cert profile0000: {exc}") from exc

    return profile


def decompress_profile0000_to_x509_der(
    reader_cert: bytes,
    issuer_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    profile = _parse_profile0000(reader_cert)
    issuer_public_key_bytes = issuer_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    authority_key_identifier = hashlib.sha1(issuer_public_key_bytes).digest()

    signature_algorithm = _der_sequence(_der_oid(OID_ECDSA_WITH_SHA256))
    issuer_name = _der_name_common_name(profile["issuer"])
    subject_name = _der_name_common_name(profile["subject"])
    validity = _der_sequence(_der_time(profile["not_before"]), _der_time(profile["not_after"]))
    subject_public_key_info = _der_sequence(
        _der_sequence(_der_oid(OID_EC_PUBLIC_KEY), _der_oid(OID_SECP256R1)),
        _der_bit_string(profile["public_key"]),
    )
    extensions = _der_tlv(
        0xA3,
        _der_sequence(
            _der_sequence(
                _der_oid(OID_AUTHORITY_KEY_IDENTIFIER),
                _der_octet_string(_der_sequence(_der_tlv(0x80, authority_key_identifier))),
            ),
            _der_sequence(
                _der_oid(OID_BASIC_CONSTRAINTS),
                _der_tlv(0x01, b"\xff"),
                _der_octet_string(_der_sequence()),
            ),
            _der_sequence(
                _der_oid(OID_KEY_USAGE),
                _der_tlv(0x01, b"\xff"),
                _der_octet_string(_der_bit_string(KEY_USAGE_DIGITAL_SIGNATURE)),
            ),
        ),
    )
    tbs_certificate = _der_sequence(
        _der_tlv(0xA0, _der_integer(b"\x02")),
        _der_integer(profile["serial"]),
        signature_algorithm,
        issuer_name,
        validity,
        subject_name,
        subject_public_key_info,
        extensions,
    )
    return _der_sequence(
        tbs_certificate,
        signature_algorithm,
        _der_bit_string(profile["signature"]),
    )


def compress_x509_to_profile0000(certificate: x509.Certificate | bytes) -> bytes:
    """Compress an X509 certificate into profile0000 DER format."""
    if isinstance(certificate, (bytes, bytearray)):
        parsed_certificate = x509.load_der_x509_certificate(bytes(certificate))
    elif isinstance(certificate, x509.Certificate):
        parsed_certificate = certificate
    else:
        raise TypeError("certificate must be x509.Certificate or DER bytes")

    serial_bytes = _normalize_serial_number(parsed_certificate.serial_number)
    issuer_name_bytes = _name_common_name_bytes(parsed_certificate.issuer, "issuer")
    subject_name_bytes = _name_common_name_bytes(parsed_certificate.subject, "subject")
    not_before_bytes = _datetime_to_profile_time(parsed_certificate.not_valid_before_utc)
    not_after_bytes = _datetime_to_profile_time(parsed_certificate.not_valid_after_utc)
    _ = _der_time(not_before_bytes)
    _ = _der_time(not_after_bytes)

    public_key = parsed_certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("certificate public key must be EC")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("certificate public key curve must be secp256r1")

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    public_key_bit_string = b"\x00" + public_key_bytes
    signature_bit_string = b"\x00" + parsed_certificate.signature

    profile_field = _der_tlv(0x04, PROFILE0000_ID)
    profile_data = bytearray()
    if serial_bytes != PROFILE0000_DEFAULT_SERIAL:
        profile_data.extend(_der_tlv(0x80, serial_bytes))
    if issuer_name_bytes != PROFILE0000_DEFAULT_ISSUER:
        profile_data.extend(_der_tlv(0x81, issuer_name_bytes))
    if not_before_bytes != PROFILE0000_DEFAULT_NOT_BEFORE:
        profile_data.extend(_der_tlv(0x82, not_before_bytes))
    if not_after_bytes != PROFILE0000_DEFAULT_NOT_AFTER:
        profile_data.extend(_der_tlv(0x83, not_after_bytes))
    if subject_name_bytes != PROFILE0000_DEFAULT_SUBJECT:
        profile_data.extend(_der_tlv(0x84, subject_name_bytes))
    profile_data.extend(_der_tlv(0x85, public_key_bit_string))
    profile_data.extend(_der_tlv(0x86, signature_bit_string))
    data_field = _der_tlv(0x30, bytes(profile_data))
    return _der_tlv(0x30, profile_field + data_field)


def generate_profile0000_certificate(
    issuer_private_key: ec.EllipticCurvePrivateKey,
    subject_public_key: ec.EllipticCurvePublicKey,
    serial_number: int | bytes | None = None,
    issuer_name: str | bytes | None = None,
    subject_name: str | bytes | None = None,
    not_before: datetime | str | bytes | None = None,
    not_after: datetime | str | bytes | None = None,
) -> bytes:
    """Build a profile0000 certificate, optionally overriding default certificate fields.

    - `serial_number` accepts positive `int` or raw bytes.
    - `issuer_name`/`subject_name` accept `str` or UTF-8 bytes.
    - `not_before`/`not_after` accept UTC `datetime`, or ASN.1 UTC/Generalized
      time text (YYMMDDhhmmssZ / YYYYMMDDhhmmssZ).
    """
    serial_bytes = _normalize_serial_number(serial_number)
    issuer_name_bytes = _normalize_name(issuer_name, PROFILE0000_DEFAULT_ISSUER)
    subject_name_bytes = _normalize_name(subject_name, PROFILE0000_DEFAULT_SUBJECT)
    not_before_bytes = _normalize_profile_time(not_before, PROFILE0000_DEFAULT_NOT_BEFORE)
    not_after_bytes = _normalize_profile_time(not_after, PROFILE0000_DEFAULT_NOT_AFTER)

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

    return compress_x509_to_profile0000(certificate)


def verify_profile1000_certificate(
    reader_cert: bytes,
    issuer_public_key: ec.EllipticCurvePublicKey,
    subject_public_key: ec.EllipticCurvePublicKey,
):
    try:
        decompressed_der = decompress_profile0000_to_x509_der(reader_cert, issuer_public_key)
        certificate = x509.load_der_x509_certificate(decompressed_der)
    except ValueError as exc:
        raise ValueError("Generated reader_cert failed local decompression/DER parse") from exc

    try:
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    except InvalidSignature as exc:
        raise ValueError(
            "Generated reader_cert failed local signature verification against reader_private_key"
        ) from exc

    cert_subject_public_key = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    expected_subject_public_key = subject_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if cert_subject_public_key != expected_subject_public_key:
        raise ValueError("Generated reader_cert subject key does not match AUTH1 signing key")
