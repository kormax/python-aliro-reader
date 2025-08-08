import logging
import os
import time
from collections.abc import Collection
from enum import IntEnum
from typing import List, Tuple

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from entity import Endpoint, KeyType
from util.crypto import (
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    get_ec_key_public_points,
    hkdf_sha256,
    load_ec_public_key_from_bytes,
)
from util.iso7816 import ISO7816, ISO7816Application, ISO7816Command, ISO7816Instruction, ISO7816Response, ISO7816Tag
from util.structable import chunked, to_bytes
from util.tlv.ber import BerTLV, BerTLVMessage

PERSISTENT_ASTR = "Persistent**"
VOLATILE_FAST = "VolatileFast"
VOLATILE_ASTR = "Volatile****"


# Random numbers presumably used to provide entropy.
# Coincidentally, they're valid UNIX epochs
READER_CONTEXT = (1096652137).to_bytes(4, "big")
DEVICE_CONTEXT = (1317567308).to_bytes(4, "big")
AUTH0_FAST_GCM_IV = b"\x00" * 12


READER_MODE = bytes.fromhex("0000000000000000")
ENDPOINT_MODE = bytes.fromhex("0000000000000001")


def _key_hex(value):
    if value is None:
        return None
    return bytes(value).hex().upper()


class AliroTransactionType(IntEnum):
    UNLOCK = 0x01


class AliroTransactionFlags(IntEnum):
    STANDARD = 0x00
    FAST = 0x01


class AliroFlow(IntEnum):
    FAST = 0x00
    STANDARD = 0x01
    ATTESTATION = 0x02


class TransportType(IntEnum):
    NFC = CONTACTLESS = 0x5E


class AliroSecureChannel:
    sk_reader: bytes
    sk_device: bytes

    counter_reader: int
    counter_endpoint: int

    def __init__(self, sk_reader: bytes, sk_device: bytes, counter_reader=1, counter_endpoint=1):
        self.sk_reader = sk_reader
        self.sk_device = sk_device

        self.counter_reader = counter_reader
        self.counter_endpoint = counter_endpoint

    def __repr__(self) -> str:
        return (
            "AliroSecureChannel("
            + f"sk_reader={_key_hex(self.sk_reader)!r}, "
            + f"sk_device={_key_hex(self.sk_device)!r}, "
            + f"counter_reader={self.counter_reader}, "
            + f"counter_endpoint={self.counter_endpoint}"
            + ")"
        )

    def encrypt_reader_data(self, plaintext: bytes) -> bytes:
        iv = READER_MODE + self.counter_reader.to_bytes(4, "big")
        ciphertext = plaintext if not plaintext else encrypt_aes_gcm(self.sk_reader, iv, plaintext)
        self.counter_reader += 1
        return ciphertext

    def decrypt_reader_data(self, ciphertext: bytes) -> bytes:
        iv = READER_MODE + self.counter_reader.to_bytes(4, "big")
        plaintext = ciphertext if not ciphertext else decrypt_aes_gcm(self.sk_reader, iv, ciphertext)
        self.counter_reader += 1
        return plaintext

    def encrypt_endpoint_data(self, plaintext: bytes) -> bytes:
        iv = ENDPOINT_MODE + self.counter_endpoint.to_bytes(4, "big")
        ciphertext = plaintext if not plaintext else encrypt_aes_gcm(self.sk_device, iv, plaintext)
        self.counter_endpoint += 1
        return ciphertext

    def decrypt_endpoint_data(self, ciphertext: bytes) -> bytes:
        iv = ENDPOINT_MODE + self.counter_endpoint.to_bytes(4, "big")
        plaintext = ciphertext if not ciphertext else decrypt_aes_gcm(self.sk_device, iv, ciphertext)
        self.counter_endpoint += 1
        return plaintext

    def encrypt_command(self, command: ISO7816Command) -> Tuple[ISO7816Command, int]:
        ciphertext = self.encrypt_reader_data(command.data)
        return (
            ISO7816Command(
                cla=command.cla,
                ins=command.ins,
                p1=command.p1,
                p2=command.p2,
                data=ciphertext,
                le=command.le,
            ),
            self.counter_reader,
        )

    def decrypt_response(self, response: ISO7816Response) -> Tuple[ISO7816Response, int]:
        plaintext = self.decrypt_endpoint_data(response.data)
        return (
            ISO7816Response(sw1=response.sw1, sw2=response.sw2, data=plaintext),
            self.counter_endpoint,
        )

    def encrypt_response(self, response: ISO7816Response) -> Tuple[ISO7816Response, int]:
        ciphertext = self.encrypt_endpoint_data(response.data)
        return (
            ISO7816Response(sw1=response.sw1, sw2=response.sw2, data=ciphertext),
            self.counter_endpoint,
        )

    def encrypt_envelope_command_data(self, message: bytes):
        return cbor2.dumps({"data": self.encrypt_reader_data(message)})

    def decrypt_envelope_response_data(self, message: bytes):
        cbor = cbor2.loads(message)
        cbor_ciphertext = cbor["data"]
        return self.decrypt_endpoint_data(cbor_ciphertext)

    def decrypt_data(self, ciphertext: bytes) -> bytes:
        return self.decrypt_endpoint_data(ciphertext)

    def decrypt_command(self, command: ISO7816Command) -> Tuple[ISO7816Command, int]:
        plaintext = self.decrypt_reader_data(command.data)
        return (
            ISO7816Command(
                cla=command.cla,
                ins=command.ins,
                p1=command.p1,
                p2=command.p2,
                data=plaintext,
                le=command.le,
            ),
            self.counter_reader,
        )

    def transceive_plain_secure(self, tag: ISO7816Tag, command: ISO7816Command) -> ISO7816Response:
        """Sends a plain command and expects a secure response"""
        decrypted_response, _ = self.decrypt_response(tag.transceive(command))
        return decrypted_response

    def transceive_secure_secure(self, tag: ISO7816Tag, command: ISO7816Command) -> ISO7816Response:
        """Sends a secure command and expects a secure response"""
        encrypted_command, _ = self.encrypt_command(command)

        encrypted_response = tag.transceive(encrypted_command)
        decrypted_response, _ = self.decrypt_response(encrypted_response)
        return decrypted_response

    def transceive_plain_plain(self, tag: ISO7816Tag, command: ISO7816Command) -> ISO7816Response:
        """Sends a plain command and expects a plain response"""
        return tag.transceive(command)

    def transceive(self, tag: ISO7816Tag, command: ISO7816Command) -> ISO7816Response:
        return self.transceive_secure_secure(tag, command)


class AliroSecureContext:
    exchange: AliroSecureChannel
    ble: AliroSecureChannel
    step_up: AliroSecureChannel
    uwb_ranging_sk: bytes
    cryptogram_sk: bytes

    def __init__(
        self,
        exchange_sk_reader,
        exchange_sk_device,
        ble_sk_reader=None,
        ble_sk_device=None,
        step_up_sk_reader=None,
        step_up_sk_device=None,
        uwb_ranging_sk=None,
        cryptogram_sk=None,
    ):
        self.exchange = AliroSecureChannel(
            sk_reader=exchange_sk_reader,
            sk_device=exchange_sk_device,
            counter_endpoint=1,
            counter_reader=1,
        )

        self.ble = (
            AliroSecureChannel(sk_reader=ble_sk_reader, sk_device=ble_sk_device)
            if ble_sk_reader and ble_sk_device
            else None
        )
        self.step_up = (
            AliroSecureChannel(sk_reader=step_up_sk_reader, sk_device=step_up_sk_device)
            if step_up_sk_reader and step_up_sk_device
            else None
        )

        self.uwb_ranging_sk = uwb_ranging_sk
        self.cryptogram_sk = cryptogram_sk

    def __repr__(self) -> str:
        return (
            "AliroSecureContext("
            + (
                ", ".join(
                    e
                    for e in [
                        f"exchange={self.exchange!r}" if self.exchange else None,
                        f"ble={self.ble!r}" if self.ble else None,
                        f"step_up={self.step_up!r}" if self.step_up else None,
                        f"uwb_ranging_sk={self.uwb_ranging_sk.hex()}" if self.uwb_ranging_sk else None,
                        f"cryptogram_sk={self.cryptogram_sk.hex()}" if self.cryptogram_sk else None,
                    ]
                    if e is not None
                )
            )
            + ")"
        )


class ProtocolError(Exception):
    pass


def _reader_instance_identifier_value(reader_group_identifier: bytes, reader_instance_identifier: bytes) -> bytes:
    if len(reader_instance_identifier) == 32:
        return reader_instance_identifier
    return reader_group_identifier + reader_instance_identifier


def find_endpoint_by_identifier(endpoints: List[Endpoint], identifier):
    return next((e for e in endpoints if e.identifier == identifier), None)


def generate_ec_key_if_provided_is_none(
    private_key: ec.EllipticCurvePrivateKey | None,
):
    return (
        ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())
        if private_key
        else ec.generate_private_key(ec.SECP256R1())
    )


def fast_auth(
    tag: ISO7816Tag,
    fci_proprietary_template: List[bytes],
    protocol_version: bytes,
    transport_type: int,
    transaction_flags: int,
    transaction_code: AliroTransactionType,
    reader_group_identifier: bytes,
    reader_instance_identifier: bytes,
    reader_public_key: ec.EllipticCurvePublicKey,
    reader_ephemeral_public_key: ec.EllipticCurvePublicKey,
    transaction_identifier: bytes,
    endpoints: List[Endpoint],
    key_size=16,
) -> Tuple[ec.EllipticCurvePublicKey, Endpoint | None, AliroSecureContext | None]:
    (
        reader_ephemeral_public_key_x,
        reader_ephemeral_public_key_y,
    ) = get_ec_key_public_points(reader_ephemeral_public_key)
    reader_ephemeral_public_key_bytes = bytes([0x04, *reader_ephemeral_public_key_x, *reader_ephemeral_public_key_y])
    reader_public_key_x, _ = get_ec_key_public_points(reader_public_key)
    reader_instance_identifier_value = _reader_instance_identifier_value(
        reader_group_identifier, reader_instance_identifier
    )
    fci_proprietary_bytes = to_bytes(fci_proprietary_template)

    command_data = BerTLVMessage(
        [
            BerTLV(0x41, value=transaction_flags),
            BerTLV(0x42, value=transaction_code),
            BerTLV(0x5C, value=protocol_version),
            BerTLV(0x87, value=reader_ephemeral_public_key_bytes),
            BerTLV(0x4C, value=transaction_identifier),
            BerTLV(0x4D, value=reader_group_identifier + reader_instance_identifier),
        ]
    )

    command = ISO7816Command(cla=0x80, ins=0x80, p1=0x00, p2=0x00, data=command_data, le=None)
    logging.info(f"AUTH0 CMD = {command}")
    response = tag.transceive(command)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"AUTH0 INVALID STATUS {response.sw}")
    logging.info(f"AUTH0 RES = {response}")
    message = BerTLVMessage.from_bytes(response.data)

    endpoint_ephemeral_public_key = message.find_by_tag_else_empty(0x86).value
    if endpoint_ephemeral_public_key is None:
        raise ProtocolError("Response does not contain endpoint_ephemeral_public_key_tag 0x86")

    endpoint_ephemeral_public_key = load_ec_public_key_from_bytes(endpoint_ephemeral_public_key)
    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(endpoint_ephemeral_public_key)

    returned_cryptogram = message.find_by_tag_else_empty(0x9D).value
    if returned_cryptogram is None:
        logging.info("AUTH0 skipped")
        return endpoint_ephemeral_public_key, None, None

    endpoint = None
    matched_endpoint = None
    matched_secure = None
    # FAST gives us no way to find out the identity of endpoint from the data for security reasons,
    # so we have to iterate over all provisioned endpoints and hope that it's there
    logging.info("Searching for an endpoint with matching cryptogram...")
    for endpoint in endpoints:
        k_persistent = endpoint.persistent_key
        endpoint_public_key_bytes = endpoint.public_key
        endpoint_public_key: ec.EllipticCurvePublicKey = load_ec_public_key_from_bytes(endpoint_public_key_bytes)
        endpoint_public_key_x, _ = get_ec_key_public_points(endpoint_public_key)

        logging.info(
            "AUTH0 fast cryptogram verify attempt endpoint=%s",
            endpoint.id.hex(),
        )
        logging.info("AUTH0 fast cryptogram verify start endpoint_pub_key_x=%s", endpoint_public_key_x.hex())
        salt = [
            reader_public_key_x,
            VOLATILE_FAST,
            reader_instance_identifier_value,
            transport_type,
            BerTLV(0x5C, value=protocol_version),
            reader_ephemeral_public_key_x,
            transaction_identifier,
            [transaction_flags, transaction_code],
            fci_proprietary_bytes,
            endpoint_public_key_x,
        ]

        okm = hkdf_sha256(k_persistent, salt, endpoint_ephemeral_public_key_x, 0xA0)
        cryptogram_sk = okm[0x00:0x20]

        try:
            plaintext = decrypt_aes_gcm(cryptogram_sk, AUTH0_FAST_GCM_IV, returned_cryptogram)
        except Exception as exc:
            logging.info(f"AUTH0 fast cryptogram decrypt failed: {exc}")
            continue
        logging.info(f"AUTH0 fast decrypted plaintext={plaintext.hex()}")
        try:
            message = BerTLVMessage.from_bytes(plaintext)
        except Exception as exc:
            logging.info(f"AUTH0 fast plaintext TLV parse failed: {exc}")
            continue
        auth_status = message.find_by_tag_else(0x5E, None)
        issued_at = message.find_by_tag_else(0x91, None)
        expires_at = message.find_by_tag_else(0x92, None)
        auth_status_value = auth_status.value if auth_status else None
        issued_at = issued_at.value if issued_at else None
        expires_at = expires_at.value if expires_at else None
        if auth_status_value is None or issued_at is None or expires_at is None:
            logging.info("AUTH0 fast cryptogram plaintext missing auth_status/issued/expires")
            continue
        if len(auth_status_value) != 2 or len(issued_at) != 0x14 or len(expires_at) != 0x14:
            logging.info("AUTH0 fast cryptogram plaintext length mismatch")
            continue

        logging.info(
            "AUTH0 fast cryptogram verified"
            f" auth_status=0x{auth_status_value.hex()}"
            f" issued_at={issued_at}"
            f" expires_at={expires_at}"
        )

        exchange_sk_reader = okm[0x20:0x40]
        exchange_sk_device = okm[0x40:0x60]

        ble_input_material = okm[0x60:0x80]

        uwb_ranging_sk = okm[0x80:0xA0]

        ble_sk_reader = hkdf_sha256(
            ble_input_material,
            b"\x00" * 32,
            b"BleSKReader",
            key_size * 2,
        )
        ble_sk_device = hkdf_sha256(
            ble_input_material,
            b"\x00" * 32,
            b"BleSKDevice",
            key_size * 2,
        )

        secure = AliroSecureContext(
            exchange_sk_reader=exchange_sk_reader,
            exchange_sk_device=exchange_sk_device,
            step_up_sk_reader=None,
            step_up_sk_device=None,
            ble_sk_reader=ble_sk_reader,
            ble_sk_device=ble_sk_device,
            uwb_ranging_sk=uwb_ranging_sk,
            cryptogram_sk=cryptogram_sk,
        )
        logging.info(f"AUTH0 fast cryptogram verified for Endpoint({endpoint.id.hex()})")
        logging.info(f"Derived secure context: {secure!r}")
        endpoint.issued_at = issued_at
        endpoint.expires_at = expires_at
        endpoint.last_auth_status = auth_status_value
        matched_endpoint = endpoint
        matched_secure = secure
        break
    return endpoint_ephemeral_public_key, matched_endpoint, matched_secure


def standard_auth(  # noqa: C901
    tag: ISO7816Tag,
    fci_proprietary_template: List[bytes],
    protocol_version: bytes,
    transport_type: int,
    transaction_flags: int,
    transaction_code: AliroTransactionType,
    reader_group_identifier: bytes,
    reader_instance_identifier: bytes,
    reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    reader_private_key: ec.EllipticCurvePrivateKey,
    transaction_identifier: bytes,
    endpoint_ephemeral_public_key: ec.EllipticCurvePublicKey,
    endpoints: List[Endpoint],
    key_size=16,
) -> Tuple[bytes | None, Endpoint | None, AliroSecureContext | None]:
    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(endpoint_ephemeral_public_key)
    reader_ephemeral_public_key_x, _ = get_ec_key_public_points(reader_ephemeral_public_key)

    authentication_hash_input_material = [
        BerTLV(0x4D, value=reader_group_identifier + reader_instance_identifier),
        BerTLV(0x86, value=endpoint_ephemeral_public_key_x),
        BerTLV(0x87, value=reader_ephemeral_public_key_x),
        BerTLV(0x4C, value=transaction_identifier),
        BerTLV(0x93, value=READER_CONTEXT),
    ]
    authentication_hash_input = to_bytes(authentication_hash_input_material)
    logging.info(f"authentication_hash_input={authentication_hash_input.hex()}")

    signature = reader_private_key.sign(authentication_hash_input, ec.ECDSA(hashes.SHA256()))
    logging.info(f"signature={signature.hex()} ({hex(len(signature))})")
    x, y = decode_dss_signature(signature)
    signature_point_form = bytes([*x.to_bytes(32, "big"), *y.to_bytes(32, "big")])
    logging.info(f"signature_point_form={signature_point_form.hex()} ({hex(len(signature_point_form))})")
    logging.info(f"transaction_flags={transaction_flags} transaction_code={transaction_code}")

    data = BerTLVMessage(
        [
            BerTLV(0x41, value=transaction_flags),
            BerTLV(0x9E, value=signature_point_form),
        ]
    )
    command = ISO7816Command(cla=0x80, ins=0x81, p1=0x00, p2=0x00, data=data)

    logging.info(f"AUTH1 COMMAND {command}")
    response = tag.transceive(command)
    logging.info(f"AUTH1 RESPONSE: {response}")
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"AUTH1 INVALID STATUS {response.sw}")

    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(endpoint_ephemeral_public_key)
    reader_ephemeral_public_key_x, _ = get_ec_key_public_points(reader_ephemeral_public_key)
    reader_public_key_x, _ = get_ec_key_public_points(reader_private_key.public_key())
    reader_instance_identifier_value = _reader_instance_identifier_value(
        reader_group_identifier, reader_instance_identifier
    )
    fci_proprietary_bytes = to_bytes(fci_proprietary_template)

    shared_key = reader_ephemeral_private_key.exchange(ec.ECDH(), endpoint_ephemeral_public_key)

    derived_key = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=transaction_identifier,
    ).derive(shared_key)

    salt = to_bytes(
        [
            reader_public_key_x,
            VOLATILE_ASTR,
            reader_group_identifier + reader_instance_identifier,
            transport_type,
            BerTLV(0x5C, value=protocol_version),
            reader_ephemeral_public_key_x,
            transaction_identifier,
            [transaction_flags, transaction_code],
            fci_proprietary_template,
        ]
    )
    info = to_bytes([endpoint_ephemeral_public_key_x])
    material = hkdf_sha256(
        derived_key,
        salt,
        info,
        key_size * 10,
    )

    exchange_sk_reader = material[:0x20]
    exchange_sk_device = material[0x20:0x40]

    step_up_input_material = material[0x40:0x60]
    ble_input_material = material[0x60:0x80]

    uwb_ranging_sk = material[0x80:0xA0]

    step_up_sk_reader = hkdf_sha256(
        step_up_input_material,
        b"\x00" * 0x20,
        b"SKReader",
        key_size * 2,
    )
    step_up_sk_device = hkdf_sha256(
        step_up_input_material,
        b"\x00" * 0x20,
        b"SKDevice",
        key_size * 2,
    )

    ble_sk_reader = hkdf_sha256(
        ble_input_material,
        b"\x00" * 0x20,
        b"BleSKReader",
        key_size * 2,
    )
    ble_sk_device = hkdf_sha256(
        ble_input_material,
        b"\x00" * 0x20,
        b"BleSKDevice",
        key_size * 2,
    )

    k_persistent = None
    logging.info(f"exchange_sk_reader={exchange_sk_reader.hex()} exchange_sk_device={exchange_sk_device.hex()}")

    secure = AliroSecureContext(
        exchange_sk_reader=exchange_sk_reader,
        exchange_sk_device=exchange_sk_device,
        step_up_sk_reader=step_up_sk_reader,
        step_up_sk_device=step_up_sk_device,
        ble_sk_reader=ble_sk_reader,
        ble_sk_device=ble_sk_device,
        uwb_ranging_sk=uwb_ranging_sk,
    )
    logging.info(f"Derived secure context: {secure!r}")
    channel = secure.exchange
    try:
        response, channel.counter_endpoint = channel.decrypt_response(response)
    except (AssertionError,) as e:
        logging.info(f"AUTH1 COULD NOT DECRYPT RESPONSE {e}")
        return k_persistent, None, None

    logging.info(f"AUTH1 DECRYPTED RESPONSE: {response}")

    tlv_array = BerTLVMessage.from_bytes(response.data)

    signature = tlv_array.find_by_tag_else_empty(0x9E).value
    if signature is None:
        raise ProtocolError("No device signature in response at tag 0x9E")

    issued_at = tlv_array.find_by_tag_else_empty(0x91).value
    expires_at = tlv_array.find_by_tag_else_empty(0x92).value
    auth_status = tlv_array.find_by_tag_else_empty(0x5E).value

    endpoint = None
    endpoint_public_key = None

    device_public_key = tlv_array.find_by_tag_else_empty(0x5A).value
    if device_public_key is not None:
        endpoint_public_key = load_ec_public_key_from_bytes(device_public_key)

    endpoint_identifier = tlv_array.find_by_tag_else_empty(0x4E).value
    if endpoint_identifier is not None:
        endpoint = find_endpoint_by_identifier(endpoints, endpoint_identifier)
        if endpoint is not None:
            endpoint_public_key = load_ec_public_key_from_bytes(endpoint.public_key)

    logging.info(
        "AUTH1 response"
        f" auth_status={auth_status.hex() if auth_status else None}"
        f" issued_at={issued_at},"
        f" expires_at={expires_at},"
        f" endpoint_identifier={endpoint_identifier.hex() if endpoint_identifier else None}"
    )

    if endpoint_public_key is None:
        return k_persistent, None, secure

    signature = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))

    verification_hash_input_material = [
        BerTLV(0x4D, value=reader_group_identifier + reader_instance_identifier),
        BerTLV(0x86, value=endpoint_ephemeral_public_key_x),
        BerTLV(0x87, value=reader_ephemeral_public_key_x),
        BerTLV(0x4C, value=transaction_identifier),
        BerTLV(0x93, value=DEVICE_CONTEXT),
    ]
    verification_hash_input = to_bytes(verification_hash_input_material)

    logging.info("AUTH1 signature verified")

    try:
        endpoint_public_key.verify(signature, verification_hash_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        logging.warning(f"Signature data does not match {e}")
        return k_persistent, None, secure

    endpoint_public_key_x, _ = get_ec_key_public_points(endpoint_public_key)
    persistent_salt = [
        reader_public_key_x,
        PERSISTENT_ASTR,
        reader_instance_identifier_value,
        transport_type,
        BerTLV(0x5C, value=protocol_version),
        reader_ephemeral_public_key_x,
        transaction_identifier,
        [transaction_flags, transaction_code],
        fci_proprietary_bytes,
        endpoint_public_key_x,
    ]

    k_persistent = hkdf_sha256(
        derived_key,
        persistent_salt,
        endpoint_ephemeral_public_key_x,
        0x20,
    )
    if endpoint is None:
        endpoint = Endpoint(
            last_used_at=0,
            counter=0,
            key_type=KeyType.SECP256R1,
            public_key=device_public_key,
            persistent_key=k_persistent,
            identifier=endpoint_identifier,
            issued_at=issued_at,
            last_auth_status=auth_status,
        )
    else:
        endpoint.persistent_key = k_persistent
        endpoint.issued_at = issued_at
        endpoint.last_auth_status = auth_status
    return k_persistent, endpoint, secure


def exchange_attestation(tag: ISO7816Tag, channel: AliroSecureChannel):
    """Performs attestation exchange, returns attestation package"""

    device_request = channel.encrypt_envelope_command_data(
        cbor2.dumps(
            # Device request entry
            {
                # Version
                "1": "1.0",
                # Document requests
                "2": [
                    {
                        # Items request
                        "1": cbor2.CBORTag(
                            24,
                            cbor2.dumps(
                                {
                                    # Name spaces
                                    "1": {
                                        "aliro-a": {
                                            "test_id": False,
                                            "credentialId": True,
                                        },
                                        "matter1": {
                                            "test_id": False,
                                            "credentialId": True,
                                        },
                                    },
                                    # Document type
                                    "5": "aliro-a",
                                    # Auxilliary data
                                    # "2"
                                }
                            ),
                        )
                    }
                ],
            }
        )
    )

    command = ISO7816Command(
        cla=0x00,
        ins=0xC3,
        p1=0x00,
        p2=0x00,
        data=BerTLV(0x53, device_request),
    )
    logging.info(f"ENVELOPE2 CMD = {command}")
    response = channel.transceive_plain_plain(tag, command)
    logging.info(f"ENVELOPE2 RES = {response}")

    data = response.data

    while response.sw1 == 0x61:
        command = ISO7816Command(
            cla=0x00, ins=ISO7816Instruction.GET_RESPONSE, p1=0x00, p2=0x00, data=None, le=response.sw2
        )
        logging.info(f"GET DATA CMD = {command}")
        response = channel.transceive_plain_plain(tag, command)
        logging.info(f"GET DATA RES = {response}")
        data += response.data

    if response.sw1 != 0x90:
        raise ProtocolError(f"ENVELOPE2 INVALID STATUS {response.sw}")

    message = BerTLV.from_bytes(data).value

    try:
        cbor = cbor2.loads(message)
        cbor_ciphertext = cbor["data"]
    except Exception:
        cbor_ciphertext = message

    cbor_plaintext = channel.decrypt_data(cbor_ciphertext)
    logging.info(f"ENVELOPE2 DECRYPTED RESPONSE: {cbor_plaintext.hex()}")

    cbor = cbor2.loads(cbor_plaintext)
    logging.info(f"ENVELOPE2 DECRYPTED CBOR: {cbor}")

    return cbor_plaintext


def mailbox_exchange(tag: ISO7816Tag, channel: AliroSecureChannel, data: bytes):
    logging.info(f"EXCHANGE DATA {data}")

    command = ISO7816Command(
        cla=0x80,
        ins=0xC9,
        p1=0x00,
        p2=0x00,
        data=to_bytes(data),
    )
    logging.info(f"EXCHANGE COMMAND {command}")

    response = channel.transceive_secure_secure(tag, command)

    logging.info(f"EXCHANGE RESPONSE {response}")
    if response.sw1 != 0x90:
        return []

    return response.data


def select_applet(tag: ISO7816Tag, applet=ISO7816Application.ALIRO):
    command = ISO7816.select_aid(applet)
    logging.info(f"SELECT CMD = {command}")
    response = tag.transceive(command)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"Could not select {applet} {response.sw}")
    logging.info(f"SELECT RES = {response}")
    return response.data


def control_flow(tag: ISO7816Tag, transaction_flags=0x00, transaction_code=0x01):
    command_data = BerTLVMessage(
        [
            BerTLV(0x41, value=transaction_flags),
            BerTLV(0x42, value=transaction_code),
        ]
    )

    command = ISO7816Command(cla=0x80, ins=0x3C, p1=0x00, p2=0x00, data=command_data, le=None)
    logging.info(f"OP_CONTROL_FLOW CMD = {command}")
    response = tag.transceive(command)
    logging.info(f"OP_CONTROL_FLOW RES = {response}")
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"OP_CONTROL_FLOW INVALID STATUS {response.sw}")
    return response.data


def perform_authentication_flow(
    tag: ISO7816Tag,
    flow: AliroFlow,
    reader_group_identifier: bytes,
    reader_instance_identifier: bytes,
    reader_private_key: ec.EllipticCurvePrivateKey,
    reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    protocol_version: bytes,
    fci_proprietary_template: List[bytes],
    transaction_identifier: bytes,
    transaction_flags: int,
    transaction_code: AliroTransactionType,
    transport_type: int,
    endpoints: List[Endpoint],
    mailbox_data=b"",
    key_size=16,
) -> Tuple[AliroFlow, Endpoint | None]:
    """Returns an Endpoint if one was found and successfully authenticated."""
    reader_public_key = reader_private_key.public_key()
    reader_public_key_x, reader_public_key_y = get_ec_key_public_points(reader_public_key)

    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()
    endpoint_ephemeral_public_key, endpoint, secure = fast_auth(
        tag=tag,
        fci_proprietary_template=fci_proprietary_template,
        protocol_version=protocol_version,
        transport_type=transport_type,
        transaction_flags=transaction_flags,
        transaction_code=transaction_code,
        reader_group_identifier=reader_group_identifier,
        reader_instance_identifier=reader_instance_identifier,
        reader_public_key=reader_public_key,
        reader_ephemeral_public_key=reader_ephemeral_public_key,
        transaction_identifier=transaction_identifier,
        endpoints=endpoints,
        key_size=key_size,
    )

    if endpoint is not None and flow == AliroFlow.FAST:
        if secure is not None:
            _ = mailbox_exchange(
                tag,
                secure.exchange,
                data=mailbox_data,
            )
            pass

        _ = control_flow(tag, 0x01, 0x01)
        return AliroFlow.FAST, endpoint

    k_persistent, endpoint, secure = standard_auth(
        tag=tag,
        fci_proprietary_template=fci_proprietary_template,
        protocol_version=protocol_version,
        transport_type=transport_type,
        transaction_flags=transaction_flags,
        transaction_code=transaction_code,
        transaction_identifier=transaction_identifier,
        reader_group_identifier=reader_group_identifier,
        reader_instance_identifier=reader_instance_identifier,
        reader_private_key=reader_private_key,
        reader_ephemeral_private_key=reader_ephemeral_private_key,
        endpoints=endpoints,
        endpoint_ephemeral_public_key=endpoint_ephemeral_public_key,
        key_size=key_size,
    )

    if endpoint is not None and k_persistent is not None:
        endpoint.persistent_key = k_persistent

    # if endpoint is None:
    #    return AliroFlow.STANDARD, None, None

    _ = mailbox_exchange(
        tag,
        secure.exchange,
        data=mailbox_data,
    )

    _ = select_applet(tag, applet=ISO7816Application.ALIRO_STEP_UP)

    _ = exchange_attestation(tag, secure.step_up)

    _ = control_flow(tag, 0x01, 0x01)

    return AliroFlow.ATTESTATION, endpoint


def read_aliro(
    tag: ISO7816Tag,
    reader_group_identifier: bytes,
    reader_instance_identifier: bytes,
    reader_private_key: bytes,
    endpoints: List[Endpoint],
    preferred_versions: Collection[bytes] = None,
    flow=AliroFlow.FAST,
    transaction_code: AliroTransactionType = AliroTransactionType.UNLOCK,
    # Generated at random if not provided
    reader_ephemeral_private_key: bytes | None = None,
    # Generated at random if not provided
    transaction_identifier: bytes | None = None,
    transport_type=TransportType.NFC,
    key_size=16,
    mailbox_data: bytes = b"",
) -> Tuple[AliroFlow, Endpoint | None]:
    """Returns the authentication flow used and an optional endpoint if authentication was successful."""
    transaction_flags = sum({AliroTransactionFlags.FAST if flow <= AliroFlow.FAST else AliroTransactionFlags.STANDARD})

    response = select_applet(tag, applet=ISO7816Application.ALIRO)

    message = BerTLVMessage.from_bytes(response)

    fci_template = message.find_by_tag_else_throw(0x6F).to_message()
    fci_proprietary_template = fci_template.find_by_tag_else_throw(0xA5).to_message()
    versions_tag = fci_proprietary_template.find_by_tag_else(0x5C, None)
    # type_tag = fci_proprietary_template.find_by_tag_else(0x80, None)

    if versions_tag is None:
        raise ProtocolError("Response does not contain supported version list at tag 0x5C")

    device_protocol_versions = list(chunked(versions_tag.value, 2))
    preferred_versions = preferred_versions or []
    for preferred_version in preferred_versions:
        if preferred_version in device_protocol_versions:
            protocol_version = preferred_version
            logging.info(f"Choosing preferred version {protocol_version.hex()}")
            break
    else:
        protocol_version = device_protocol_versions[0]
        logging.info(f"Defaulting to the newest available version {protocol_version.hex()}")
    if protocol_version not in (b"\x01\x00", b"\x00\x09"):
        raise ProtocolError("Unknown version code")

    reader_private_key = ec.derive_private_key(int.from_bytes(reader_private_key, "big"), ec.SECP256R1())

    logging.info(f"{fci_proprietary_template} -> {fci_proprietary_template.to_bytes().hex()}")

    result_flow, endpoint = perform_authentication_flow(
        tag=tag,
        flow=flow,
        reader_group_identifier=reader_group_identifier,
        reader_instance_identifier=reader_instance_identifier,
        reader_private_key=reader_private_key,
        reader_ephemeral_private_key=generate_ec_key_if_provided_is_none(reader_ephemeral_private_key),
        protocol_version=protocol_version,
        fci_proprietary_template=BerTLV(0xA5, fci_proprietary_template),
        transaction_identifier=transaction_identifier or os.urandom(16),
        transaction_flags=transaction_flags,
        transaction_code=transaction_code,
        transport_type=transport_type,
        endpoints=endpoints,
        key_size=key_size,
        mailbox_data=mailbox_data,
    )
    if endpoint is not None:
        endpoint.last_used_at = int(time.time())
        endpoint.counter += 1
        endpoint.last_fci_template = BerTLV(0xA5, fci_proprietary_template).to_bytes()
        endpoint.last_protocol_version = protocol_version
        endpoint.last_auth_flow = result_flow.name

    return result_flow, endpoint
