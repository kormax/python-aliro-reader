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
from util.iso7816 import (
    ISO7816,
    ISO7816Application,
    ISO7816Command,
    ISO7816Instruction,
    ISO7816Response,
    ISO7816Tag,
)
from util.structable import chunked, to_bytes
from util.tlv.ber import BerTLV, BerTLVMessage

from .auth1_command_parameters import Auth1CommandParameters
from .authentication_policy import AuthenticationPolicy
from .flow import AliroFlow
from .interface import Interface
from .reader_status import ReaderStatus
from .signaling_bitmask import SignalingBitmask

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
APDU_COMMAND_CHAINING_CLA_BIT = 0x10
APDU_COMMAND_CHAINING_MAX_CHUNK = 0xFF
APDU_DEFAULT_MAX_COMMAND_DATA = 255
APDU_DEFAULT_MAX_RESPONSE_DATA = 256
APDU_MAX_PRE_CHAINING_PAYLOAD = 2000


def _key_hex(value):
    if value is None:
        return None
    return bytes(value).hex().upper()


class AliroTransactionFlags(IntEnum):
    STANDARD = 0x00
    FAST = 0x01


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
                ne=command.ne,
            ),
            self.counter_reader,
        )

    def decrypt_response(self, response: ISO7816Response) -> Tuple[ISO7816Response, int]:
        plaintext = self.decrypt_endpoint_data(response.data)
        return (
            ISO7816Response(sw1=response.sw1, sw2=response.sw2, data=plaintext),
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
                ne=command.ne,
            ),
            self.counter_reader,
        )


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


def find_endpoint_by_key_slot(endpoints: List[Endpoint], key_slot):
    return next((e for e in endpoints if e.key_slot == key_slot), None)


def find_endpoint_by_public_key(endpoints: List[Endpoint], public_key: bytes):
    return next((e for e in endpoints if e.public_key == public_key), None)


def generate_ec_key_if_provided_is_none(
    private_key: ec.EllipticCurvePrivateKey | None,
):
    return (
        ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())
        if private_key
        else ec.generate_private_key(ec.SECP256R1())
    )


def resolve_max_command_data_size_from_select_fci(fci_proprietary_template: BerTLVMessage) -> int:
    extended_info = fci_proprietary_template.find_by_tag_else(0x7F66, None)
    if extended_info is None:
        return APDU_DEFAULT_MAX_COMMAND_DATA

    extended_fields = BerTLVMessage.from_bytes(extended_info.value).tags
    max_reception_tag = next((field for field in extended_fields if field.tag == b"\x02"), None)
    if max_reception_tag is None:
        raise ProtocolError("Malformed SELECT response: 7F66 does not include max reception APDU size INTEGER")

    max_command_data_size = int.from_bytes(max_reception_tag.value, "big")
    if max_command_data_size <= 0:
        raise ProtocolError(f"Malformed SELECT response: invalid max reception APDU size {max_command_data_size}")
    return max_command_data_size


def transceive_with_chaining(  # noqa: C901
    tag: ISO7816Tag,
    command: ISO7816Command,
    *,
    label: str,
    allow_command_chaining: bool = True,
    allow_response_chaining: bool = True,
    max_chunk_size: int = APDU_COMMAND_CHAINING_MAX_CHUNK,
) -> ISO7816Response:
    response = None
    last_command = command
    max_response_apdu_size = APDU_DEFAULT_MAX_RESPONSE_DATA
    payload = to_bytes(command.data)
    if len(payload) > APDU_MAX_PRE_CHAINING_PAYLOAD:
        raise ProtocolError(
            f"{label} command payload exceeds {APDU_MAX_PRE_CHAINING_PAYLOAD} bytes before chaining: {len(payload)}"
        )
    max_data_per_chunk = int(max_chunk_size)
    if max_data_per_chunk <= 0:
        raise ProtocolError(f"{label} invalid max command chunk size: {max_data_per_chunk}")
    if len(payload) > max_data_per_chunk and not allow_command_chaining:
        raise ProtocolError(
            f"{label} command payload {len(payload)} exceeds APDU max {max_data_per_chunk} without chaining"
        )

    total_chunks = max(1, (len(payload) + max_data_per_chunk - 1) // max_data_per_chunk)

    for chunk_index in range(total_chunks):
        start = chunk_index * max_data_per_chunk
        chunk_payload = payload[start : start + max_data_per_chunk]
        is_last = chunk_index == total_chunks - 1
        chunk_requires_extended = len(chunk_payload) > APDU_COMMAND_CHAINING_MAX_CHUNK or (is_last and command.ne > 256)
        chunk_command = ISO7816Command(
            cla=command.cla if is_last else (command.cla | APDU_COMMAND_CHAINING_CLA_BIT),
            ins=command.ins,
            p1=command.p1,
            p2=command.p2,
            data=chunk_payload,
            ne=command.ne if is_last else 0,
            extended=chunk_requires_extended,
        )

        chunk_number = chunk_index + 1
        chunk_suffix = f" CHAIN {chunk_number}/{total_chunks}" if total_chunks > 1 else ""
        logging.info(f"{label} COMMAND{chunk_suffix} {chunk_command}")
        response = tag.transceive(chunk_command)
        logging.info(f"{label} RESPONSE{chunk_suffix} {response}")
        if len(response.data) > max_response_apdu_size:
            raise ProtocolError(
                f"{label} response APDU data length {len(response.data)} exceeds device max {max_response_apdu_size}"
            )
        last_command = chunk_command
        if chunk_number != total_chunks and response.sw != (0x90, 0x00):
            raise ProtocolError(f"{label} INVALID STATUS DURING COMMAND CHAIN {response.sw}")

    if response is None:
        raise ProtocolError(f"{label} EMPTY RESPONSE")

    if not allow_response_chaining or response.sw1 != 0x61:
        if len(response.data) > APDU_MAX_PRE_CHAINING_PAYLOAD:
            raise ProtocolError(
                f"{label} response payload exceeds {APDU_MAX_PRE_CHAINING_PAYLOAD} bytes before chaining: "
                f"{len(response.data)}"
            )
        return response

    response_data = bytearray(response.data)
    if len(response_data) > APDU_MAX_PRE_CHAINING_PAYLOAD:
        raise ProtocolError(
            f"{label} response payload exceeds {APDU_MAX_PRE_CHAINING_PAYLOAD} bytes before chaining: "
            f"{len(response_data)}"
        )
    while response.sw1 == 0x61:
        get_response_command = ISO7816Command(
            cla=last_command.cla,
            ins=ISO7816Instruction.GET_RESPONSE,
            p1=0x00,
            p2=0x00,
            ne=256 if response.sw2 == 0 else response.sw2,
        )
        logging.info(f"{label} GET_RESPONSE COMMAND {get_response_command}")
        response = tag.transceive(get_response_command)
        logging.info(f"{label} GET_RESPONSE RESPONSE {response}")
        if len(response.data) > max_response_apdu_size:
            raise ProtocolError(
                f"{label} response APDU data length {len(response.data)} exceeds device max {max_response_apdu_size}"
            )
        response_data.extend(response.data)
        if len(response_data) > APDU_MAX_PRE_CHAINING_PAYLOAD:
            raise ProtocolError(
                f"{label} response payload exceeds {APDU_MAX_PRE_CHAINING_PAYLOAD} bytes before chaining:"
                f" {len(response_data)}"
            )

    return ISO7816Response(sw1=response.sw1, sw2=response.sw2, data=response_data)


def fast_auth(  # noqa: C901
    tag: ISO7816Tag,
    fci_proprietary_template: List[bytes],
    protocol_version: bytes,
    interface: Interface,
    command_parameters: int,
    authentication_policy: AuthenticationPolicy,
    reader_group_identifier: bytes,
    reader_group_sub_identifier: bytes,
    auth0_command_vendor_extension: bytes | None,
    reader_public_key: ec.EllipticCurvePublicKey,
    reader_ephemeral_public_key: ec.EllipticCurvePublicKey,
    transaction_identifier: bytes,
    endpoints: List[Endpoint],
    max_command_data_size: int = APDU_DEFAULT_MAX_COMMAND_DATA,
    key_size=16,
) -> Tuple[ec.EllipticCurvePublicKey, Endpoint | None, AliroSecureContext | None, bytes]:
    (
        reader_ephemeral_public_key_x,
        reader_ephemeral_public_key_y,
    ) = get_ec_key_public_points(reader_ephemeral_public_key)
    reader_ephemeral_public_key_bytes = bytes([0x04, *reader_ephemeral_public_key_x, *reader_ephemeral_public_key_y])
    reader_public_key_x, _ = get_ec_key_public_points(reader_public_key)
    fci_proprietary_bytes = to_bytes(fci_proprietary_template)
    auth0_command_vendor_extension_tlv = None
    if auth0_command_vendor_extension is not None:
        if len(auth0_command_vendor_extension) > 127:
            raise ValueError(
                f"auth0_command_vendor_extension cannot exceed 127 bytes (got {len(auth0_command_vendor_extension)})"
            )
        auth0_command_vendor_extension_tlv = BerTLV(0xB1, value=auth0_command_vendor_extension)

    command_data = BerTLVMessage(
        [
            BerTLV(0x41, value=command_parameters),
            BerTLV(0x42, value=authentication_policy),
            BerTLV(0x5C, value=protocol_version),
            BerTLV(0x87, value=reader_ephemeral_public_key_bytes),
            BerTLV(0x4C, value=transaction_identifier),
            BerTLV(0x4D, value=reader_group_identifier + reader_group_sub_identifier),
            auth0_command_vendor_extension_tlv,
        ]
    )

    command = ISO7816Command(cla=0x80, ins=0x80, p1=0x00, p2=0x00, data=command_data)
    response = transceive_with_chaining(tag, command, label="AUTH0", max_chunk_size=max_command_data_size)
    logging.info(f"AUTH0 RESPONSE: {response}")
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"AUTH0 INVALID STATUS {response.sw}")
    message = BerTLVMessage.from_bytes(response.data)

    endpoint_ephemeral_public_key = message.find_by_tag_else_empty(0x86).value
    if endpoint_ephemeral_public_key is None:
        raise ProtocolError("Response does not contain endpoint_ephemeral_public_key_tag 0x86")
    if len(endpoint_ephemeral_public_key) != 65 or endpoint_ephemeral_public_key[0] != 0x04:
        raise ProtocolError(
            "Response contains invalid endpoint_ephemeral_public_key_tag 0x86"
            f" length={len(endpoint_ephemeral_public_key)}"
        )

    endpoint_ephemeral_public_key = load_ec_public_key_from_bytes(endpoint_ephemeral_public_key)
    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(endpoint_ephemeral_public_key)

    fast_requested = (command_parameters & int(AliroTransactionFlags.FAST)) != 0
    returned_cryptogram = message.find_by_tag_else_empty(0x9D).value
    auth0_response_vendor_extension_tlv = message.find_by_tag_else(0xB2, None)
    if auth0_response_vendor_extension_tlv is not None and len(auth0_response_vendor_extension_tlv.value) > 127:
        raise ProtocolError(
            "Response contains invalid auth0_response_vendor_extension_tag 0xB2"
            f" length={len(auth0_response_vendor_extension_tlv.value)}"
        )
    auth0_info_suffix = b""
    if auth0_command_vendor_extension_tlv is not None:
        auth0_info_suffix += auth0_command_vendor_extension_tlv.to_bytes()
    if auth0_response_vendor_extension_tlv is not None:
        auth0_info_suffix += auth0_response_vendor_extension_tlv.to_bytes()
    if returned_cryptogram is not None and len(returned_cryptogram) != 64:
        raise ProtocolError(f"Response contains invalid cryptogram_tag 0x9D length={len(returned_cryptogram)}")
    if not fast_requested and returned_cryptogram is not None:
        raise ProtocolError("AUTH0 response contains cryptogram while expedited-fast was not requested")
    if fast_requested and returned_cryptogram is None:
        raise ProtocolError("AUTH0 response does not contain cryptogram while expedited-fast was requested")
    if returned_cryptogram is None:
        logging.info("AUTH0 skipped")
        return endpoint_ephemeral_public_key, None, None, auth0_info_suffix

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
            reader_group_identifier + reader_group_sub_identifier,
            interface,
            BerTLV(0x5C, value=protocol_version),
            reader_ephemeral_public_key_x,
            transaction_identifier,
            [command_parameters, authentication_policy],
            fci_proprietary_bytes,
            endpoint_public_key_x,
        ]

        okm = hkdf_sha256(k_persistent, salt, endpoint_ephemeral_public_key_x + auth0_info_suffix, 0xA0)
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
        auth_status_value = message.find_by_tag_else_empty(0x5E).value
        credential_signed_timestamp = message.find_by_tag_else_empty(0x91).value
        revocation_signed_timestamp = message.find_by_tag_else_empty(0x92).value
        if auth_status_value is None or credential_signed_timestamp is None or revocation_signed_timestamp is None:
            logging.info("AUTH0 fast cryptogram plaintext missing signaling/timestamps")
            continue
        if (
            len(auth_status_value) != 2
            or len(credential_signed_timestamp) != 0x14
            or len(revocation_signed_timestamp) != 0x14
        ):
            logging.info("AUTH0 fast cryptogram plaintext length mismatch")
            continue
        signaling_bitmask = SignalingBitmask.parse(auth_status_value)

        logging.info(
            "AUTH0 fast cryptogram verified"
            f" signaling_bitmask={signaling_bitmask!r}"
            f" credential_signed_timestamp={credential_signed_timestamp}"
            f" revocation_signed_timestamp={revocation_signed_timestamp}"
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
        endpoint.credential_signed_timestamp = credential_signed_timestamp
        endpoint.revocation_signed_timestamp = revocation_signed_timestamp
        endpoint.last_signaling_bitmask = signaling_bitmask
        matched_endpoint = endpoint
        matched_secure = secure
        break
    return endpoint_ephemeral_public_key, matched_endpoint, matched_secure, auth0_info_suffix


def load_cert(
    tag: ISO7816Tag,
    reader_cert: bytes,
    max_command_data_size: int = APDU_DEFAULT_MAX_COMMAND_DATA,
):
    command = ISO7816Command(
        cla=0x80,
        ins=0xD1,
        p1=0x00,
        p2=0x00,
        data=reader_cert,
    )
    response = transceive_with_chaining(tag, command, label="LOAD_CERT", max_chunk_size=max_command_data_size)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"LOAD_CERT INVALID STATUS {response.sw}")


def standard_auth(  # noqa: C901
    tag: ISO7816Tag,
    fci_proprietary_template: List[bytes],
    protocol_version: bytes,
    interface: Interface,
    command_parameters: int,
    authentication_policy: AuthenticationPolicy,
    reader_group_identifier: bytes,
    reader_group_sub_identifier: bytes,
    reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    reader_private_key: ec.EllipticCurvePrivateKey,
    transaction_identifier: bytes,
    endpoint_ephemeral_public_key: ec.EllipticCurvePublicKey,
    endpoints: List[Endpoint],
    auth0_info_suffix: bytes = b"",
    reader_certificate: bytes | None = None,
    max_command_data_size: int = APDU_DEFAULT_MAX_COMMAND_DATA,
    key_size=16,
) -> Tuple[bytes | None, Endpoint | None, AliroSecureContext | None]:
    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(endpoint_ephemeral_public_key)
    reader_ephemeral_public_key_x, _ = get_ec_key_public_points(reader_ephemeral_public_key)

    authentication_hash_input_material = [
        BerTLV(0x4D, value=reader_group_identifier + reader_group_sub_identifier),
        BerTLV(0x86, value=endpoint_ephemeral_public_key_x),
        BerTLV(0x87, value=reader_ephemeral_public_key_x),
        BerTLV(0x4C, value=transaction_identifier),
        BerTLV(0x93, value=READER_CONTEXT),
    ]
    authentication_hash_input = to_bytes(authentication_hash_input_material)
    logging.info(f"authentication_hash_input={authentication_hash_input.hex()}")
    auth_signing_private_key = reader_private_key
    auth_signing_key_source = "reader_private_key"

    if reader_certificate is not None:
        logging.info("LOAD_CERT enabled via configured reader_certificate (%d bytes)", len(reader_certificate))
        load_cert(tag, reader_certificate, max_command_data_size=max_command_data_size)

    signature = auth_signing_private_key.sign(authentication_hash_input, ec.ECDSA(hashes.SHA256()))
    logging.info(f"signature={signature.hex()} ({hex(len(signature))})")
    x, y = decode_dss_signature(signature)
    signature_point_form = bytes([*x.to_bytes(32, "big"), *y.to_bytes(32, "big")])
    logging.info(f"signature_point_form={signature_point_form.hex()} ({hex(len(signature_point_form))})")
    logging.info(
        f"command_parameters={command_parameters} authentication_policy={authentication_policy}"
        f" auth_signing_key_source={auth_signing_key_source}"
    )

    auth1_command_parameters = Auth1CommandParameters.REQUEST_PUBLIC_KEY
    data = BerTLVMessage(
        [
            BerTLV(0x41, value=auth1_command_parameters),
            BerTLV(0x9E, value=signature_point_form),
        ]
    )
    command = ISO7816Command(cla=0x80, ins=0x81, p1=0x00, p2=0x00, data=data)
    response = transceive_with_chaining(tag, command, label="AUTH1", max_chunk_size=max_command_data_size)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"AUTH1 INVALID STATUS {response.sw}")

    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(endpoint_ephemeral_public_key)
    reader_ephemeral_public_key_x, _ = get_ec_key_public_points(reader_ephemeral_public_key)
    reader_public_key_x, _ = get_ec_key_public_points(reader_private_key.public_key())
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
            reader_group_identifier + reader_group_sub_identifier,
            interface,
            BerTLV(0x5C, value=protocol_version),
            reader_ephemeral_public_key_x,
            transaction_identifier,
            [command_parameters, authentication_policy],
            fci_proprietary_template,
        ]
    )
    info = to_bytes([endpoint_ephemeral_public_key_x, auth0_info_suffix])
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
    if len(signature) != 64:
        raise ProtocolError(f"Invalid device signature length at tag 0x9E: {len(signature)}")

    credential_signed_timestamp = tlv_array.find_by_tag_else_empty(0x91).value
    revocation_signed_timestamp = tlv_array.find_by_tag_else_empty(0x92).value
    auth_status = tlv_array.find_by_tag_else_empty(0x5E).value
    if auth_status is None:
        raise ProtocolError("No signaling bitmap in response at tag 0x5E")
    if len(auth_status) != 2:
        raise ProtocolError(f"Invalid signaling bitmap length at tag 0x5E: {len(auth_status)}")
    if credential_signed_timestamp is not None and len(credential_signed_timestamp) != 20:
        raise ProtocolError(
            f"Invalid credential_signed_timestamp length at tag 0x91: {len(credential_signed_timestamp)}"
        )
    if revocation_signed_timestamp is not None and len(revocation_signed_timestamp) != 20:
        raise ProtocolError(
            f"Invalid revocation_signed_timestamp length at tag 0x92: {len(revocation_signed_timestamp)}"
        )
    signaling_bitmask = SignalingBitmask.parse(auth_status)

    endpoint = None
    endpoint_public_key = None

    device_public_key = tlv_array.find_by_tag_else_empty(0x5A).value
    if device_public_key is not None and (len(device_public_key) != 65 or device_public_key[0] != 0x04):
        raise ProtocolError(f"Invalid Access Credential public key length/format at tag 0x5A: {len(device_public_key)}")
    if device_public_key is not None:
        endpoint_public_key = load_ec_public_key_from_bytes(device_public_key)

    key_slot = tlv_array.find_by_tag_else_empty(0x4E).value
    if key_slot is not None and len(key_slot) != 8:
        raise ProtocolError(f"Invalid key_slot length at tag 0x4E: {len(key_slot)}")
    key_slot_requested = auth1_command_parameters.key_slot_requested
    if key_slot_requested and key_slot is None:
        raise ProtocolError("AUTH1 response must contain key_slot (0x4E) when key slot was requested")
    if key_slot is None and device_public_key is None:
        raise ProtocolError("AUTH1 response must contain either key_slot (0x4E) or public key (0x5A)")
    if key_slot is not None:
        endpoint = find_endpoint_by_key_slot(endpoints, key_slot)
        if endpoint is not None:
            endpoint_public_key = load_ec_public_key_from_bytes(endpoint.public_key)
    elif device_public_key is not None:
        endpoint = find_endpoint_by_public_key(endpoints, device_public_key)
        if endpoint is not None:
            endpoint_public_key = load_ec_public_key_from_bytes(endpoint.public_key)

    logging.info(
        "AUTH1 response"
        f" signaling_bitmask={signaling_bitmask!r}"
        f" credential_signed_timestamp={credential_signed_timestamp},"
        f" revocation_signed_timestamp={revocation_signed_timestamp},"
        f" key_slot={key_slot.hex() if key_slot else None}"
    )

    if endpoint_public_key is None:
        return k_persistent, None, secure

    signature = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))

    verification_hash_input_material = [
        BerTLV(0x4D, value=reader_group_identifier + reader_group_sub_identifier),
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
        reader_group_identifier + reader_group_sub_identifier,
        interface,
        BerTLV(0x5C, value=protocol_version),
        reader_ephemeral_public_key_x,
        transaction_identifier,
        [command_parameters, authentication_policy],
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
            key_slot=key_slot,
            credential_signed_timestamp=credential_signed_timestamp,
            revocation_signed_timestamp=revocation_signed_timestamp,
            last_signaling_bitmask=signaling_bitmask,
        )
    else:
        endpoint.persistent_key = k_persistent
        endpoint.credential_signed_timestamp = credential_signed_timestamp
        endpoint.revocation_signed_timestamp = revocation_signed_timestamp
        endpoint.last_signaling_bitmask = signaling_bitmask
    return k_persistent, endpoint, secure


def exchange_step_up_documents(
    tag: ISO7816Tag,
    channel: AliroSecureChannel,
    max_command_data_size: int = APDU_DEFAULT_MAX_COMMAND_DATA,
):
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
                                            "element2": True,
                                            "element4": True,
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
    response = transceive_with_chaining(tag, command, label="ENVELOPE", max_chunk_size=max_command_data_size)
    if response.sw1 != 0x90:
        raise ProtocolError(f"ENVELOPE INVALID STATUS {response.sw}")

    message = BerTLV.from_bytes(response.data).value

    try:
        cbor = cbor2.loads(message)
        cbor_ciphertext = cbor["data"]
    except Exception:
        cbor_ciphertext = message

    cbor_plaintext = channel.decrypt_data(cbor_ciphertext)
    logging.info(f"ENVELOPE DECRYPTED RESPONSE: {cbor_plaintext.hex()}")

    cbor = cbor2.loads(cbor_plaintext)
    logging.info(f"ENVELOPE DECRYPTED CBOR: {cbor}")

    return cbor_plaintext


def exchange(
    tag: ISO7816Tag,
    channel: AliroSecureChannel,
    tlvs: bytes | BerTLV | BerTLVMessage | List[BerTLV] = b"",
    *,
    skip_chaining=False,
    max_command_data_size: int = APDU_DEFAULT_MAX_COMMAND_DATA,
) -> ISO7816Response:
    command = ISO7816Command(
        cla=0x80,
        ins=0xC9,
        p1=0x00,
        p2=0x00,
        data=to_bytes(tlvs),
    )
    logging.info(f"EXCHANGE COMMAND {command}")

    encrypted_command, _ = channel.encrypt_command(command)
    response = transceive_with_chaining(
        tag,
        encrypted_command,
        label="EXCHANGE",
        allow_response_chaining=not skip_chaining,
        max_chunk_size=max_command_data_size,
    )
    if response.sw != (0x90, 0x00):
        return response

    response, _ = channel.decrypt_response(response)
    logging.info(f"EXCHANGE DECRYPTED RESPONSE {response}")
    return response


def select_applet(tag: ISO7816Tag, applet=ISO7816Application.ALIRO):
    command = ISO7816.select_aid(applet)
    logging.info(f"SELECT CMD = {command}")
    response = tag.transceive(command)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"Could not select {applet} {response.sw}")
    logging.info(f"SELECT RES = {response}")
    return response.data


def control_flow(
    tag: ISO7816Tag,
    status: ReaderStatus = ReaderStatus.FAILURE_NO_INFORMATION,
):
    if status not in ReaderStatus.op_control_flow_allowed():
        raise ValueError(f"Unsupported OP_CONTROL_FLOW status: {status}")

    s1_parameter, s2_parameter = status.value
    command_data = BerTLVMessage(
        [
            BerTLV(0x41, value=s1_parameter),
            BerTLV(0x42, value=s2_parameter),
        ]
    )

    command = ISO7816Command(cla=0x80, ins=0x3C, p1=0x00, p2=0x00, data=command_data)
    logging.info(f"OP_CONTROL_FLOW CMD = {command}")
    response = tag.transceive(command)
    logging.info(f"OP_CONTROL_FLOW RES = {response}")
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"OP_CONTROL_FLOW INVALID STATUS {response.sw}")
    return response.data


def complete_transaction(
    tag: ISO7816Tag,
    secure: AliroSecureChannel | None,
    reader_status: ReaderStatus = ReaderStatus.STATE_UNSECURE,
    max_command_data_size: int = APDU_DEFAULT_MAX_COMMAND_DATA,
):
    # Per spec, completion should be sent via EXCHANGE (0x97) when secure channel exists;
    # otherwise use CONTROL FLOW to indicate failure.
    if secure is None:
        logging.info("Secure channel unavailable, sending CONTROL FLOW failure indication")
        return control_flow(tag)

    # IOS implementation hangs after EXCHANGE of status, and there is no chaining,
    # so we set skip_chaining to True to force a GET RESPONSE and avoid the hang
    response = exchange(
        tag,
        secure,
        BerTLV(0x97, value=reader_status),
        skip_chaining=True,
        max_command_data_size=max_command_data_size,
    )
    if response.sw1 not in (0x90, 0x61):
        logging.info("Reader status EXCHANGE failed, sending CONTROL FLOW failure indication")
        return control_flow(tag)
    return response.data


def perform_authentication_flow(
    tag: ISO7816Tag,
    flow: AliroFlow,
    reader_group_identifier: bytes,
    reader_group_sub_identifier: bytes,
    auth0_command_vendor_extension: bytes | None,
    reader_private_key: ec.EllipticCurvePrivateKey,
    reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    protocol_version: bytes,
    fci_proprietary_template: List[bytes],
    transaction_identifier: bytes,
    command_parameters: int,
    authentication_policy: AuthenticationPolicy,
    reader_certificate: bytes | None,
    interface: Interface,
    endpoints: List[Endpoint],
    max_command_data_size: int = APDU_DEFAULT_MAX_COMMAND_DATA,
    key_size=16,
) -> Tuple[AliroFlow, Endpoint | None]:
    """Returns an Endpoint if one was found and successfully authenticated."""
    reader_public_key = reader_private_key.public_key()

    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()
    endpoint_ephemeral_public_key, endpoint, secure, auth0_info_suffix = fast_auth(
        tag=tag,
        fci_proprietary_template=fci_proprietary_template,
        protocol_version=protocol_version,
        interface=interface,
        command_parameters=command_parameters,
        authentication_policy=authentication_policy,
        reader_group_identifier=reader_group_identifier,
        reader_group_sub_identifier=reader_group_sub_identifier,
        auth0_command_vendor_extension=auth0_command_vendor_extension,
        reader_public_key=reader_public_key,
        reader_ephemeral_public_key=reader_ephemeral_public_key,
        transaction_identifier=transaction_identifier,
        endpoints=endpoints,
        max_command_data_size=max_command_data_size,
        key_size=key_size,
    )

    if endpoint is not None and flow == AliroFlow.FAST:
        _ = complete_transaction(
            tag,
            secure.exchange if secure is not None else None,
            reader_status=ReaderStatus.STATE_UNSECURE,
            max_command_data_size=max_command_data_size,
        )
        return AliroFlow.FAST, endpoint

    k_persistent, endpoint, secure = standard_auth(
        tag=tag,
        fci_proprietary_template=fci_proprietary_template,
        protocol_version=protocol_version,
        interface=interface,
        command_parameters=command_parameters,
        authentication_policy=authentication_policy,
        transaction_identifier=transaction_identifier,
        reader_group_identifier=reader_group_identifier,
        reader_group_sub_identifier=reader_group_sub_identifier,
        reader_private_key=reader_private_key,
        reader_ephemeral_private_key=reader_ephemeral_private_key,
        endpoints=endpoints,
        endpoint_ephemeral_public_key=endpoint_ephemeral_public_key,
        auth0_info_suffix=auth0_info_suffix,
        reader_certificate=reader_certificate,
        max_command_data_size=max_command_data_size,
        key_size=key_size,
    )

    if endpoint is not None and k_persistent is not None:
        endpoint.persistent_key = k_persistent

    if endpoint is None:
        logging.info("AUTH1 did not resolve an endpoint; stopping before step-up and reporting reader failure status")
        _ = complete_transaction(
            tag,
            secure.exchange if secure is not None else None,
            reader_status=ReaderStatus.ACCESS_CREDENTIAL_PUBLIC_KEY_NOT_FOUND,
            max_command_data_size=max_command_data_size,
        )
        return AliroFlow.STANDARD, None

    if secure is None or secure.exchange is None or flow == AliroFlow.STANDARD:
        _ = complete_transaction(
            tag,
            secure.exchange if secure is not None else None,
            reader_status=ReaderStatus.STATE_UNSECURE,
            max_command_data_size=max_command_data_size,
        )
        return AliroFlow.STANDARD, endpoint

    if endpoint.last_signaling_bitmask is None or (
        endpoint.last_signaling_bitmask & SignalingBitmask.STEP_UP_SELECT_REQUIRED_FOR_DOC_RETRIEVAL
    ):
        _ = select_applet(tag, applet=ISO7816Application.ALIRO_STEP_UP)

    if secure.step_up is not None:
        _ = exchange_step_up_documents(tag, secure.step_up, max_command_data_size=max_command_data_size)

    _ = complete_transaction(
        tag,
        secure.step_up if secure is not None else None,
        reader_status=ReaderStatus.STATE_UNSECURE,
        max_command_data_size=max_command_data_size,
    )

    return AliroFlow.STEP_UP, endpoint


def read_aliro(
    tag: ISO7816Tag,
    reader_group_identifier: bytes,
    reader_group_sub_identifier: bytes,
    auth0_command_vendor_extension: bytes | None,
    reader_private_key: bytes,
    endpoints: List[Endpoint],
    preferred_versions: Collection[bytes] = None,
    flow=AliroFlow.FAST,
    authentication_policy: AuthenticationPolicy = AuthenticationPolicy.USER_DEVICE_SETTING,
    reader_certificate: bytes | None = None,
    # Generated at random if not provided
    reader_ephemeral_private_key: bytes | None = None,
    # Generated at random if not provided
    transaction_identifier: bytes | None = None,
    interface=Interface.NFC,
    key_size=16,
) -> Tuple[AliroFlow, Endpoint | None]:
    """Returns the authentication flow used and an optional endpoint if authentication was successful."""
    command_parameters = sum({AliroTransactionFlags.FAST if flow <= AliroFlow.FAST else AliroTransactionFlags.STANDARD})

    response = select_applet(tag, applet=ISO7816Application.ALIRO)

    message = BerTLVMessage.from_bytes(response)

    fci_template = message.find_by_tag_else_throw(0x6F).to_message()
    fci_proprietary_template = fci_template.find_by_tag_else_throw(0xA5).to_message()
    max_command_data_size = resolve_max_command_data_size_from_select_fci(fci_proprietary_template)
    logging.info(f"Using max APDU data size from FCI: {max_command_data_size}")
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
        reader_group_sub_identifier=reader_group_sub_identifier,
        auth0_command_vendor_extension=auth0_command_vendor_extension,
        reader_private_key=reader_private_key,
        reader_ephemeral_private_key=generate_ec_key_if_provided_is_none(reader_ephemeral_private_key),
        protocol_version=protocol_version,
        fci_proprietary_template=BerTLV(0xA5, fci_proprietary_template),
        transaction_identifier=transaction_identifier or os.urandom(16),
        command_parameters=command_parameters,
        authentication_policy=authentication_policy,
        reader_certificate=reader_certificate,
        interface=interface,
        endpoints=endpoints,
        max_command_data_size=max_command_data_size,
        key_size=key_size,
    )
    if endpoint is not None:
        endpoint.last_used_at = int(time.time())
        endpoint.counter += 1
        endpoint.last_fci_template = BerTLV(0xA5, fci_proprietary_template).to_bytes()
        endpoint.last_protocol_version = protocol_version
        endpoint.last_auth_flow = result_flow.name

    return result_flow, endpoint
