from typing import Tuple

from util.crypto import decrypt_aes_gcm, encrypt_aes_gcm
from util.iso7816 import ISO7816Command, ISO7816Response
from util.structable import Packable

READER_MODE = bytes.fromhex("0000000000000000")
ENDPOINT_MODE = bytes.fromhex("0000000000000001")


def _key_hex(value):
    if value is None:
        return None
    return bytes(value).hex().upper()


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

    def encrypt_reader_data(self, plaintext: bytes | Packable) -> bytes:
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


__all__ = [
    "READER_MODE",
    "ENDPOINT_MODE",
    "AliroSecureChannel",
    "AliroSecureContext",
]
