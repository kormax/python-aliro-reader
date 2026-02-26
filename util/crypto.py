from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key

from util.structable import Packable, to_bytes

ECSDA_PUBLIC_KEY_ASN_HEADER = bytearray.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")


def get_ec_key_public_points(key):
    return key.public_numbers().x.to_bytes(32, "big"), key.public_numbers().y.to_bytes(32, "big")


def load_ec_public_key_from_bytes(data: Union[bytes, str], curve=ec.SECP256R1()):
    if isinstance(data, str):
        data = bytes.fromhex(data)
    if data[0] == 0x04:
        return EllipticCurvePublicNumbers(
            int.from_bytes(data[1:33], "big"),
            int.from_bytes(data[33:], "big"),
            curve=curve,
        ).public_key()
    elif data[0] in (0x03, 0x02):
        return load_der_public_key(ECSDA_PUBLIC_KEY_ASN_HEADER + data)
    else:
        raise ValueError("Does not look like an ec key")


def decrypt_aes_gcm(key: bytes, iv: bytes, ciphertext: bytes):
    ciphertext, tag = ciphertext[:-16], ciphertext[-16:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, bytes(tag)),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_aes_gcm(key: bytes, iv: bytes, plaintext: bytes):
    assert len(iv) == 12, "IV must be 12 bytes for GCM mode"
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    return encryptor.update(to_bytes(plaintext)) + encryptor.finalize() + encryptor.tag


def hkdf_sha256(ikm: bytes, salt: bytes | Packable | list, info: bytes | Packable | list, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=to_bytes(salt),
        info=to_bytes(info),
    ).derive(ikm)
