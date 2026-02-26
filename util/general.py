import base64
import binascii


def hex_or_base64_to_bytes(value: str) -> tuple[bytes]:
    normalized = "".join(value.split())
    if len(normalized) == 0:
        raise ValueError("value cannot be empty")

    hex_candidate = normalized[2:] if normalized.lower().startswith("0x") else normalized
    try:
        return bytes.fromhex(hex_candidate)
    except ValueError:
        pass

    try:
        return base64.b64decode(normalized, validate=True)
    except binascii.Error as exc:
        raise ValueError("value must be hex or base64") from exc
