from enum import IntFlag


class SignalingBitmask(IntFlag):
    ACCESS_DOCUMENT_RETRIEVABLE = 1 << 0
    REVOCATION_DOCUMENT_RETRIEVABLE = 1 << 1
    STEP_UP_SELECT_REQUIRED_FOR_DOC_RETRIEVAL = 1 << 2
    MAILBOX_HAS_NON_ZERO_DATA = 1 << 3
    MAILBOX_READ_SUPPORTED = 1 << 4
    MAILBOX_WRITE_SET_SUPPORTED = 1 << 5
    ISSUER_BACKEND_NOTIFY_SUPPORTED = 1 << 6
    BOUND_APP_NOTIFY_SUPPORTED = 1 << 7
    UPDATE_DOC_SUPPORTED_EXPEDITED = 1 << 9
    MAILBOX_FEATURE_SET_SUPPORTED_STEP_UP = 1 << 10
    NOTIFY_FEATURE_SUPPORTED_STEP_UP = 1 << 11
    UPDATE_DOC_SUPPORTED_STEP_UP = 1 << 12

    @classmethod
    def parse(cls, value):
        if value is None:
            return None
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        if isinstance(value, (bytes, bytearray)):
            if len(value) == 0:
                return None
            return cls(int.from_bytes(value, "big"))
        if isinstance(value, (list, tuple, set)):
            bitmask = cls(0)
            for entry in value:
                bitmask |= cls[str(entry).strip().upper()]
            return bitmask

        normalized = str(value).strip().lower()
        if normalized == "":
            return None
        if normalized.startswith("0x"):
            normalized = normalized[2:]
        return cls(int(normalized, 16))

    def to_bytes(self) -> bytes:
        return int(self).to_bytes(2, "big")

    def to_names(self):
        return [flag.name for flag in type(self) if self & flag]
