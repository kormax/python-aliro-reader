from enum import Enum


class ReaderStatus(Enum):
    FAILURE_NO_INFORMATION = (0x00, 0x00)
    ACCESS_CREDENTIAL_PUBLIC_KEY_NOT_FOUND = (0x00, 0x01)
    ACCESS_CREDENTIAL_PUBLIC_KEY_EXPIRED = (0x00, 0x02)
    ACCESS_CREDENTIAL_PUBLIC_KEY_NOT_TRUSTED = (0x00, 0x03)
    INVALID_USER_DEVICE_SIGNATURE = (0x00, 0x04)
    INVALID_DATA_FORMAT = (0x00, 0x06)
    INVALID_DATA_CONTENT = (0x00, 0x07)
    STATUS_WORD_ERROR = (0x00, 0x20)
    NO_KEY_SLOT_IN_RESPONSE = (0x00, 0x21)
    NO_PUBLIC_KEY_IN_RESPONSE = (0x00, 0x22)
    NO_USER_DEVICE_SIGNATURE_PRESENT = (0x00, 0x23)
    INVALID_ACCESS_RIGHTS = (0x00, 0x25)
    HARDWARE_ISSUE = (0x00, 0x26)
    FAILURE_PROTOCOL_VERSION_NOT_SUPPORTED = (0x00, 0x27)

    STATE_SECURE = (0x01, 0x00)
    STATE_UNSECURE = (0x01, 0x01)
    STATE_OBSTRUCTED = (0x01, 0x02)
    ENTERING_SECURE_STATE = (0x01, 0x80)
    ENTERING_UNSECURE_STATE = (0x01, 0x81)
    STATE_UNKNOWN = (0x01, 0x82)

    @property
    def first_byte(self) -> int:
        return self.value[0]

    @property
    def second_byte(self) -> int:
        return self.value[1]

    def to_bytes(self) -> bytes:
        return bytes(self.value)

    @classmethod
    def op_control_flow_allowed(cls) -> set["ReaderStatus"]:
        return {
            cls.FAILURE_NO_INFORMATION,
            cls.FAILURE_PROTOCOL_VERSION_NOT_SUPPORTED,
        }
