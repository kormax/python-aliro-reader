from enum import IntFlag


class Auth1CommandParameters(IntFlag):
    REQUEST_KEY_SLOT = 0x00
    REQUEST_PUBLIC_KEY = 0x01

    @property
    def key_slot_requested(self) -> bool:
        return not bool(self & type(self).REQUEST_PUBLIC_KEY)

    @property
    def public_key_requested(self) -> bool:
        return bool(self & type(self).REQUEST_PUBLIC_KEY)
