from enum import IntEnum


class AuthenticationPolicy(IntEnum):
    USER_DEVICE_SETTING = 0x01
    USER_DEVICE_SETTING_SECURE_ACTION = 0x02
    FORCE_USER_AUTHENTICATION = 0x03

    @classmethod
    def parse(cls, value):
        if value is None:
            return cls.USER_DEVICE_SETTING
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)

        normalized = str(value).strip().lower().replace(" ", "_")
        aliases = {
            "express": cls.USER_DEVICE_SETTING,
            "original": cls.USER_DEVICE_SETTING,
            "user": cls.USER_DEVICE_SETTING,
            "user_device_setting": cls.USER_DEVICE_SETTING,
            "secure": cls.USER_DEVICE_SETTING_SECURE_ACTION,
            "user_device_setting_secure_action": cls.USER_DEVICE_SETTING_SECURE_ACTION,
            "force": cls.FORCE_USER_AUTHENTICATION,
            "force_user_authentication": cls.FORCE_USER_AUTHENTICATION,
        }
        if normalized in aliases:
            return aliases[normalized]

        return cls[normalized.upper()]
