from enum import IntEnum


class AliroFlow(IntEnum):
    FAST = 0x00
    STANDARD = 0x01
    STEP_UP = 0x02

    @classmethod
    def parse(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)

        normalized = str(value).strip().lower().replace("-", "_")
        aliases = {
            "expedited": cls.FAST,
            "fast": cls.FAST,
            "standard": cls.STANDARD,
            "attestation": cls.STEP_UP,
            "step_up": cls.STEP_UP,
            "stepup": cls.STEP_UP,
        }
        if normalized in aliases:
            return aliases[normalized]

        return cls[normalized.upper()]
