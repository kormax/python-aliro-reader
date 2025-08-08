from typing import Tuple

from util.structable import Packable, PackableData, to_bytes

ECP_HEADER = 0x6A
SUBTYPE_HOMEKEY = 0x06
TYPE_ACCESS = 0x02
TCI_ALIRO = bytes.fromhex("204220")


class ECP(Packable):
    """Elliptic Curve Point"""

    command: int
    version: int

    def to_bytes(self):
        raise NotImplementedError()

    @staticmethod
    def aliro(identifier: bytes, **kwargs):
        return ECPV2(
            terminal_type=TYPE_ACCESS,
            terminal_subtype=SUBTYPE_HOMEKEY,
            payload=(
                TCI_ALIRO,
                # 8 bytes long unique identifier that is the same on all locks in one household
                identifier[:8],
            ),
            **kwargs,
        )


class ECPV2(ECP):
    """Elliptic Curve Point Version 2"""

    params: Tuple[int, int, int, int, int, int, int]
    unknown: Tuple[int, int, int]

    def __init__(
        self,
        terminal_type: int,
        terminal_subtype: int,
        payload: PackableData = b"",
        flag_1=1,  # Usually set to 1. Will require auth if not set
        flag_2=1,  # Authentication not required flag; Usually set to 1 (to enable express mode)
        flag_3=0,
        flag_4=0,
    ):
        self.terminal_type = terminal_type
        self.terminal_subtype = terminal_subtype
        self.payload = payload
        self.flag_1 = flag_1
        self.flag_2 = flag_2
        self.flag_3 = flag_3
        self.flag_4 = flag_4

    @property
    def version(self):
        return 0x02

    def to_bytes(self):
        payload = to_bytes(self.payload)
        assert len(payload) <= 15
        terminal_info = (self.flag_1 << 7) + (self.flag_2 << 6) + (self.flag_3 << 5) + (self.flag_4 << 4) + len(payload)
        terminal = (terminal_info, self.terminal_type, self.terminal_subtype)
        return to_bytes(
            (
                ECP_HEADER,
                self.version,
                terminal,
                payload,
            )
        )
