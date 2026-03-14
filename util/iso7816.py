from enum import Enum, IntEnum
from typing import Any, Union

from util.structable import Packable, Unpackable, to_bytes

#
# Command and response classes were inspired by and based on similar classes from following projects:
# https://github.com/apuigsech/emv-framework
# Documentation regarding the params was taken from:
# https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/
#


class ISO7816Application(Enum):
    ALIRO_EXPEDITED = bytes.fromhex("A000000909ACCE5501")
    ALIRO_STEP_UP = bytes.fromhex("A000000909ACCE5502")


class ISO7816Instruction(IntEnum):
    SELECT_FILE = 0xA4

    GET_RESPONSE = 0xC0


class ISO7816Class(int):
    pass


class ISO7816Command(Packable):
    cla: Union[int, ISO7816Class]
    ins: Union[int, ISO7816Instruction]
    p1: int
    p2: int
    data: bytes
    ne: int
    extended: bool

    def __init__(
        self,
        *,
        cla=0x00,
        ins=0x00,
        p1=0x00,
        p2=0x00,
        data=None,
        # None resolves to max amount of response requested for selected format
        ne=None,
        extended: bool | None = None,
    ):
        super().__init__()
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = to_bytes(data) if data is not None else b""
        if len(self.data) > 0xFFFF:
            raise ValueError(f"APDU data length exceeds extended limit (65535): {len(self.data)}")

        if ne is None:
            ne_value = None  # auto: resolved to max for format after extended is known
        elif ne == 0 or ne == -1:
            ne_value = 0
        else:
            ne_value = int(ne)
            if ne_value < 0:
                raise ValueError(f"Ne must be 0 (no Le field), None (max for format), or 1-65536, actual = {ne_value}")
            elif ne_value > 65536:
                raise ValueError(f"Ne {ne_value} exceeds maximum (65536)")

        resolved_extended = (
            bool(extended)
            if extended is not None
            else (len(self.data) > 0xFF or (ne_value is not None and ne_value > 256))
        )

        if ne_value is None:
            ne_value = 65536 if resolved_extended else 256

        if not resolved_extended and len(self.data) > 0xFF:
            raise ValueError(
                f"APDU data length {len(self.data)} exceeds short format limit (255); "
                f"remove extended=False or reduce data"
            )
        if ne_value != 0:
            ne_limit = 65536 if resolved_extended else 256
            if ne_value > ne_limit:
                raise ValueError(
                    f"Ne {ne_value} exceeds {'extended' if resolved_extended else 'short'} format limit ({ne_limit})"
                )

        self.extended = resolved_extended
        self.ne = ne_value

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]):  # noqa: C901
        """
        1:  | cla | ins | p1 | p2 |                                      len = 4
        2s: | cla | ins | p1 | p2 | le |                                 len = 5
        3s: | cla | ins | p1 | p2 | lc | body |                          len = 6..260
        4s: | cla | ins | p1 | p2 | lc | body | le |                     len = 7..261
        2e: | cla | ins | p1 | p2 | 00 | le1 | le2 |                     len = 7
        3e: | cla | ins | p1 | p2 | 00 | lc1 | lc2 | body |              len = 8..65542
        4e: | cla | ins | p1 | p2 | 00 | lc1 | lc2 | body | le1 | le2 |  len =10..65544
        """
        command = bytes(data)
        if len(command) < 4:
            raise ValueError("APDU command must contain at least 4 bytes (CLA, INS, P1, P2)")
        cla, ins, p1, p2 = command[:4]
        payload = command[4:]

        # Case 1
        if len(payload) == 0:
            return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=b"", extended=False)

        # Case 2s must be handled before extended-marker detection because
        # short Le=0x00 is valid and means "maximum short response length (Ne=256)".
        if len(payload) == 1:
            ne = 256 if payload[0] == 0 else payload[0]
            return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=b"", ne=ne, extended=False)

        # Extended-length cases start with 0x00 after header.
        if payload[0] == 0x00:
            if len(payload) < 3:
                raise ValueError("Malformed extended APDU: missing length bytes after 0x00 marker")

            # Case 2e: header + 00 + Le(2)
            if len(payload) == 3:
                le = int.from_bytes(payload[1:3], "big")
                ne = 65536 if le == 0 else le
                return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=b"", ne=ne, extended=True)

            lc = int.from_bytes(payload[1:3], "big")
            if lc == 0:
                raise ValueError("Malformed extended APDU: Lc=0 is not valid for command data")

            data_start = 3
            data_end = data_start + lc
            if len(payload) < data_end:
                raise ValueError(
                    f"Malformed extended APDU: Lc={lc} but only {len(payload) - data_start} data bytes present"
                )
            if len(payload) == data_end:
                # Case 3e
                return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=payload[data_start:data_end], extended=True)
            if len(payload) == data_end + 2:
                # Case 4e
                le = int.from_bytes(payload[data_end : data_end + 2], "big")
                ne = 65536 if le == 0 else le
                return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=payload[data_start:data_end], ne=ne, extended=True)
            raise ValueError(
                f"Malformed extended APDU: {len(payload) - data_end} trailing bytes after data (expected 0 or 2)"
            )

        # Remaining short-length cases (payload[0] != 0x00, so lc >= 1).
        lc = payload[0]
        data_start = 1
        data_end = data_start + lc
        if len(payload) < data_end:
            raise ValueError(f"Malformed short APDU: Lc={lc} but only {len(payload) - data_start} data bytes present")
        if len(payload) == data_end:
            # Case 3s
            return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=payload[data_start:data_end], extended=False)
        if len(payload) == data_end + 1:
            # Case 4s
            le = payload[data_end]
            ne = 256 if le == 0 else le
            return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=payload[data_start:data_end], ne=ne, extended=False)
        raise ValueError(f"Malformed short APDU: {len(payload) - data_end} trailing bytes after data (expected 0 or 1)")

    @property
    def nc(self):
        return len(to_bytes(self.data))

    @property
    def lc(self):
        if self.nc == 0:
            return b""
        if self.extended:
            return self.nc.to_bytes(2, "big")
        return bytes([self.nc])

    @property
    def le(self) -> bytes:
        if self.ne == 0:
            return b""
        limit = 65536 if self.extended else 256
        wire = 0 if self.ne == limit else self.ne
        if self.extended:
            return wire.to_bytes(2, "big")
        return bytes([wire])

    def to_bytes(self) -> bytes:
        if self.extended:
            if self.nc > 0:
                return bytes([self.cla, self.ins, self.p1, self.p2, 0x00, *self.lc, *self.data, *self.le])
            if self.le:
                return bytes([self.cla, self.ins, self.p1, self.p2, 0x00, *self.le])
            return bytes([self.cla, self.ins, self.p1, self.p2])

        if self.nc > 0:
            return bytes([self.cla, self.ins, self.p1, self.p2, *self.lc, *self.data, *self.le])
        return bytes([self.cla, self.ins, self.p1, self.p2, *self.le])

    def __repr__(self):
        return (
            "ISO7816Command("
            + f"cla=0x{to_bytes(self.cla).hex()}"
            + f"; ins=0x{to_bytes(self.ins).hex()}"
            + f"; p1=0x{to_bytes(self.p1).hex()}"
            + f"; p2=0x{to_bytes(self.p2).hex()}"
            + (f"; lc=0x{self.lc.hex()}({self.nc})" if self.lc else "")
            + (f"; data={to_bytes(self.data).hex()}" if self.nc else "")
            + (f"; le=0x{self.le.hex()}" if self.le else "")
            + (f"; extended={self.extended}" if self.extended is True else "")
            + ")"
        )


class ISO7816StatusGroup(IntEnum):
    SUCCESS = 0x90
    OK = 0x91
    OK_MORE_DATA_LEFT = 0x61

    WARNING_AND_MEMORY_WAS_CHANGED = 0x62
    WARNING_AND_MEMORY_WAS_NOT_CHANGED = 0x63

    ERROR_COMMAND_NOT_EXECUTED_MEMORY_NOT_CHANGED = 0x64
    ERROR_COMMAND_NOT_EXECUTED_MEMORY_CHANGED = 0x65
    ERROR_COMMAND_NOT_EXECUTED_DUE_TO_SECURITY_SETTINGS = 0x66

    ERROR_FORMAT_WRONG_COMMAND_LENGTH = 0x67
    ERROR_LOGIC_CHANNEL_UNSUPPORTED = 0x68
    ERROR_COMMAND_NOT_ALLOWED = 0x69
    ERROR_WRONG_PARAMETERS_V1 = 0x6A
    ERROR_WRONG_PARAMETERS_V2 = 0x6B
    ERROR_WRONG_LE = 0x6C
    ERROR_WRONG_INS = 0x6D
    ERROR_UNKNOWN_CLA = 0x6E
    ERROR_UNKNOWN = 0x6F


class ISO7816Response(Unpackable, Packable):
    sw1: Union[int, ISO7816StatusGroup]
    sw2: int
    data: bytearray

    def __init__(self, *, sw1=0x00, sw2=0x00, data=None):
        try:
            self.sw1 = ISO7816StatusGroup(sw1)
        except (TypeError, ValueError):
            self.sw1 = sw1
        self.sw2 = sw2
        self.data = data or bytearray()

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> "ISO7816Response":
        *data, sw1, sw2 = data
        return ISO7816Response(sw1=sw1, sw2=sw2, data=bytearray(data))

    @property
    def sw(self):
        return self.sw1, self.sw2

    def to_bytes(self):
        return to_bytes((self.data, self.sw1, self.sw2))

    def __repr__(self):
        return (
            "ISO7816Response("
            + f"sw1=0x{hex(self.sw1)[2:].zfill(2)}"
            + f"; sw2=0x{hex(self.sw2)[2:].zfill(2)}"
            + (f"; data={self.data.hex()}({len(self.data)})" if len(self.data) else "")
            + ")"
        )


class ISO7816:
    @classmethod
    def select_file(cls, data: bytes, cla=0x00, p1=0x00, p2=0x00, ne=256):
        return ISO7816Command(
            cla=cla,
            ins=ISO7816Instruction.SELECT_FILE,
            p1=p1,
            p2=p2,
            data=data,
            ne=ne,
        )

    @classmethod
    def select_aid(cls, aid: Union[bytes, ISO7816Application], p1=0x04, p2=0x00, ne=256):
        return cls.select_file(data=aid, p1=p1, p2=p2, ne=ne)


class ISO7816Tag:
    def __init__(self, implementation: Any) -> None:
        self._implementation = implementation

    def transceive(self, data: Union[bytes, ISO7816Command]) -> ISO7816Response:
        return ISO7816Response.from_bytes(
            self._implementation.transceive(bytes(data.to_bytes()) if isinstance(data, ISO7816Command) else bytes(data))
        )
