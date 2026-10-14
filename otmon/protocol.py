"""Jason Stys: bounded Modbus/TCP ADU decoder for FC03/04/06/16 and explicit unsupported-code visibility."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: SUPPORTED — line 38
# variable: EXCEPTIONS — line 39
# definition: Message — line 43
# variable: transaction — line 46
# variable: unit — line 47
# variable: function — line 48
# variable: address — line 49
# variable: quantity — line 50
# variable: values — line 51
# variable: exception — line 52
# variable: supported — line 53
# definition: decode — line 56
# parameter: data — line 56
# parameter: response — line 56
# variable: length — line 59
# variable: protocol — line 59
# variable: transaction — line 59
# variable: unit — line 59
# variable: function — line 64
# variable: body — line 65
# variable: values — line 89
# variable: address — line 93
# variable: count — line 93
# variable: quantity — line 93
# variable: values — line 101
# variable: address — line 104
# variable: value — line 104
# variable: limit — line 107
# END CODE MAP

import struct
from dataclasses import dataclass

from otmon.contracts import require

SUPPORTED = {3, 4, 6, 16}
EXCEPTIONS = {1, 2, 3, 4, 5, 6, 8, 10, 11}


@dataclass(frozen=True)
class Message:
    """One decoded PDU; addresses exist only when carried, responses need correlation for read addresses."""

    transaction: int
    unit: int
    function: int
    address: int | None = None
    quantity: int | None = None
    values: tuple[int, ...] = ()
    exception: int | None = None
    supported: bool = True


def decode(data: bytes, response: bool) -> Message:
    """Validate exact MBAP/PDU lengths and bounds without treating unsupported functions as healthy traffic."""
    require(8 <= len(data) <= 260, "invalid ADU size")
    transaction, protocol, length, unit = struct.unpack(">HHHB", data[:7])
    require(
        protocol == 0 and 2 <= length <= 254 and length + 6 == len(data),
        "invalid MBAP header",
    )
    function = data[7]
    body = data[8:]
    require(function != 0 and function != 128, "invalid function code")
    if function & 128:
        require(
            response and len(body) == 1 and body[0] in EXCEPTIONS,
            "invalid exception response",
        )
        return Message(
            transaction,
            unit,
            function & 127,
            exception=body[0],
            supported=(function & 127) in SUPPORTED,
        )
    if function not in SUPPORTED:
        return Message(transaction, unit, function, supported=False)
    if function in {3, 4} and response:
        require(
            len(body) >= 3
            and body[0] == len(body) - 1
            and body[0] % 2 == 0
            and 2 <= body[0] <= 250,
            "invalid read response",
        )
        values = struct.unpack(">" + "H" * (body[0] // 2), body[1:])
        return Message(transaction, unit, function, quantity=len(values), values=values)
    if function == 16 and not response:
        require(len(body) >= 7, "invalid multiple-write request")
        address, quantity, count = struct.unpack(">HHB", body[:5])
        require(
            1 <= quantity <= 123
            and count == 2 * quantity
            and len(body) == 5 + count
            and address + quantity <= 65536,
            "invalid multiple-write bounds",
        )
        values = struct.unpack(">" + "H" * quantity, body[5:])
        return Message(transaction, unit, function, address, quantity, values)
    require(len(body) == 4, "invalid fixed PDU size")
    address, value = struct.unpack(">HH", body)
    if function == 6:
        return Message(transaction, unit, function, address, 1, (value,))
    limit = 123 if function == 16 else 125
    require(
        1 <= value <= limit and address + value <= 65536,
        "invalid register quantity/address",
    )
    return Message(transaction, unit, function, address, value)
