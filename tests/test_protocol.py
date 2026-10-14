"""Jason Stys: independent hex/field protocol vectors, extreme quantities and structured/random fuzzing."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_golden_hex — line 52
# parameter: raw — line 53
# parameter: response — line 54
# parameter: address — line 55
# parameter: quantity — line 56
# parameter: values — line 57
# variable: message — line 60
# variable: i — line 91
# definition: test_protocol_reject — line 93
# parameter: data — line 93
# parameter: response — line 93
# definition: test_supported_and_unknown — line 99
# variable: unsupported — line 101
# definition: test_decoder_fuzz — line 115
# parameter: data — line 115
# parameter: response — line 115
# variable: message — line 118
# definition: test_structured_read — line 126
# parameter: address — line 126
# parameter: quantity — line 126
# variable: request — line 128
# variable: response — line 129
# END CODE MAP

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from examples.scenarios import (
    adu,
    read_request,
    read_response,
    write_request,
    write_response,
)
from otmon.contracts import Rejected
from otmon.protocol import decode


@pytest.mark.parametrize(
    "raw,response,address,quantity,values",
    [
        ("000100000006010300640002", False, 100, 2, ()),
        ("000100000007010304006400c8", True, None, 2, (100, 200)),
        ("000100000006010600c801f4", False, 200, 1, (500,)),
        ("000100000006011000c80002", True, 200, 2, ()),
        ("00010000000b011000c800020401f40258", False, 200, 2, (500, 600)),
    ],
)
def test_golden_hex(
    raw: str,
    response: bool,
    address: int | None,
    quantity: int,
    values: tuple[int, ...],
) -> None:
    """Parse official-layout manually encoded vectors, not only encoder/decoder round trips."""
    message = decode(bytes.fromhex(raw), response)
    assert (message.address, message.quantity, message.values) == (
        address,
        quantity,
        values,
    )


@pytest.mark.parametrize(
    "data,response",
    [
        (b"x" * 7, False),
        (b"x" * 261, False),
        (bytes.fromhex("000100010006010300640002"), False),
        (bytes.fromhex("000100000005010300640002"), False),
        (adu(1, b"\0"), False),
        (adu(1, b"\x80"), True),
        (adu(1, b"\x83\x02"), False),
        (adu(1, b"\x83\x07"), True),
        (adu(1, b"\x83"), True),
        (adu(1, b"\x03\x01\0"), True),
        (adu(1, b"\x03\x04\0\0"), True),
        (read_request(quantity=0), False),
        (read_request(quantity=126), False),
        (read_request(address=65535, quantity=2), False),
        (adu(1, b"\x06\0"), False),
        (adu(1, b"\x10\0"), False),
        (adu(1, b"\x10\0\xc8\0\x02\x02\0\x01"), False),
        (write_request(function=16, values=tuple(range(124))), False),
        (write_response(function=16, value=124), True),
    ],
    ids=[f"malformed-{i}" for i in range(19)],
)
def test_protocol_reject(data: bytes, response: bool) -> None:
    """Reject nonexact MBAP/PDU, illegal exception/read/write size/address boundaries."""
    with pytest.raises(Rejected):
        decode(data, response)


def test_supported_and_unknown() -> None:
    """Unknown functions remain explicit visibility gaps; valid exception/base fields are preserved."""
    unsupported = decode(adu(1, b"\x2b\x0e\x01\x00"), False)
    assert not unsupported.supported and unsupported.function == 43
    assert decode(adu(1, b"\xab\x01"), True).supported is False
    assert decode(adu(1, b"\x83\x02"), True).exception == 2
    assert decode(write_request(), False) == decode(write_response(), True)
    assert decode(read_request(function=4, quantity=125), False).quantity == 125
    assert (
        decode(write_request(function=16, values=tuple(range(123))), False).quantity
        == 123
    )


@given(st.binary(max_size=300), st.booleans())
@settings(max_examples=150, deadline=None)
def test_decoder_fuzz(data: bytes, response: bool) -> None:
    """Random bounded ADUs cannot escape controlled rejection or execute anything."""
    try:
        message = decode(data, response)
    except Rejected:
        return
    assert 0 <= message.transaction <= 65535 and 0 <= message.unit <= 255


@given(st.integers(1, 125), st.integers(0, 65411))
@settings(max_examples=100, deadline=None)
def test_structured_read(quantity: int, address: int) -> None:
    """Exercise valid read-count/address space with independent request/response field checks."""
    request = decode(read_request(address=address, quantity=quantity), False)
    response = decode(read_response(values=(123,) * quantity), True)
    assert (
        request.quantity == response.quantity == quantity and request.address == address
    )
