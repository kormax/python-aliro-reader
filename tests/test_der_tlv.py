import pytest

from util.tlv.der import DerTLV


def test_der_tlv_short_length_encoding_roundtrip():
    tlv = DerTLV(0x5A, b"\x01\x02")
    encoded = tlv.to_bytes()

    assert encoded == b"\x5a\x02\x01\x02"

    parsed = DerTLV.from_bytes(encoded)
    assert parsed.tag == b"\x5a"
    assert parsed.value == b"\x01\x02"


def test_der_tlv_long_length_encoding_roundtrip():
    value = bytes(range(200))
    tlv = DerTLV(0x5A, value)
    encoded = tlv.to_bytes()

    assert encoded[:3] == b"\x5a\x81\xc8"

    parsed = DerTLV.from_bytes(encoded)
    assert parsed.tag == b"\x5a"
    assert parsed.value == value


def test_der_tlv_rejects_indefinite_length():
    # Indefinite form (0x80) is BER-only, not DER.
    encoded = b"\x5a\x80\x00\x00"
    with pytest.raises(ValueError):
        DerTLV.from_bytes(encoded)


def test_der_tlv_rejects_non_canonical_long_form_for_short_length():
    # 127 encoded in long form should be rejected by DER.
    encoded = b"\x5a\x81\x7f" + (b"\xaa" * 0x7F)
    with pytest.raises(ValueError):
        DerTLV.from_bytes(encoded)


def test_der_tlv_helper_constructors():
    assert isinstance(DerTLV.primitive(0x80, 1), DerTLV)
    assert DerTLV.primitive(0x80, 1).to_bytes() == b"\x80\x01\x01"
    assert DerTLV.context_primitive(0, b"\xab").to_bytes() == b"\x80\x01\xab"
    assert DerTLV.context_constructed(3, b"\x01\x02").to_bytes() == b"\xa3\x02\x01\x02"
    assert DerTLV.boolean(True).to_bytes() == b"\x01\x01\xff"
    assert DerTLV.boolean(False).to_bytes() == b"\x01\x01\x00"
    assert DerTLV.time("200101000000Z").to_bytes() == b"\x17\x0d200101000000Z"
    assert DerTLV.time("20200101000000Z").to_bytes() == b"\x18\x0f20200101000000Z"

    sequence = DerTLV.sequence(DerTLV.integer(1), DerTLV.octet_string(b"\xaa"))
    assert sequence.to_bytes() == b"\x30\x06\x02\x01\x01\x04\x01\xaa"


def test_der_tlv_context_helpers_validate_tag_range():
    with pytest.raises(ValueError):
        DerTLV.context_primitive(31, b"\x00")
    with pytest.raises(ValueError):
        DerTLV.context_constructed(-1, b"\x00")
