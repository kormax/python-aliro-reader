from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aliro.certificate import (
    Profile0000Certificate,
)


def _hex_bytes(value: str) -> bytes:
    return bytes.fromhex("".join(value.split()))


def _public_key(value: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _hex_bytes(value))


def _private_key(value: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_der_private_key(_hex_bytes(value), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return key


def test_profile0000_generate_supports_custom_fields():
    issuer_private_key = ec.generate_private_key(ec.SECP256R1())
    subject_public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    profile = Profile0000Certificate.generate(
        issuer_private_key=issuer_private_key,
        subject_public_key=subject_public_key,
        serial_number=_hex_bytes("04278ba9fd71"),
        issuer_name="custom issuer name",
        subject_name="custom subject name",
        not_before="200102000000Z",
        not_after="250505000000Z",
    )
    reader_cert = profile.to_bytes()

    parsed = Profile0000Certificate.from_bytes(reader_cert)
    assert parsed.serial == _hex_bytes("04278ba9fd71")
    assert parsed.issuer == b"custom issuer name"
    assert parsed.not_before == b"200102000000Z"
    assert parsed.not_after == b"250505000000Z"
    assert parsed.subject == b"custom subject name"
    assert (
        parsed.subject_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )[0]
        == 0x04
    )
    assert parsed.signature[0] == 0x30

    assert Profile0000Certificate.from_bytes(reader_cert).to_bytes() == reader_cert

    _ = parsed.to_x509_der_bytes(issuer_private_key.public_key())
    parsed.verify(issuer_public_key=issuer_private_key.public_key())
    assert parsed.subject_public_key.public_numbers() == subject_public_key.public_numbers()


def test_demo1_certificate_vector_end_to_end():
    """Aliro Specification v1.0, section 14.1, Demo 1."""
    reader_public_key_hex = """
    04842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc340
    1c3a4f4e5a59251d45243ac8544a665cb951422f
    """
    reader_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201a39e361b0db1915c2
    510bd92f3dbeb319ed68b16a0294347629d2e4becdb599a14403420004842242f6182ba1c1138d32b77fb9f7f3
    7b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb9
    51422f
    """
    issuer_public_key_hex = """
    04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f372814a312c3cb82a5a9
    7bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd
    """
    issuer_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104204b45df37a327a31303
    113f9965d14de94f025f881515e13034a3d8a9ac47e43ea14403420004793e3a8f20428d54e7318046d75d05a8
    737eb6e074e5146a207bff62dae90e24039f372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da
    7de7bd
    """
    input_x509_cert_hex = """
    308201523081f9a003020102020101300a06082a8648ce3d0403023011310f300d06035504030c066973737565
    72301e170d3230303130313030303030305a170d3439303130313030303030305a30123110300e06035504030c
    077375626a6563743059301306072a8648ce3d020106082a8648ce3d03010703420004842242f6182ba1c1138d
    32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243a
    c8544a665cb951422fa341303f301f0603551d230418301680142318e55671f08eae212142a817720fb817ee93
    bf300c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06082a8648ce3d0403020348
    0030450221008720a2f08626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c76783607a22cc60220236a4b757c
    d497c8570e84fa3221be99f6c78cc7cbc71d7328aa99be03f1eccf
    """
    compressed_cert_hex = """
    3081950402000030818e85420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb
    36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f86480030450221008720a2f0
    8626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c76783607a22cc60220236a4b757cd497c8570e84fa3221be
    99f6c78cc7cbc71d7328aa99be03f1eccf
    """

    reader_private_key = _private_key(reader_private_key_hex)
    issuer_private_key = _private_key(issuer_private_key_hex)
    compressed_cert = _hex_bytes(compressed_cert_hex)
    input_x509_cert = _hex_bytes(input_x509_cert_hex)
    issuer_public_key = _public_key(issuer_public_key_hex)
    subject_public_key = _public_key(reader_public_key_hex)

    # Compression must reproduce the exact profile0000 vector.
    assert Profile0000Certificate.from_x509(input_x509_cert).to_bytes() == compressed_cert
    assert (
        Profile0000Certificate.from_x509(x509.load_der_x509_certificate(input_x509_cert)).to_bytes() == compressed_cert
    )

    # Vector sanity: private key blobs must map to the expected public keys.
    assert reader_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(reader_public_key_hex)
    assert issuer_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(issuer_public_key_hex)

    # Profile parsing expectations from Demo 1 (all optional fields omitted).
    profile = Profile0000Certificate.from_bytes(compressed_cert)
    assert profile.serial == Profile0000Certificate.DEFAULT_SERIAL
    assert profile.issuer == Profile0000Certificate.DEFAULT_ISSUER
    assert profile.not_before == Profile0000Certificate.DEFAULT_NOT_BEFORE
    assert profile.not_after == Profile0000Certificate.DEFAULT_NOT_AFTER
    assert profile.subject == Profile0000Certificate.DEFAULT_SUBJECT

    # Decompression must reproduce the exact DER X509 vector.
    decompressed_der = Profile0000Certificate.from_bytes(compressed_cert).to_x509_der_bytes(issuer_public_key)
    assert decompressed_der == _hex_bytes(input_x509_cert_hex)

    # Verification passes for the expected issuer/subject key pair.
    parsed_profile = Profile0000Certificate.from_bytes(compressed_cert)
    parsed_profile.verify(issuer_public_key=issuer_public_key)
    assert parsed_profile.subject_public_key.public_numbers() == subject_public_key.public_numbers()

    # Subject key comparison is caller-managed.
    wrong_subject_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    assert parsed_profile.subject_public_key.public_numbers() != wrong_subject_key.public_numbers()


def test_demo2_certificate_vector_end_to_end():
    """Aliro Specification v1.0, section 14.1, Demo 2."""
    reader_public_key_hex = """
    04842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc340
    1c3a4f4e5a59251d45243ac8544a665cb951422f
    """
    reader_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201a39e361b0db1915c2
    510bd92f3dbeb319ed68b16a0294347629d2e4becdb599a14403420004842242f6182ba1c1138d32b77fb9f7f3
    7b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb9
    51422f
    """
    issuer_public_key_hex = """
    04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f372814a312c3cb82a5a9
    7bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd
    """
    issuer_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104204b45df37a327a31303
    113f9965d14de94f025f881515e13034a3d8a9ac47e43ea14403420004793e3a8f20428d54e7318046d75d05a8
    737eb6e074e5146a207bff62dae90e24039f372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da
    7de7bd
    """
    input_x509_cert_hex = """
    308201643082010aa003020102020604278ba9fd71300a06082a8648ce3d040302301d311b301906035504030c
    12637573746f6d20697373756572206e616d65301e170d3230303130313030303030305a170d32353035303530
    30303030305a30123110300e06035504030c077375626a6563743059301306072a8648ce3d020106082a8648ce
    3d03010703420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f9
    1a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422fa341303f301f0603551d2304183016801423
    18e55671f08eae212142a817720fb817ee93bf300c0603551d130101ff04023000300e0603551d0f0101ff0404
    03020780300a06082a8648ce3d040302034800304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa7
    53cbd876c02f0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47bf5a7236accfb378347e
    """
    compressed_cert_hex = """
    3081c0040200003081b9800604278ba9fd718112637573746f6d20697373756572206e616d65830d3235303530
    353030303030305a85420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb3649
    0a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f864800304502206080fed25cf442
    226d5017c0e3f5f929ff5cbd18bfa753cbd876c02f0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cec
    e7c96fff47bf5a7236accfb378347e
    """

    reader_private_key = _private_key(reader_private_key_hex)
    issuer_private_key = _private_key(issuer_private_key_hex)
    compressed_cert = _hex_bytes(compressed_cert_hex)
    input_x509_cert = _hex_bytes(input_x509_cert_hex)
    issuer_public_key = _public_key(issuer_public_key_hex)
    subject_public_key = _public_key(reader_public_key_hex)

    # Compression must reproduce the exact profile0000 vector.
    assert Profile0000Certificate.from_x509(input_x509_cert).to_bytes() == compressed_cert
    assert (
        Profile0000Certificate.from_x509(x509.load_der_x509_certificate(input_x509_cert)).to_bytes() == compressed_cert
    )

    # Vector sanity: private key blobs must map to the expected public keys.
    assert reader_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(reader_public_key_hex)
    assert issuer_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(issuer_public_key_hex)

    # Profile parsing expectations from Demo 2.
    profile = Profile0000Certificate.from_bytes(compressed_cert)
    assert profile.serial == _hex_bytes("04278ba9fd71")
    assert profile.issuer == b"custom issuer name"
    assert profile.not_before == Profile0000Certificate.DEFAULT_NOT_BEFORE
    assert profile.not_after == b"250505000000Z"
    assert profile.subject == Profile0000Certificate.DEFAULT_SUBJECT

    # Decompression must reproduce the exact DER X509 vector.
    decompressed_der = Profile0000Certificate.from_bytes(compressed_cert).to_x509_der_bytes(issuer_public_key)
    assert decompressed_der == _hex_bytes(input_x509_cert_hex)

    # Verification passes for the expected issuer/subject key pair.
    parsed_profile = Profile0000Certificate.from_bytes(compressed_cert)
    parsed_profile.verify(issuer_public_key=issuer_public_key)
    assert parsed_profile.subject_public_key.public_numbers() == subject_public_key.public_numbers()

    # Subject key comparison is caller-managed.
    wrong_subject_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    assert parsed_profile.subject_public_key.public_numbers() != wrong_subject_key.public_numbers()


def test_demo3_certificate_vector_end_to_end():
    """Aliro Specification v1.0, section 14.1, Demo 3."""
    reader_public_key_hex = """
    04842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc340
    1c3a4f4e5a59251d45243ac8544a665cb951422f
    """
    reader_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201a39e361b0db1915c2
    510bd92f3dbeb319ed68b16a0294347629d2e4becdb599a14403420004842242f6182ba1c1138d32b77fb9f7f3
    7b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb9
    51422f
    """
    issuer_public_key_hex = """
    04f47eb42a771052580c086efdaaa3084aa3ff7a67ce23393a0373c63487df1a637d1fb34b2d2e7d5c8f92097a
    0619b5c5cc6c5850af74c019ebbec4273358aa94
    """
    issuer_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042086b9e3843d949890fd
    50e49c8542db575bac41d344f17588ddafe4535521ce55a14403420004f47eb42a771052580c086efdaaa3084a
    a3ff7a67ce23393a0373c63487df1a637d1fb34b2d2e7d5c8f92097a0619b5c5cc6c5850af74c019ebbec42733
    58aa94
    """
    input_x509_cert_hex = """
    308201513081f9a003020102020101300a06082a8648ce3d0403023011310f300d06035504030c066973737565
    72301e170d3230303130313030303030305a170d3235303530353030303030305a30123110300e06035504030c
    077375626a6563743059301306072a8648ce3d020106082a8648ce3d03010703420004842242f6182ba1c1138d
    32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243a
    c8544a665cb951422fa341303f301f0603551d230418301680147faeab3831311eac3c8bdc7d49cd0f8b3f1a9c
    2f300c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06082a8648ce3d0403020347
    00304402205a15bb0cd0718e077815fe8c71ddb05378c89fbf5ae2f976f2b506fcc224fa0402201aae5e32782d
    d979e71c8e1e6ba31054b121ac77933a4a7b3cf10e97cb64b9fe
    """
    compressed_cert_hex = """
    3081a30402000030819c830d3235303530353030303030305a85420004842242f6182ba1c1138d32b77fb9f7f3
    7b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb9
    51422f864700304402205a15bb0cd0718e077815fe8c71ddb05378c89fbf5ae2f976f2b506fcc224fa0402201a
    ae5e32782dd979e71c8e1e6ba31054b121ac77933a4a7b3cf10e97cb64b9fe
    """

    reader_private_key = _private_key(reader_private_key_hex)
    issuer_private_key = _private_key(issuer_private_key_hex)
    compressed_cert = _hex_bytes(compressed_cert_hex)
    input_x509_cert = _hex_bytes(input_x509_cert_hex)
    issuer_public_key = _public_key(issuer_public_key_hex)
    subject_public_key = _public_key(reader_public_key_hex)

    # Compression must reproduce the exact profile0000 vector.
    assert Profile0000Certificate.from_x509(input_x509_cert).to_bytes() == compressed_cert
    assert (
        Profile0000Certificate.from_x509(x509.load_der_x509_certificate(input_x509_cert)).to_bytes() == compressed_cert
    )

    # Vector sanity: private key blobs must map to the expected public keys.
    assert reader_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(reader_public_key_hex)
    assert issuer_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(issuer_public_key_hex)

    # Profile parsing expectations from Demo 3.
    profile = Profile0000Certificate.from_bytes(compressed_cert)
    assert profile.serial == Profile0000Certificate.DEFAULT_SERIAL
    assert profile.issuer == Profile0000Certificate.DEFAULT_ISSUER
    assert profile.not_before == Profile0000Certificate.DEFAULT_NOT_BEFORE
    assert profile.not_after == b"250505000000Z"
    assert profile.subject == Profile0000Certificate.DEFAULT_SUBJECT

    # Decompression must reproduce the exact DER X509 vector.
    decompressed_der = Profile0000Certificate.from_bytes(compressed_cert).to_x509_der_bytes(issuer_public_key)
    assert decompressed_der == _hex_bytes(input_x509_cert_hex)

    # Verification passes for the expected issuer/subject key pair.
    parsed_profile = Profile0000Certificate.from_bytes(compressed_cert)
    parsed_profile.verify(issuer_public_key=issuer_public_key)
    assert parsed_profile.subject_public_key.public_numbers() == subject_public_key.public_numbers()

    # Subject key comparison is caller-managed.
    wrong_subject_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    assert parsed_profile.subject_public_key.public_numbers() != wrong_subject_key.public_numbers()


def test_demo4_certificate_vector_end_to_end():
    """Aliro Specification v1.0, section 14.1, Demo 4."""
    reader_public_key_hex = """
    04842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc340
    1c3a4f4e5a59251d45243ac8544a665cb951422f
    """
    reader_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201a39e361b0db1915c2
    510bd92f3dbeb319ed68b16a0294347629d2e4becdb599a14403420004842242f6182ba1c1138d32b77fb9f7f3
    7b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb9
    51422f
    """
    issuer_public_key_hex = """
    04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f372814a312c3cb82a5a9
    7bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd
    """
    issuer_private_key_hex = """
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104204b45df37a327a31303
    113f9965d14de94f025f881515e13034a3d8a9ac47e43ea14403420004793e3a8f20428d54e7318046d75d05a8
    737eb6e074e5146a207bff62dae90e24039f372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da
    7de7bd
    """
    input_x509_cert_hex = """
    308201993082013fa00302010202145555555555555555555555555555555555555555300a06082a8648ce3d04
    0302302b3129302706035504030c20637573746f6d20697373756572206e616d652e2e2e2e2e2e2e2e2e2e2e2e
    2e2e301e170d3230303130323030303030305a170d3235303530353030303030305a302b312930270603550403
    0c20637573746f6d207375626a656374206e616d652e2e2e2e2e2e2e2e2e2e2e2e2e3059301306072a8648ce3d
    020106082a8648ce3d03010703420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188b
    eadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422fa341303f301f0603551d
    230418301680142318e55671f08eae212142a817720fb817ee93bf300c0603551d130101ff04023000300e0603
    551d0f0101ff040403020780300a06082a8648ce3d040302034800304502206a552690283860fc94916ebbc92f
    3510abb62a7a4729be57c2bde9fadf417e71022100c2385d82cfb33a357d5402f3e20fb271d0145b72b38a4a2b
    4a6ebc6e14dd83b5
    """
    compressed_cert_hex = """
    3082010e0402000030820106801455555555555555555555555555555555555555558120637573746f6d206973
    73756572206e616d652e2e2e2e2e2e2e2e2e2e2e2e2e2e820d3230303130323030303030305a830d3235303530
    353030303030305a8420637573746f6d207375626a656374206e616d652e2e2e2e2e2e2e2e2e2e2e2e2e854200
    04842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc340
    1c3a4f4e5a59251d45243ac8544a665cb951422f864800304502206a552690283860fc94916ebbc92f3510abb6
    2a7a4729be57c2bde9fadf417e71022100c2385d82cfb33a357d5402f3e20fb271d0145b72b38a4a2b4a6ebc6e
    14dd83b5
    """

    reader_private_key = _private_key(reader_private_key_hex)
    issuer_private_key = _private_key(issuer_private_key_hex)
    compressed_cert = _hex_bytes(compressed_cert_hex)
    input_x509_cert = _hex_bytes(input_x509_cert_hex)
    issuer_public_key = _public_key(issuer_public_key_hex)
    subject_public_key = _public_key(reader_public_key_hex)

    # Compression must reproduce the exact profile0000 vector.
    assert Profile0000Certificate.from_x509(input_x509_cert).to_bytes() == compressed_cert
    assert (
        Profile0000Certificate.from_x509(x509.load_der_x509_certificate(input_x509_cert)).to_bytes() == compressed_cert
    )

    # Vector sanity: private key blobs must map to the expected public keys.
    assert reader_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(reader_public_key_hex)
    assert issuer_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ) == _hex_bytes(issuer_public_key_hex)

    # Profile parsing expectations from Demo 4 (all tunable fields present).
    profile = Profile0000Certificate.from_bytes(compressed_cert)
    assert profile.serial == _hex_bytes("5555555555555555555555555555555555555555")
    assert profile.issuer == b"custom issuer name.............."
    assert profile.not_before == b"200102000000Z"
    assert profile.not_after == b"250505000000Z"
    assert profile.subject == b"custom subject name............."

    # Decompression must reproduce the exact DER X509 vector.
    decompressed_der = Profile0000Certificate.from_bytes(compressed_cert).to_x509_der_bytes(issuer_public_key)
    assert decompressed_der == _hex_bytes(input_x509_cert_hex)

    # Verification passes for the expected issuer/subject key pair.
    parsed_profile = Profile0000Certificate.from_bytes(compressed_cert)
    parsed_profile.verify(issuer_public_key=issuer_public_key)
    assert parsed_profile.subject_public_key.public_numbers() == subject_public_key.public_numbers()

    # Subject key comparison is caller-managed.
    wrong_subject_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    assert parsed_profile.subject_public_key.public_numbers() != wrong_subject_key.public_numbers()
