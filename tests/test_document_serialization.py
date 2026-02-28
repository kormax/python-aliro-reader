import json
from datetime import datetime, timezone

import cbor2

from aliro.document import (
    DeviceRequest,
    DeviceResponse,
    Document,
    DocumentRequest,
    IssuerAuthCoseSign1,
    IssuerSignedItem,
    SessionData,
)


def test_request_and_session_dict_roundtrip():
    request = DeviceRequest(
        version="1.0",
        document_requests=[
            DocumentRequest(doc_type="aliro-a", scopes={"matter1": True}),
            DocumentRequest(doc_type="aliro-r", scopes={"matter1": False}),
        ],
    )
    request_dict = request.to_dict()
    request_json = json.dumps(request_dict)
    restored_request = DeviceRequest.from_dict(json.loads(request_json))
    assert restored_request.to_dict() == request_dict

    session_data = SessionData(data=b"\xaa\xbb\xcc")
    session_dict = session_data.to_dict()
    session_json = json.dumps(session_dict)
    restored_session = SessionData.from_dict(json.loads(session_json))
    assert restored_session.to_dict() == session_dict
    assert restored_session.data == b"\xaa\xbb\xcc"


def test_access_document_model_dict_roundtrip():
    now = datetime(2026, 2, 26, 15, 54, 26, tzinfo=timezone.utc)

    issuer_signed_item = IssuerSignedItem(
        digest_id=0,
        random=b"\xaa" * 8,
        element_identifier="matter1",
        element_value={
            0: 1,
            1: b"\x01\x02\x03",
            2: [{"type": "allow"}],
            3: {"weekly": [1, 2]},
            4: [1, 2, 3],
            5: {100: [b"\xaa"]},
            6: {200: [b"\xbb"]},
        },
    )

    issuer_auth = IssuerAuthCoseSign1(
        protected_headers_encoded=cbor2.dumps({1: -7}),
        unprotected_headers={4: b"\x8d\x8c\x64\x00\xfc\x91\x87\xef"},
        payload=cbor2.dumps(
            cbor2.CBORTag(
                24,
                cbor2.dumps(
                    {
                        "1": "1.0",
                        "2": "SHA-256",
                        "3": {"aliro-a": {0: b"\x33" * 32}},
                        "4": {"1": {1: 2, 3: -7, -1: 1, -2: b"\x11" * 32, -3: b"\x22" * 32}},
                        "5": "aliro-a",
                        "6": {"1": now, "2": now, "3": datetime(4001, 1, 1, 0, 0, tzinfo=timezone.utc)},
                        "7": True,
                    }
                ),
            )
        ),
        signature=b"\x44" * 64,
    )

    access_document = Document(
        doc_type="aliro-a",
        issuer_signed_items={"aliro-a": [issuer_signed_item]},
        issuer_auth=issuer_auth,
    )

    response = DeviceResponse(
        version="1.0",
        status=0,
        documents=[access_document],
    )

    serialized = response.to_dict()
    serialized_json = json.dumps(serialized)
    restored = DeviceResponse.from_dict(json.loads(serialized_json))

    assert restored.to_dict() == serialized
    assert len(restored.access_documents) == 1
    restored_access_document = restored.access_documents[0]
    assert isinstance(restored_access_document, Document)
    assert restored_access_document.issuer_auth is not None
    assert restored_access_document.issuer_auth.issuer_id == b"\x8d\x8c\x64\x00\xfc\x91\x87\xef"
    restored_access_data = restored_access_document.issuer_signed_items["aliro-a"][0].access_data
    assert restored_access_data is not None
    assert restored_access_data.id == b"\x01\x02\x03"
    assert restored_access_document.issuer_auth.mobile_security_object.device_key.endpoint_public_key == bytes(
        [0x04]
    ) + (b"\x11" * 32) + (b"\x22" * 32)
