import json
from uuid import uuid4

import pytest
from websockets import connect as ws_connect

from has_python.has_lib import HASAuthentication, KeyType, Operation, SignDataHAS

"""
Testing Note: this relies on running Arcange's PKSA server
"""


@pytest.mark.asyncio
async def test_transaction_request():
    test_account = "v4vapp.dev"
    has = HASAuthentication(hive_acc=test_account)
    async with ws_connect(has.uri) as websocket:
        has.websocket = websocket
        time_to_wait = await has.connect_with_challenge()
        img = await has.get_qrcode()
        img.show()
        await has.waiting_for_challenge_response(time_to_wait)
        assert has.token
        assert has.expire

        payload = {"HAS": "testing"}
        payload_json = json.dumps(payload, separators=(",", ":"), default=str)
        op = Operation(
            "custom_json",
            {
                "required_auths": [],
                "required_posting_auths": [test_account],
                "id": "v4vapp_has_testing",
                "json": payload_json,
            },
        )

        time_to_wait = await has.transaction_request(ops=op.__repr__())
        await has.waiting_for_challenge_response(time_to_wait=time_to_wait)


def test_json_builder():
    test_account = "v4vapp.dev"
    payload = {"HAS": "testing"}
    payload_json = json.dumps(payload, separators=(",", ":"), default=str)
    op = Operation(
        "custom_json",
        {
            "required_auths": [],
            "required_posting_auths": [test_account],
            "id": "v4vapp_has_testing",
            "json": payload_json,
        },
    )

    test_sd = SignDataHAS(
        key_type=KeyType.posting, ops=op.op_value, broadcast=True, auth_key_uuid=uuid4()
    )

    test_sd_bytes = test_sd.bytes
    test_sd_encrypted = test_sd.encrypted_b64
    pass
