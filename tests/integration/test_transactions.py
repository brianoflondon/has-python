import json
import logging

import pytest
from websockets import connect as ws_connect

from has_python.has_lib import HASAuthentication, Operation

"""
Testing Note: this relies on running Arcange's PKSA server
"""


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
    # format="{asctime} {levelname} {module} {lineno:>5} : {message}",
    # datefmt="%Y-%m-%dT%H:%M:%S,uuu",
)


@pytest.mark.asyncio
async def test_transaction_request():
    test_account = "v4vapp.dev"
    has = HASAuthentication(hive_acc=test_account)
    async with ws_connect(has.uri) as websocket:
        has.websocket = websocket
        time_to_wait = await has.connect_with_challenge()
        img = await has.get_qrcode()
        if not test_account == "v4vapp.dev":
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
        pass
