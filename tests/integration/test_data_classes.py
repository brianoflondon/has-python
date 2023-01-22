import json
from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from has_python.has_lib2 import (
    CmdType,
    HASApp,
    HASMessage,
    HASWait,
    build_auth_req_challenge,
)


@pytest.mark.asyncio
async def test_build_auth_req_challenge():
    # Tests ChallengeHAS
    # Tests AuthDataHAS
    # Tests AuthReqHAS
    auth_req = await build_auth_req_challenge(
        acc_name="v4vapp.dev",
        key_type="posting",
        challenge_message="pytest testing",
        token=uuid4(),
        use_pksa_key=True,
    )
    assert auth_req


def test_has_app():
    has_app = HASApp()
    assert has_app


def test_has_message():
    for item in [e.value for e in CmdType]:
        hm = HASMessage.parse_raw(json.dumps({"cmd": item}))
        assert hm.cmd.value == item
    try:
        hm = HASMessage.parse_raw(json.dumps({"cmd": "bad"}))
    except ValidationError as ex:
        assert ex.args[0][0]._loc == "cmd"


def test_has_wait():
    hw = HASWait(cmd=CmdType.auth_wait, expire=datetime.now())
    assert hw
    hw = HASWait(cmd=CmdType.sign_wait, expire=datetime.now())
    assert hw
    try:
        hw = HASWait(cmd=CmdType.sign_ack, expire=datetime.now())
    except ValidationError:
        assert True
