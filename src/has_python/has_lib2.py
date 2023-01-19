import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Type
from uuid import UUID, uuid4

import requests
import websockets
from dotenv import load_dotenv
from PIL import ImageDraw, ImageFont
from pydantic import BaseModel, ValidationError
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_H
from qrcode.image.styledpil import StyledPilImage

from has_python.jscrypt_encode_for_python import js_decrypt, js_encrypt

logging.getLogger("graphenerpc").setLevel(logging.WARNING)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
)

load_dotenv()
HAS_SERVER = "wss://hive-auth.arcange.eu"
HAS_APP_DATA = {
    "name": "has-python",
    "description": "Demo - HiveAuthService from Python",
    "icon": "https://api.v4v.app/v1/hive/avatar/v4vapp",
}
HAS_AUTH_REQ_SECRET = UUID(os.getenv("HAS_AUTH_REQ_SECRET"))
HAS_PROTOCOL_MIN = 0.8


def str_bytes(uuid: UUID) -> bytes:
    return str(uuid).encode("utf-8")


class CmdType(str, Enum):
    connected = "connected"
    auth_req = "auth_req"
    auth_wait = "auth_wait"
    auth_ack = "auth_ack"
    auth_nack = "auth_nack"
    auth_err = "auth_err"
    sign_req = "sign_req"
    sign_wait = "sign_wait"
    sign_ack = "sign_ack"
    sign_nack = "sign_nack"
    sign_error = "sign_error"


class KeyType(str, Enum):
    posting = "posting"
    active = "active"
    memo = "memo"


class HASMessage(BaseModel):
    cmd: CmdType


class HASCommon(HASMessage):
    """Common data across all sending classes"""

    hive_acc: str
    key_type: KeyType = KeyType.posting


class ChallengeHAS(BaseModel):
    key_type: KeyType = KeyType.posting
    challenge: str
    pubkey: str | None

    def __init__(__pydantic_self__, **data: Any) -> None:
        if data.get("challenge_data"):
            if "timestamp" not in data["challenge_data"].keys():
                data["challenge_data"]["timestamp"] = datetime.utcnow().timestamp()
            data["challenge"] = json.dumps(data.get("challenge_data"), default=str)
        if not data.get("challenge"):
            raise KeyError("challenge is required")
        if "key_type" in data.keys() and data.get("key_type") is None:
            del data["key_type"]
        super().__init__(**data)


class HASApp(BaseModel):
    name: str = HAS_APP_DATA["name"]
    description: str = HAS_APP_DATA["description"]
    icon: str = HAS_APP_DATA["icon"]


class AuthDataHAS(BaseModel):
    app: HASApp = HASApp()
    token: str | None
    challenge: ChallengeHAS | None
    auth_key: UUID

    @property
    def bytes(self):
        """Return object as json string in bytes: does not include the `auth_key_uuid`"""
        return json.dumps(self.dict(exclude={"auth_key"})).encode("utf-8")

    @property
    def encrypted_b64(self) -> bytes:
        return js_encrypt(self.bytes, str_bytes(self.auth_key))


class AuthReqHAS(HASMessage):
    account: str
    data: str
    token: str | None
    auth_key: str | None


class AuthWaitHAS(HASMessage):
    uuid: UUID
    expire: datetime
    account: str


class AuthPayloadHAS(BaseModel):
    host: str = HAS_SERVER
    account: str
    uuid: UUID
    key: UUID

    @property
    def qr_text(self) -> str:
        """Text for a QR Code"""
        return f"has://auth_req/{self.auth_payload_base64}"

    @property
    def auth_payload_base64(self) -> str:
        return base64.b64encode((self.json()).encode()).decode("utf-8")

    def qr_image(self, extra_text: str) -> StyledPilImage:
        """QR Code Image"""
        qr = QRCode(
            version=1,
            error_correction=ERROR_CORRECT_H,
            box_size=10,
            border=6,
        )
        qr.add_data(self.qr_text)
        res = requests.get(f"https://api.v4v.app/v1/hive/avatar/{self.account}")
        if res.status_code == 200:
            # avatar_im = Image.open(BytesIO(res.content))
            with open(f"/tmp/{self.account}.png", "wb") as file:
                file.write(res.content)

            img = qr.make_image(
                image_factory=StyledPilImage,
                embeded_image_path=f"/tmp/{self.account}.png",
            )
        else:
            img = qr.make_image()
        draw = ImageDraw.Draw(img)
        font = ImageFont.truetype("src/has_python/arial_narrow_bold_italic.ttf", 24)
        draw.text((100, 10), extra_text, font=font, fill="black")
        return img


class AuthAckHAS(HASMessage):
    uuid: UUID
    data: str

    def validate(self):
        """Validates an authentication and challenge"""
        # Find the matching index of ACK_WAIT_LIST
        index = [
            i
            for i, auth_wait in enumerate(ACK_WAIT_LIST)
            if auth_wait.uuid == self.uuid
        ][0]
        auth_wait = ACK_WAIT_LIST[index]
        # Hmmm not sure about this assumption
        auth_object = AUTH_LIST[index]
        del ACK_WAIT_LIST[index]
        del AUTH_LIST[index]
        if auth_object.acc_name != auth_wait.account:
            raise
        data_bytes = self.data.encode("utf-8")
        data_string = js_decrypt(
            data_bytes, str_bytes(auth_object.auth_data.auth_key)
        ).decode("utf-8")
        auth_ack_data = AuthAckDataHAS.parse_raw(data_string)
        logging.debug(f"AUTH_LIST items: {len(AUTH_LIST)}")
        logging.debug(f"ACK_WAIT_LIST items: {len(ACK_WAIT_LIST)}")
        logging.debug(auth_ack_data)
        logging.debug(f"Token: {auth_ack_data.token}")


class AuthAckDataHAS(BaseModel):
    token: str
    expire: datetime
    challenge: ChallengeHAS = None


class ConnectedHAS(HASMessage):
    cmd: str
    server: str
    socketid: str
    timeout: int
    ping_rate: int
    version: str
    protocol: float
    received: datetime = datetime.utcnow()


class AuthObjectHAS(BaseModel):
    acc_name: str
    auth_data: AuthDataHAS
    auth_req: AuthReqHAS


async def get_auth_req_challenge(
    acc_name: str, key_type: KeyType, challenge_message: str, token: str = None
) -> AuthObjectHAS:
    """
    Sends an `auth_req` with a challenge
    """
    challenge = ChallengeHAS(
        key_type=key_type,
        challenge_data={
            "timestamp": datetime.now(tz=timezone.utc).timestamp(),
            "app_session_id": uuid4(),
            "message": challenge_message,
        },
    )
    auth_data = AuthDataHAS(token=token, challenge=challenge, auth_key=uuid4())
    auth_req = AuthReqHAS(
        cmd=CmdType.auth_req,
        account=acc_name,
        data=auth_data.encrypted_b64,
        auth_key=js_encrypt(
            str_bytes(auth_data.auth_key), str_bytes(HAS_AUTH_REQ_SECRET)
        ),
    )

    return AuthObjectHAS(acc_name=acc_name, auth_data=auth_data, auth_req=auth_req)


async def socket_listen(has_socket):
    """
    Listen to a socket and act on what is received.
    """
    try:
        while True:
            msg = await has_socket.recv()
            cmd = HASMessage.parse_raw(msg)
            logging.debug(f"-------> Recivied: {cmd}")
            logging.debug(msg)
            match cmd.cmd:
                case CmdType.connected:
                    processed = ConnectedHAS.parse_raw(msg)
                    processed.socketid
                    logging.debug(processed)
                case CmdType.auth_wait:
                    auth_wait = AuthWaitHAS.parse_raw(msg)
                    # Display QR Code
                    # This is where KEY is definied
                    auth_payload = AuthPayloadHAS(
                        account=auth_wait.account,
                        uuid=auth_wait.uuid,
                        key=uuid4(),
                    )
                    extra_text = str(
                        f"Check: {auth_wait.uuid} - " f"{auth_wait.account}"
                    )
                    img = auth_payload.qr_image(extra_text=extra_text)
                    img.show()
                    ACK_WAIT_LIST.append(auth_wait)
                    logging.debug(auth_wait)

                case CmdType.auth_ack:
                    auth_ack = AuthAckHAS.parse_raw(msg)
                    logging.debug(auth_ack)
                    auth_ack.validate()
            if has_socket.closed:
                break

    except (ValidationError, KeyError):
        pass
    except websockets.exceptions.ConnectionClosed as ex:
        logging.warning(ex)
    except Exception as ex:
        logging.exception(ex)


async def execute_tasks(has_socket):
    """Watches the task Queue"""
    while True:
        msg: HASMessage = await TASK_QUEUE.get()
        await has_socket.send(msg.json(exclude_none=True))
        logging.debug(f"<------ Sent:   {msg.cmd}")


async def main_loop():
    async with websockets.connect(HAS_SERVER) as has_socket:
        tasks = [
            socket_listen(has_socket),
            execute_tasks(has_socket),
            test_send(),
        ]
        answers = await asyncio.gather(*tasks)


async def test_send():
    for i in range(1):
        # await asyncio.sleep(3)
        auth_object = await get_auth_req_challenge(
            acc_name="v4vapp.dev",
            key_type=KeyType.posting,
            challenge_message=f"{i} Welcome to the party",
        )
        AUTH_LIST.append(auth_object)
        await TASK_QUEUE.put(auth_object.auth_req)


TASK_QUEUE = asyncio.Queue()
AUTH_LIST: List[AuthObjectHAS] = []
ACK_WAIT_LIST: List[AuthWaitHAS] = []


if __name__ == "__main__":
    asyncio.run(main_loop())
