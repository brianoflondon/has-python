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

from has_python.hive_validation import (
    Operation,
    SignedAnswer,
    SignedAnswerData,
    validate_hivekeychain_ans,
)
from has_python.jscrypt_encode_for_python import js_decrypt, js_encrypt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
)
logging.getLogger("graphenerpc").setLevel(logging.ERROR)

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


class HASMessage(BaseModel):
    cmd: CmdType


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
    account: str
    uuid: UUID
    key: UUID  # This is the auth-key used when creating "The APP must then encrypt the auth_data object using an encryption key (auth_key)"
    host: str = HAS_SERVER

    @property
    def qr_text(self) -> str:
        """Text for a QR Code"""
        return f"has://auth_req/{self.auth_payload_base64}"

    @property
    def auth_payload_base64(self) -> str:
        return base64.b64encode((self.json()).encode("utf-8")).decode("utf-8")

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
        auth_wait = GLOBAL_LISTS.find_wait(self.uuid)
        GLOBAL_LISTS.del_wait(auth_wait)
        # Hmmm not sure about this assumption
        auth_object = GLOBAL_LISTS.find_auth(auth_wait.account)
        GLOBAL_LISTS.del_auth(auth_object)

        if auth_object.acc_name != auth_wait.account:
            raise
        data_bytes = self.data.encode("utf-8")
        data_string = js_decrypt(
            data_bytes, str_bytes(auth_object.auth_data.auth_key)
        ).decode("utf-8")
        auth_ack_data = AuthAckDataHAS.parse_raw(data_string)
        logging.info(auth_ack_data)
        logging.info(f"Token: {auth_ack_data.token}")
        signed_answer = SignedAnswer(
            result=auth_ack_data.challenge.challenge,
            request_id=1,
            publicKey=auth_ack_data.challenge.pubkey,
            data=SignedAnswerData(
                _type="HAS",
                username=auth_object.auth_req.account,
                message=auth_object.auth_data.challenge.challenge,
                method=auth_object.auth_data.challenge.key_type,
                key=auth_object.auth_data.challenge.key_type,
            ),
        )
        verification = validate_hivekeychain_ans(signed_answer)
        if verification.success:
            valid_token = ValidToken(
                acc_name=verification.acc_name,
                token=auth_ack_data.token,
                exipre=auth_ack_data.expire,
                auth_key=auth_object.auth_data.auth_key,
            )
            GLOBAL_LISTS.token_list.append(valid_token)


class AuthAckDataHAS(BaseModel):
    token: str
    expire: datetime
    challenge: ChallengeHAS = None


class HASCommon(HASMessage):
    """Common data across all sending classes"""

    hive_acc: str
    key_type: KeyType = KeyType.posting


class ConnectedHAS(HASMessage):
    server: str
    socketid: str
    timeout: int
    ping_rate: int
    version: str
    protocol: float
    received: datetime = datetime.now(tz=timezone.utc)


class SignReqHAS(HASMessage):
    account: str
    token: str
    data: str
    auth_key: UUID


class SignWaitHAS(HASMessage):
    uuid: UUID
    expire: datetime


class AuthObjectHAS(BaseModel):
    acc_name: str
    auth_data: AuthDataHAS
    auth_req: AuthReqHAS
    timestamp: datetime = datetime.now(tz=timezone.utc)


class ValidToken(BaseModel):
    acc_name: str
    token: str
    exipre: datetime
    auth_key: UUID


async def build_auth_req_challenge(
    acc_name: str,
    key_type: KeyType,
    challenge_message: str,
    token: str = None,
    use_pksa_key: bool = False,
) -> AuthObjectHAS:
    """
    Builds an `auth_req` with a challenge
    """
    challenge = ChallengeHAS(
        key_type=key_type,
        challenge_data={
            "timestamp": datetime.now(tz=timezone.utc).timestamp(),
            "app_session_id": uuid4(),
            "message": challenge_message,
        },
    )
    auth_data = AuthDataHAS(
        token=token,
        challenge=challenge,
        auth_key=uuid4(),  # UUID("37c3b377-cf91-44a3-9e21-6af5b8773bf3"), # hard coded
    )
    auth_req = AuthReqHAS(
        cmd=CmdType.auth_req,
        account=acc_name,
        data=auth_data.encrypted_b64,
    )
    if use_pksa_key:
        auth_req.auth_key = js_encrypt(
            str_bytes(auth_data.auth_key), str_bytes(HAS_AUTH_REQ_SECRET)
        )

    return AuthObjectHAS(acc_name=acc_name, auth_data=auth_data, auth_req=auth_req)


class SignDataHAS(BaseModel):
    key_type: KeyType
    ops: list
    broadcast: bool

    @property
    def bytes(self):
        """
        Return object as json string in bytes: does not include the `auth_key_uuid`
        Also needs to carefully encode ops only once.
        """
        # self_dict = self.dict(exclude={"auth_key_uuid"})
        json_data = json.dumps(self.dict())
        encoded_bytes = json_data.encode("utf-8")
        return encoded_bytes

    def encrypted_b64(self, auth_key) -> bytes:
        return js_encrypt(self.bytes, str_bytes(auth_key))


async def socket_listen(has_socket):
    """
    Listen to a socket and act on what is received.
    """
    try:
        while True:
            msg = await has_socket.recv()
            cmd = HASMessage.parse_raw(msg)
            logging.info(f"<------ Recivied: {cmd}")
            logging.info(msg)
            match cmd.cmd:
                case CmdType.connected:
                    processed = ConnectedHAS.parse_raw(msg)
                    processed.socketid
                    logging.info(processed)
                case CmdType.auth_wait:
                    auth_wait = AuthWaitHAS.parse_raw(msg)
                    # Display QR Code
                    auth_payload = AuthPayloadHAS(
                        account=auth_wait.account,
                        uuid=auth_wait.uuid,
                        key=GLOBAL_LISTS.find_auth(
                            auth_wait.account
                        ).auth_data.auth_key,
                    )
                    extra_text = str(
                        f"Check: {auth_wait.uuid} - " f"{auth_wait.account}"
                    )
                    img = auth_payload.qr_image(extra_text=extra_text)
                    if not auth_wait.account == "v4vapp.dev":
                        img.show()
                    GLOBAL_LISTS.wait_list.append(auth_wait)
                    logging.info(auth_wait)

                case CmdType.sign_wait:
                    sign_wait = SignWaitHAS.parse_raw(msg)
                    logging.info(
                        f"****** Alert User to authorise transaction {sign_wait.uuid}"
                    )

                case CmdType.auth_ack:
                    auth_ack = AuthAckHAS.parse_raw(msg)
                    logging.debug(auth_ack)
                    auth_ack.validate()
                case CmdType.sign_error:
                    logging.info("Sign Error")

            if has_socket.closed:
                break

    except (ValidationError, KeyError) as ex:
        logging.error(ex)
        pass
    except websockets.exceptions.ConnectionClosed as ex:
        logging.warning(ex)
    except Exception as ex:
        logging.exception(ex)


async def execute_tasks(has_socket):
    """Watches the task Queue"""
    while True:
        msg: HASMessage = await TASK_QUEUE.get()
        try:
            await has_socket.send(msg.json(exclude_none=True))
        except Exception as ex:
            logging.exception(ex)
            logging.info("Putting the msg back int the Queue")
            await TASK_QUEUE.put(msg)

        logging.info(f"------> Sent:   {msg.cmd}")


async def main_loop():
    async with websockets.connect(HAS_SERVER) as has_socket:
        tasks = [
            socket_listen(has_socket),
            execute_tasks(has_socket),
            test_send_auth_req(),
            test_send_transaction(),
            # test_send_transaction(),
            # test_send_transaction(),
        ]
        answers = await asyncio.gather(*tasks)


async def test_send_auth_req():
    for acc in ["v4vapp.dev"]:  # ,'brianoflondon']:
        # await asyncio.sleep(3)
        use_pksa_key = False
        if acc == "v4vapp.dev":
            use_pksa_key = True
        auth_object = await build_auth_req_challenge(
            acc_name=acc,
            key_type=KeyType.posting,
            challenge_message=f"{acc} Welcome to the Party!",
            use_pksa_key=use_pksa_key,
        )
        GLOBAL_LISTS.auth_list.append(auth_object)
        await TASK_QUEUE.put(auth_object.auth_req)


async def test_send_transaction():
    test_account = "v4vapp.dev"
    # find valid Token
    while True:
        await asyncio.sleep(5)
        valid_token = GLOBAL_LISTS.find_token(test_account)
        if valid_token:
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
            sign_data = SignDataHAS(
                key_type=KeyType.posting,
                ops=[op.to_dict()],
                broadcast=True,
            )
            sign_req = SignReqHAS(
                cmd=CmdType.sign_req,
                account=valid_token.acc_name,
                token=valid_token.token,
                auth_key=valid_token.auth_key,
                data=sign_data.encrypted_b64(valid_token.auth_key),
            )
            logging.info(sign_req)
            GLOBAL_LISTS.auth_list.append(sign_req)
            await TASK_QUEUE.put(sign_req)
            break


class AllLists(BaseModel):
    auth_list: List[AuthObjectHAS] = []
    wait_list: List[AuthWaitHAS] = []
    token_list: List[ValidToken] = []

    def find_auth(self, acc_name: str) -> AuthObjectHAS:
        found = [item for item in self.auth_list if item.acc_name == acc_name]
        if len(found) == 1:
            return found[0]
        raise Exception("Need to deal with multiple concurrent auth requests")

    def del_auth(self, found: AuthObjectHAS):
        """Finda auth item and deletes it"""
        index = self.auth_list.index(found)
        del self.auth_list[index]

    def find_wait(self, uuid: UUID) -> AuthWaitHAS:
        found = [item for item in self.wait_list if item.uuid == uuid]
        if len(found) == 1:
            return found[0]
        raise Exception("Need to deal with multiple concurrent auth requests")

    def del_wait(self, found: AuthWaitHAS):
        """Finds a waiting item and deletes it"""
        index = self.wait_list.index(found)
        del self.wait_list[index]

    def find_token(self, acc_name: str) -> ValidToken | None:
        found = [item for item in self.token_list if item.acc_name == acc_name]
        if not found:
            return None
        if len(found) == 1:
            return found[0]
        raise Exception("Need to deal with multiple concurrent auth requests")


GLOBAL_LISTS: AllLists = AllLists()
TASK_QUEUE = asyncio.Queue()
# AUTH_LIST: AuthList = AuthList()
# ACK_WAIT_LIST: List[AuthWaitHAS] = []
# VALID_TOKEN_LIST: List[ValidToken] = []

if __name__ == "__main__":
    asyncio.run(main_loop())
