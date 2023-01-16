import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

import requests
from dotenv import load_dotenv
from PIL import ImageDraw, ImageFont
from pydantic import AnyUrl, BaseModel
from pydantic.error_wrappers import ValidationError
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_H
from qrcode.image.styledpil import StyledPilImage
# from websockets import connect as ws_connect
from websockets.legacy.client import WebSocketClientProtocol

from has_python.hive_validation import (
    SignedAnswer,
    SignedAnswerData,
    SignedAnswerVerification,
    validate_hivekeychain_ans,
)
from has_python.jscrypt_encode_for_python import js_decrypt, js_encrypt

# from Crypto.Cipher import AES


# https://stackoverflow.com/questions/35472396/how-does-cryptojs-get-an-iv-when-none-is-specified
# https://gist.github.com/tly1980/b6c2cc10bb35cb4446fb6ccf5ee5efbc
# https://devpress.csdn.net/python/630460127e6682346619ab98.html


HAS_AUTHENTICATION_TIME_LIMIT = 600

load_dotenv()

HAS_SERVER = "wss://hive-auth.arcange.eu"

HIVE_ACCOUNT = "v4vapp.dev"
HAS_APP_DATA = {
    "name": "has-python",
    "description": "Demo - HiveAuthService from Python",
    "icon": "https://api.v4v.app/v1/hive/avatar/v4vapp",
}
HAS_AUTH_REQ_SECRET = UUID(os.getenv("HAS_AUTH_REQ_SECRET"))


class HASApp(BaseModel):
    name: str = HAS_APP_DATA["name"]
    description: str = HAS_APP_DATA["description"]
    icon: str = HAS_APP_DATA["icon"]


class KeyType(str, Enum):
    posting = "posting"
    active = "active"
    memo = "memo"


class ConnectedHAS(BaseModel):
    cmd: str
    server: str
    socketid: str
    timeout: int
    ping_rate: int
    version: str
    protocol: float
    received: datetime = datetime.utcnow()


class CmdType(str, Enum):
    auth_wait = "auth_wait"
    auth_ack = "auth_ack"
    auth_nack = "auth_nack"
    auth_err = "auth_err"


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
        super().__init__(**data)


class ChallengeAckHAS(BaseModel):
    cmd: CmdType = CmdType.auth_ack
    uuid: UUID
    data: str


class ChallengeAckData(BaseModel):
    pubkey: str
    challenge: str


class HASAuthenticationRefused(Exception):
    pass


class HASAuthenticationTimeout(Exception):
    pass


class AuthDataHAS(BaseModel):
    app: HASApp = HASApp()
    token: str | None
    challenge: ChallengeHAS | None

    @property
    def bytes(self):
        """Return object as json string in bytes"""
        return json.dumps(self.dict()).encode("utf-8")


class AuthReqHAS(BaseModel):
    cmd: str = "auth_req"
    account: str
    data: str
    token: str | None
    auth_key: str | None


class AuthPayloadHAS(BaseModel):
    host: str = HAS_SERVER
    account: str
    uuid: UUID
    key: UUID


def str_bytes(uuid: UUID) -> bytes:
    return str(uuid).encode("utf-8")


class AuthWaitHAS(BaseModel):
    cmd: CmdType
    uuid: UUID
    expire: datetime
    account: str


class AuthAckNakErrHAS(BaseModel):
    cmd: CmdType | None
    uuid: UUID | None
    data: str | None


class AuthAckData(BaseModel):
    token: str
    expire: datetime
    challenge: ChallengeHAS = None


class HASAuthentication(BaseModel):
    hive_acc: str = HIVE_ACCOUNT
    uri: AnyUrl = HAS_SERVER
    websocket: WebSocketClientProtocol | None
    challenge_message: str | None
    app_session_id: UUID = uuid4()
    auth_key_uuid: UUID = uuid4()
    connected_has: ConnectedHAS | None
    auth_wait: AuthWaitHAS | None
    auth_data: AuthDataHAS | None
    auth_req: AuthReqHAS | None
    auth_payload: AuthPayloadHAS | None
    auth_ack: AuthAckNakErrHAS | None
    signed_answer: SignedAnswer | None
    verification: SignedAnswerVerification = False
    token: str | None
    expire: datetime | None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.setup_challenge(**data)

    @property
    def auth_ack_data(self) -> AuthAckData | str:
        """
        On the fly decryption of a response from HAS
        If the response is a rejection `auth_nack` this
        will probably return as a string"""
        data_bytes = self.auth_ack.data.encode("utf-8")
        data_string = js_decrypt(data_bytes, str_bytes(self.auth_key_uuid)).decode(
            "utf-8"
        )
        try:
            return AuthAckData.parse_raw(data_string)
        except ValidationError:
            return data_string
        except Exception as ex:
            logging.exception(ex)
            return data_string

    @property
    def auth_key(self) -> bytes:
        return self.auth_key_uuid.bytes

    @property
    def b64_auth_data_encrypted(self):
        return js_encrypt(self.auth_data.bytes, str_bytes(self.auth_key_uuid))

    @property
    def b64_auth_payload_encrypted(self):
        return js_encrypt(str_bytes(self.auth_key_uuid), str_bytes(HAS_AUTH_REQ_SECRET))

    @property
    def qr_text(self) -> str:
        auth_payload_base64 = base64.b64encode(
            (self.auth_payload.json()).encode()
        ).decode("utf-8")
        return f"has://auth_req/{auth_payload_base64}"

    def setup_challenge(self, **data: Any):
        try:
            challenge = ChallengeHAS(
                challenge_data={
                    "timestamp": datetime.now(tz=timezone.utc).timestamp(),
                    "app_session_id": self.app_session_id,
                    "message": data.get("challenge_message"),
                }
            )
            self.auth_data = AuthDataHAS(challenge=challenge, token=self.token)
            self.auth_req = AuthReqHAS(
                account=self.hive_acc,
                data=self.b64_auth_data_encrypted,
                # Auth Key needed for using a PKSA Service without QR codes
                auth_key=self.b64_auth_payload_encrypted,
            )
        except KeyError as ex:
            logging.error(ex)
            raise

    def decrypt(self):
        """
        Decrypts a challenge response received back from HAS.

        Sets property `validated` to `True` and `time_to_validate` if
        challenge is returned successfully
        """
        if (
            self.auth_ack.cmd == CmdType.auth_ack
            and self.auth_key
            and self.auth_data
            and self.auth_payload
            and self.auth_ack.data
        ):
            self.signed_answer = SignedAnswer(
                success=True,
                error=None,
                result=self.auth_ack_data.challenge.challenge,
                data=SignedAnswerData(
                    answer_type="HAS",
                    username=self.auth_payload.account,
                    message=self.auth_data.challenge.challenge,
                    method=self.auth_data.challenge.key_type,
                    key=self.auth_data.challenge.key_type,
                ),
                request_id=1,
                publicKey=self.auth_ack_data.challenge.pubkey,
            )
            self.verification = validate_hivekeychain_ans(self.signed_answer)
        elif self.auth_ack.cmd == CmdType.auth_nack:
            if self.auth_payload.uuid == self.auth_ack_data:
                logging.info("Authentication refused: integrity good")
            else:
                logging.warning("Authentication refuse: integrity FAILURE")
                raise HASAuthenticationRefused("Integrity FAILURE")

    async def get_qrcode(self) -> StyledPilImage:
        if qr_text := self.qr_text:
            qr = QRCode(
                version=1,
                error_correction=ERROR_CORRECT_H,
                box_size=10,
                border=6,
            )
            qr.add_data(qr_text)
            # Create a new image with a white background
            text = str(f"Check: {self.auth_wait.uuid} - {self.hive_acc}")
            res = requests.get(f"https://api.v4v.app/v1/hive/avatar/{self.hive_acc}")
            if res.status_code == 200:
                # avatar_im = Image.open(BytesIO(res.content))
                with open(f"/tmp/{self.hive_acc}.png", "wb") as file:
                    file.write(res.content)

                img = qr.make_image(
                    image_factory=StyledPilImage,
                    embeded_image_path=f"/tmp/{self.hive_acc}.png",
                )
            else:
                img = qr.make_image()
            draw = ImageDraw.Draw(img)
            font = ImageFont.truetype("src/has_python/arial_narrow_bold_italic.ttf", 24)
            draw.text((100, 10), text, font=font, fill="black")
            return img

    async def connect_with_challenge(self):
        if self.token and self.expire and datetime.now(tz=timezone.utc) < self.expire:
            # Sets up the challenge with the existing token if it exists.
            self.setup_challenge()
        try:
            msg = await self.websocket.recv()
            self.connected_has = ConnectedHAS.parse_raw(msg)
            logging.debug(self.connected_has)
        except Exception as ex:
            logging.error(ex)
        await self.websocket.send(self.auth_req.json())
        msg = await self.websocket.recv()
        self.auth_wait = AuthWaitHAS.parse_raw(msg)
        self.auth_payload = AuthPayloadHAS(
            account=self.hive_acc, uuid=self.auth_wait.uuid, key=self.auth_key_uuid
        )
        time_to_wait = self.auth_wait.expire - datetime.now(tz=timezone.utc)
        logging.info(self.qr_text)
        logging.debug(f"Waiting for PKSA: {time_to_wait}")
        return time_to_wait

    async def waiting_for_challenge_response(self, time_to_wait: int):
        try:
            msg = await asyncio.wait_for(self.websocket.recv(), time_to_wait.seconds)
        except TimeoutError:
            logging.warning("Timeout waiting for HAS PKSA Response")
            raise HASAuthenticationTimeout("Timeout waiting for response")

        self.auth_ack = AuthAckNakErrHAS.parse_raw(msg)
        logging.debug(self.auth_ack)
        if self.auth_ack.uuid == self.auth_wait.uuid:
            logging.info("uuid OK")
            self.decrypt()
            if self.verification.success:
                logging.info(
                    f"Authentication successful in "
                    f"{self.verification.elapsed_time.seconds:.2f} seconds"
                )
                self.token = self.auth_ack_data.token
                self.expire = self.auth_ack_data.expire
            else:
                logging.warning("Not successful")
                raise HASAuthenticationRefused("Integrity good")
