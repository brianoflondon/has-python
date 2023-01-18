import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
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
from websockets.legacy.client import WebSocketClientProtocol

from has_python.has_errors import HASErr, HASFailure
from has_python.hive_validation import (
    SignedAnswer,
    SignedAnswerData,
    SignedAnswerVerification,
    validate_hivekeychain_ans,
)
from has_python.jscrypt_encode_for_python import js_decrypt, js_encrypt

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


class Operation:
    """Taken from Lighthive by Emre"""

    def __init__(self, type, value):
        self.type = type
        self.op_type = "%s_operation" % type
        self.op_value = value

    def to_dict(self):
        # return {
        #     "type": self.op_type,
        #     "value": self.op_value,
        # }
        return [self.type, self.op_value]

    def __repr__(self):
        return self.to_dict()


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
    sign_req = "sign_req"
    sign_wait = "sign_wait"
    sign_ack = "sign_ack"
    sign_nack = "sign_nack"


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


class ChallengeAckHAS(BaseModel):
    cmd: CmdType = CmdType.auth_ack
    uuid: UUID
    data: str


class ChallengeAckData(BaseModel):
    pubkey: str
    challenge: str


class AuthDataHAS(BaseModel):
    app: HASApp = HASApp()
    token: str | None
    challenge: ChallengeHAS | None
    auth_key_uuid: UUID

    def __init__(__pydantic_self__, **data: Any) -> None:
        super().__init__(**data)

    @property
    def bytes(self):
        """
        Return object as json string in bytes: does not include the `auth_key_uuid`
        """
        return json.dumps(self.dict(exclude={"auth_key_uuid"})).encode("utf-8")

    @property
    def encrypted_b64(self) -> bytes:
        return js_encrypt(self.bytes, str_bytes(self.auth_key_uuid))


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


class AuthSignWaitHAS(BaseModel):
    cmd: CmdType
    uuid: UUID
    expire: datetime
    account: str | None


class AuthSignAckNakErrHAS(BaseModel):
    cmd: CmdType | None
    uuid: UUID | None
    data: str | None
    error: dict | None
    broadcast: bool = False


class AuthAckDataHAS(BaseModel):
    token: str
    expire: datetime
    challenge: ChallengeHAS = None


class SignDataHAS(BaseModel):
    key_type: KeyType
    ops: dict
    broadcast: bool
    auth_key_uuid: UUID

    @property
    def bytes(self):
        """
        Return object as json string in bytes: does not include the `auth_key_uuid`
        Also needs to carefully encode ops only once.
        """
        # self.ops = json.dumps(self.ops)
        holding_json = self.dict(exclude={"auth_key_uuid"})
        if temp_store := self.ops.get("json"):
            self.ops["json"] = "replaceMeNowZigaZiga"
            holding_json = json.dumps([[self.dict(exclude={"auth_key_uuid"})]])
            holding_json = holding_json.replace(
                "replaceMeNowZigaZiga", json.dumps(temp_store)
            )
        return holding_json.encode("utf-8")

    @property
    def encrypted_b64(self) -> bytes:
        return js_encrypt(self.bytes, str_bytes(self.auth_key_uuid))

    class Config:
        arbitrary_types_allowed = True


class SignReqHAS(BaseModel):
    cmd: CmdType = CmdType.sign_req
    account: str
    token: str
    data: str
    auth_key_uuid: UUID

    def __init__(__pydantic_self__, **data: Any) -> None:
        super().__init__(**data)


class HASAuthentication(BaseModel):
    hive_acc: str = HIVE_ACCOUNT
    key_type: KeyType = KeyType.posting
    uri: AnyUrl = HAS_SERVER
    websocket: WebSocketClientProtocol | None
    challenge_message: str | None
    app_session_id: UUID
    auth_key_uuid: UUID
    connected_has: ConnectedHAS | None
    auth_wait: AuthSignWaitHAS | None
    auth_data: AuthDataHAS
    auth_req: AuthReqHAS
    auth_payload: AuthPayloadHAS | None
    auth_sign_ack: AuthSignAckNakErrHAS | None
    sign_data: SignDataHAS | None
    sign_req: SignReqHAS | None
    signed_answer: SignedAnswer | None
    verification: SignedAnswerVerification | bool = False
    error: HASFailure | None
    token: str | None
    expire: datetime | None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data: Any):
        """
        Populates the challenge data with the correct encoding and supplies
        an encrypted one time key:
            encrypted with this app's HAS_AUTH_REQ_SECRET
        This is necessary if running against a PKSA service instead of an
        interactive client (such as Hive KeyChain)
        """
        # NOTE: challenge_data will be converted to a challenge str
        # Within the constructor of ChallengeHAS
        data["app_session_id"] = uuid4()
        data["auth_key_uuid"] = uuid4()
        data["challenge"] = ChallengeHAS(
            key_type=data.get("key_type"),
            challenge_data={
                "timestamp": datetime.now(tz=timezone.utc).timestamp(),
                "app_session_id": data.get("app_session_id"),
                "message": data.get("challenge_message"),
            },
        )
        data["auth_data"] = AuthDataHAS(**data)
        data["auth_req"] = AuthReqHAS(
            account=data["hive_acc"],
            data=data["auth_data"].encrypted_b64,
            # Auth Key needed for using a PKSA Service without QR codes
            auth_key=js_encrypt(
                str_bytes(data["auth_key_uuid"]), str_bytes(HAS_AUTH_REQ_SECRET)
            ),
            **data,
        )
        super().__init__(**data)

    @property
    def auth_ack_data(self) -> AuthAckDataHAS | str:
        """
        On the fly decryption of a response from HAS
        If the response is a rejection `auth_nack` this
        will probably return as a string"""
        if self.auth_sign_ack.data:
            data_bytes = self.auth_sign_ack.data.encode("utf-8")
            data_string = js_decrypt(data_bytes, str_bytes(self.auth_key_uuid)).decode(
                "utf-8"
            )
        else:
            return ""
        try:
            return AuthAckDataHAS.parse_raw(data_string)
        except ValidationError:
            return data_string
        except Exception as ex:
            logging.exception(ex)
            return data_string

    @property
    def auth_key(self) -> bytes:
        return self.auth_key_uuid.bytes

    # @property
    # def b64_auth_data_encrypted(self) -> bytes:
    #     return js_encrypt(self.auth_data.bytes, str_bytes(self.auth_key_uuid))

    @property
    def b64_auth_payload_encrypted(self) -> bytes:
        """
        Encrypts the HAS_AUTH_REQ_SECRET for sharing with a PKSA as a service.
        ignored when using Hive Keychain interactively
        """
        return js_encrypt(str_bytes(self.auth_key_uuid), str_bytes(HAS_AUTH_REQ_SECRET))

    @property
    def qr_text(self) -> str:
        auth_payload_base64 = base64.b64encode(
            (self.auth_payload.json()).encode()
        ).decode("utf-8")
        return f"has://auth_req/{auth_payload_base64}"

    def decrypt(self):
        """
        Decrypts a challenge response received back from HAS.

        Sets property `validated` to `True` and `time_to_validate` if
        challenge is returned successfully
        """
        if (
            self.auth_sign_ack.cmd in [CmdType.auth_ack, CmdType.sign_ack]
            and self.auth_key
            and self.auth_data
            and self.auth_payload
            and self.auth_sign_ack.data
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
        elif self.auth_sign_ack.cmd is CmdType.auth_nack:
            self.verification = False
            if self.auth_payload.uuid == self.auth_sign_ack.uuid:
                logging.debug("Communication with HAS integrity good")
                if not self.auth_sign_ack.data:
                    self.error = HASFailure(
                        message=f"No PKSA found for account {self.hive_acc}",
                        code=HASErr.no_pksa,
                    )
                    logging.debug(self.error.message)
                    raise self.error
                if (
                    self.auth_sign_ack.data
                    and str(self.auth_payload.uuid) == self.auth_ack_data
                ):
                    self.error = HASFailure(
                        message="Authentication refused: integrity GOOD",
                        code=HASErr.refused,
                    )
                    logging.debug(self.error.message)
                    raise self.error
                else:
                    self.error = HASFailure(
                        message="Authentication refused: integrity FAILURE",
                        code=HASErr.refused_bad,
                    )
                    logging.debug(self.error.message)
                    raise self.error
        elif self.auth_sign_ack.cmd is CmdType.sign_nack:
            self.verification = False
            if self.auth_wait.uuid == self.auth_sign_ack.uuid:
                logging.debug("Communication with HAS integrity good")
                self.error = HASFailure(
                    message="Transaction failed", code=HASErr.transaction_failed
                )
                raise self.error

    async def get_qrcode(self) -> StyledPilImage:
        """
        Returns a QR Image
        """
        if qr_text := self.qr_text:
            qr = QRCode(
                version=1,
                error_correction=ERROR_CORRECT_H,
                box_size=10,
                border=6,
            )
            qr.add_data(qr_text)
            # Create a new image with a white background
            text = str(
                f"Check: {self.auth_wait.uuid} - "
                f"{self.hive_acc} - {self.key_type.value}"
            )
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

    async def connect_with_challenge(self) -> timedelta:
        """
        Perform initial connection with a challenge. Returns the time to wait
        taken from the `expire` field in the `auth_wait` received from HAS
        """
        try:
            msg = await self.websocket.recv()
            self.connected_has = ConnectedHAS.parse_raw(msg)
            logging.debug(self.connected_has)
        except Exception as ex:
            logging.error(ex)
        await self.websocket.send(self.auth_req.json())
        msg = await self.websocket.recv()
        self.auth_wait = AuthSignWaitHAS.parse_raw(msg)
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
            self.error = HASFailure(
                message="Timeout waiting for response", code=HASErr.timeout
            )
            logging.warning(self.error.message)
            raise self.error

        self.auth_sign_ack = AuthSignAckNakErrHAS.parse_raw(msg)
        logging.debug(self.auth_sign_ack)
        if self.auth_sign_ack.uuid == self.auth_wait.uuid:
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
                self.error = HASFailure(
                    message="Authentication refused", code=HASErr.other
                )
                raise self.error

    async def transaction_request(self, ops: dict, broadcast: bool = True):
        """
        Create, sign and send a transaction.
        """
        self.sign_data = SignDataHAS(
            key_type=self.key_type,
            ops=ops,
            auth_key_uuid=self.auth_key_uuid,
            broadcast=broadcast,
        )

        self.sign_req = SignReqHAS(
            account=self.hive_acc,
            token=self.token,
            auth_key_uuid=self.auth_key_uuid,
            data=self.sign_data.encrypted_b64,
        )
        await self.websocket.send(self.sign_req.json())
        msg = await self.websocket.recv()
        self.auth_wait = AuthSignWaitHAS.parse_raw(msg)
        self.auth_wait.account = self.hive_acc
        time_to_wait = self.auth_wait.expire - datetime.now(tz=timezone.utc)
        logging.debug(f"Waiting for PKSA: {time_to_wait}")
        return time_to_wait

        # try:
        #     msg = await asyncio.wait_for(self.websocket.recv(), time_to_wait.seconds)
        # except TimeoutError:
        #     self.error = HASAuthenticationFailure(
        #         message="Timeout waiting for response", code=HASAuthErr.timeout
        #     )
        #     logging.warning(self.error.message)
        #     raise self.error

        try:
            auth_ack = AuthSignAckNakErrHAS.parse_raw(msg)

            logging.debug(auth_ack)
        except Exception as ex:
            logging.error(ex)
