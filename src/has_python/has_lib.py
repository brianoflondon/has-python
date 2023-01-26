import asyncio
import base64
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Awaitable, List, Tuple
from uuid import UUID, uuid4

import requests
import websockets
from dotenv import load_dotenv
from PIL import ImageDraw, ImageFont
from pydantic import BaseModel, ValidationError, validator
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_H
from qrcode.image.styledpil import StyledPilImage

from has_python.hive_validation import (
    Operation,
    SignedAnswer,
    SignedAnswerData,
    SignedAnswerVerification,
    validate_hivekeychain_ans,
)
from has_python.jscrypt_encode_for_python import js_decrypt, js_encrypt

logging.getLogger("beemapi.graphenerpc").setLevel(logging.ERROR)
logging.getLogger("beemapi.node").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)


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


class HiveVerificationFailure(Exception):
    pass


class HASResult(Exception):
    pass


class CmdType(str, Enum):
    connected = "connected"
    auth_req = "auth_req"
    challenge_req = "challenge_req"
    challenge_wait = "challenge_wait"
    challenge_ack = "challenge_ack"
    challenge_err = "challenge_err"
    auth_wait = "auth_wait"
    auth_ack = "auth_ack"
    auth_nack = "auth_nack"
    auth_err = "auth_err"
    sign_req = "sign_req"
    sign_wait = "sign_wait"
    sign_ack = "sign_ack"
    sign_nack = "sign_nack"
    sign_err = "sign_err"


class KeyType(str, Enum):
    posting = "posting"
    active = "active"
    memo = "memo"


class HASMessage(BaseModel):
    """Base for all messages which flow between HAS and app"""

    cmd: CmdType | None
    auth_key: UUID | None


class ValidToken(BaseModel):
    """Holds a valid token as returned following an authentication"""

    expire: datetime
    acc_name: str
    token: UUID
    expire: datetime
    auth_key: UUID


class HASApp(BaseModel):
    name: str = HAS_APP_DATA["name"]
    description: str = HAS_APP_DATA["description"]
    icon: str = HAS_APP_DATA["icon"]


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

    @property
    def bytes(self):
        """Return object as json string in bytes: does not include the `auth_key_uuid`
        also convert the token UUID if it exists to str"""
        return json.dumps(self.dict(exclude={"pub_key"}), default=str).encode("utf-8")

    def encrypted_b64(self, auth_key: UUID) -> bytes:
        return js_encrypt(self.bytes, str_bytes(auth_key))


class AuthDataHAS(BaseModel):
    app: HASApp = HASApp()
    token: UUID | None
    challenge: ChallengeHAS | None
    auth_key: UUID

    @property
    def bytes(self):
        """Return object as json string in bytes: does not include the `auth_key_uuid`
        also convert the token UUID if it exists to str"""
        return json.dumps(self.dict(exclude={"auth_key"}), default=str).encode("utf-8")

    @property
    def encrypted_b64(self) -> bytes:
        return js_encrypt(self.bytes, str_bytes(self.auth_key))


class _AuthChallReqHAS(HASMessage):
    account: str
    data: str
    token: UUID | None
    encrypted_auth_key: str | None


class AuthChallReqHAS(HASMessage):
    account: str
    data: str
    token: UUID | None
    auth_key: str | None

    class Config:
        allow_population_by_field_name = True


class HASWait(HASMessage):
    """Wait replies sent by HAS server"""

    expire: datetime
    uuid: UUID | None
    account: str | None

    @validator("cmd")
    def cmd_must_be(cls, v):
        if v not in [CmdType.auth_wait, CmdType.sign_wait, CmdType.challenge_wait]:
            raise ValueError("Not a Waiting Cmd type")
        return v


class AuthPayloadHAS(BaseModel):
    """This is the auth-key used when creating
    The APP must then encrypt the auth_data object
    using an encryption key (auth_key)"""

    account: str
    uuid: UUID
    key: UUID
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

    def validate_hive(self):
        validate_hive_auth_req(self.uuid, self.data)


class ChallengeAckHAS(HASMessage):
    uuid: UUID
    data: str

    def validate_hive(self):
        validate_hive_sign_req(self.uuid, self.data)


class AuthNackHAS(HASMessage):
    uuid: UUID
    data: str

    def validate_hive(self):
        validate_hive_auth_req(self.uuid, self.data)


class HASChallenge(HASWait):
    challenge: ChallengeHAS = None


class AuthAckDataHAS(HASChallenge):
    token: UUID


class ChallAckDataHAS(HASChallenge):
    pubkey: str


class SignAckHAS(HASMessage):
    uuid: UUID
    broadcast: bool = True
    data: Any


class SignNackHAS(HASMessage):
    uuid: UUID
    error: str

    def validate_hive(self):
        validate_hive_sign_req(self.uuid, self.error)


class SignErrHAS(HASMessage):
    uuid: UUID
    error: str

    def validate_hive(self):
        validate_hive_sign_req(self.uuid, self.error)


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
    token: UUID
    data: str
    auth_key: UUID

    def __init__(self, account: str, token: ValidToken, data: str) -> None:
        super().__init__(
            cmd=CmdType.sign_req,
            account=account,
            token=token.token,
            data=data,
            auth_key=token.auth_key,
        )


class ChallengeReqHAS(HASMessage):
    account: str
    token: UUID
    data: str
    auth_key: UUID

    def __init__(
        self,
        account: str,
        key_type: KeyType,
        token: ValidToken,
        challenge_message: str,
    ) -> None:
        challenge = ChallengeHAS(
            key_type=key_type,
            challenge_data={
                "timestamp": datetime.now(tz=timezone.utc).timestamp(),
                "app_session_id": uuid4(),
                "message": challenge_message,
            },
        )
        data = (challenge.encrypted_b64(token.auth_key)).decode("utf-8")
        super().__init__(
            cmd=CmdType.challenge_req,
            account=account,
            token=token.token,
            data=data,
            auth_key=token.auth_key,
        )


class AuthSignObject(AuthDataHAS, _AuthChallReqHAS):
    timestamp: datetime = datetime.now(tz=timezone.utc)

    def __init__(
        __pydantic_self__,
        acc_name: str,
        key_type: KeyType,
        challenge_message: str,
        use_pksa_key: bool = False,
        auth_key: UUID = uuid4(),
        token: ValidToken = None,
    ) -> None:
        """
        Builds an `auth_req` with a challenge.
        If token is given needs to use the previous `auth_key`
        """
        timestamp = datetime.now(tz=timezone.utc).timestamp()
        challenge = ChallengeHAS(
            key_type=key_type,
            challenge_data={
                "timestamp": timestamp,
                "app_session_id": uuid4(),
                "message": challenge_message,
            },
        )
        cmd = CmdType.auth_req
        if token:
            auth_key = token.auth_key
            cmd = CmdType.sign_req
        auth_data = AuthDataHAS(
            challenge=challenge,
            auth_key=auth_key,
        )
        auth_chall_req = _AuthChallReqHAS(
            cmd=cmd,
            account=acc_name,
            data=auth_data.encrypted_b64,
        )
        all_data = auth_data.dict(exclude_unset=True) | auth_chall_req.dict(
            exclude_unset=True
        )
        if use_pksa_key:
            encrypted_auth_key = js_encrypt(
                str_bytes(auth_data.auth_key), str_bytes(HAS_AUTH_REQ_SECRET)
            )
            all_data = all_data | {"encrypted_auth_key": encrypted_auth_key}
        super().__init__(**all_data)

    @property
    def auth_req(self) -> AuthChallReqHAS:
        """Returns only an auth_req"""
        auth_req = AuthChallReqHAS(
            cmd=CmdType.auth_req,
            auth_key=self.encrypted_auth_key,
            account=self.account,
            data=self.data,
            token=self.token,
        )
        # Have to transform `encrypted_auth_key` to `auth_key`
        return auth_req


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


def purge_a_list(any_list: List):
    """Checks for expired itesm in any list. Returns a list with
    expired items removed"""
    delete_list = []
    for i, item in enumerate(any_list):
        if item.expire:
            expires_in = item.expire - datetime.now(tz=timezone.utc)
            if expires_in < timedelta(seconds=0):
                delete_list.append(i)
            else:
                logger.info(f"Expires in {expires_in} | {item}")
    if delete_list:
        for item in delete_list:
            logging.info(f"Request expired: {any_list[item]}")
        any_list = [i for j, i in enumerate(any_list) if j not in delete_list]
    return any_list


class AllLists(BaseModel):
    # items: List[AuthObjectHAS | ]
    auth_list: List[AuthSignObject] = []
    wait_list: List[HASWait] = []
    token_list: List[ValidToken] = []

    def purge_expired(self) -> Tuple[int, int]:
        """Check for epired waiting objects and tokens
        Returns a tuple of number of waiting items and valid tokens"""
        self.wait_list = purge_a_list(self.wait_list)
        self.token_list = purge_a_list(self.token_list)
        return (len(self.wait_list), len(self.token_list))

    def find_auth(self, acc_name: str) -> AuthSignObject:
        found = [item for item in self.auth_list if item.account == acc_name]
        if len(found) == 1:
            return found[0]
        raise Exception("Need to deal with multiple concurrent auth requests")

    def del_auth(self, found: AuthSignObject):
        """Finda auth item and deletes it"""
        index = self.auth_list.index(found)
        del self.auth_list[index]

    def find_wait(self, uuid: UUID) -> HASWait:
        found = [item for item in self.wait_list if item.uuid == uuid]
        if len(found) == 1:
            return found[0]
        raise Exception("Need to deal with multiple concurrent auth requests")

    def del_wait(self, found: HASWait):
        """Finds a waiting item and deletes it"""
        index = self.wait_list.index(found)
        del self.wait_list[index]

    def find_token_by_account(self, acc_name: str) -> ValidToken | None:
        found = [item for item in self.token_list if item.acc_name == acc_name]
        if not found:
            return None
        if len(found) == 1:
            return found[0]
        raise Exception("Need to deal with multiple concurrent auth requests")

    def find_token_by_uuid_str(self, token_str: str) -> ValidToken | None:
        found = [item for item in self.token_list if str(item.token) == token_str]
        if len(found) == 1:
            return found[0]
        raise Exception("Need to deal with multiple concurrent auth requests")


def validate_hive_sign_req(uuid: UUID, data: str):
    """Can't be sure which waiting request this is for"""

    sign_wait = GLOBAL_LISTS.find_wait(uuid)
    if not sign_wait:
        raise
    GLOBAL_LISTS.del_wait(sign_wait)
    data_bytes = data.encode("utf-8")
    for auth_object in GLOBAL_LISTS.auth_list:
        try:
            data_string = js_decrypt(
                data_bytes, str_bytes(auth_object.auth_key)
            ).decode(encoding="utf-8")
            decoded_data = json.loads(data_string)
            decoded_challenge = ChallengeHAS.parse_obj(decoded_data)
            verification = check_hive_signature(
                decoded_challenge, auth_object, decoded_data, data_string
            )

        except Exception as ex:
            logger.error(ex)

    pass


def validate_hive_auth_req(uuid: UUID, data: str):
    """Validates an authentication and challenge
    or validates a challenge on its own"""
    # Find the matching index of ACK_WAIT_LIST
    auth_wait = GLOBAL_LISTS.find_wait(uuid)
    if not auth_wait:
        raise
    GLOBAL_LISTS.del_wait(auth_wait)

    if auth_wait.account:
        auth_object = GLOBAL_LISTS.find_auth(auth_wait.account)
        GLOBAL_LISTS.del_auth(auth_object)
        if auth_object and auth_object.account != auth_wait.account:
            raise HiveVerificationFailure()
        auth_key = auth_object.auth_key
        data_bytes = data.encode("utf-8")
        data_string = js_decrypt(data_bytes, str_bytes(auth_key)).decode(
            encoding="utf-8"
        )
        # If AuthNack the datastring is a UUID:
        try:
            check_uuid = UUID(data_string)
            if check_uuid == uuid:
                logger.info("Integrity Check good: Authorisation rejected")
                return
                # raise HASResult("auth_nack")
        except ValueError:
            decoded_data = json.loads(data_string)
            if decoded_data.get("token"):
                decoded_challenge = ChallengeHAS.parse_obj(
                    decoded_data.get("challenge")
                )
            else:
                decoded_challenge = ChallengeHAS.parse_obj(decoded_data)
            verification = check_hive_signature(
                decoded_challenge, auth_object, decoded_data, data_string
            )


def check_hive_signature(
    decoded_challenge: dict,
    auth_object: AuthSignObject,
    decoded_data: dict,
    data_string: str,
) -> SignedAnswerVerification:
    signed_answer = SignedAnswer(
        result=decoded_challenge.challenge,
        request_id=1,
        publicKey=decoded_challenge.pubkey,
        data=SignedAnswerData(
            _type="HAS",
            username=auth_object.account,
            message=auth_object.challenge.challenge,
            method=auth_object.challenge.key_type,
            key=auth_object.challenge.key_type,
        ),
    )
    verification = validate_hivekeychain_ans(signed_answer)
    if decoded_data.get("token"):
        auth_ack_data = AuthAckDataHAS.parse_raw(data_string)
        logger.info(f"Token: {auth_ack_data.token}")
        if verification.success:
            valid_token = ValidToken(
                acc_name=verification.acc_name,
                token=auth_ack_data.token,
                expire=auth_ack_data.expire,
                auth_key=auth_object.auth_key,
            )
            GLOBAL_LISTS.token_list.append(valid_token)
    return verification


async def build_auth_req_challenge(
    acc_name: str,
    key_type: KeyType,
    challenge_message: str,
    token: UUID = None,
    use_pksa_key: bool = False,
) -> AuthSignObject:
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
    auth_req = _AuthChallReqHAS(
        cmd=CmdType.auth_req,
        account=acc_name,
        data=auth_data.encrypted_b64,
    )
    if use_pksa_key:
        auth_req.auth_key = js_encrypt(
            str_bytes(auth_data.auth_key), str_bytes(HAS_AUTH_REQ_SECRET)
        )

    return AuthSignObject(acc_name=acc_name, auth_data=auth_data, auth_req=auth_req)


async def socket_listen(has_socket):
    """
    Listen to a socket and act on what is received.
    """
    while True:
        try:
            msg = await has_socket.recv()
            cmd = HASMessage.parse_raw(msg)
            logger.info(f"<------ Recivied: {cmd}")
            logger.debug(msg)
            match cmd.cmd:
                case CmdType.connected:
                    processed = ConnectedHAS.parse_raw(msg)
                    processed.socketid
                    logger.info(processed)
                case CmdType.auth_wait:
                    auth_wait = HASWait.parse_raw(msg)
                    # Display QR Code - move this code to HASWait class
                    auth_payload = AuthPayloadHAS(
                        account=auth_wait.account,
                        uuid=auth_wait.uuid,
                        key=GLOBAL_LISTS.find_auth(auth_wait.account).auth_key,
                    )
                    extra_text = str(
                        f"Check: {auth_wait.uuid} - " f"{auth_wait.account}"
                    )
                    img = auth_payload.qr_image(extra_text=extra_text)
                    if not auth_wait.account == "v4vapp.dev":
                        img.show()
                    GLOBAL_LISTS.wait_list.append(auth_wait)
                    logger.info(auth_wait)
                case CmdType.sign_wait:
                    sign_wait = HASWait.parse_raw(msg)
                    logger.info(
                        f"****** Alert User to authorise transaction "
                        f"{sign_wait.uuid}"
                    )
                    GLOBAL_LISTS.wait_list.append(sign_wait)
                case CmdType.challenge_wait:
                    challenge_wait = HASWait.parse_raw(msg)
                    logger.info(
                        f"****** Alert User to authorise challenge   "
                        f"{challenge_wait.uuid}"
                    )
                    GLOBAL_LISTS.wait_list.append(challenge_wait)
                case CmdType.auth_ack:
                    auth_ack = AuthAckHAS.parse_raw(msg)
                    logger.debug(auth_ack)
                    auth_ack.validate_hive()
                case CmdType.challenge_ack:
                    challenge_ack = ChallengeAckHAS.parse_raw(msg)
                    logger.debug(challenge_ack)
                    challenge_ack.validate_hive()
                case CmdType.auth_nack:
                    auth_nack = AuthNackHAS.parse_raw(msg)
                    logger.debug(auth_nack)
                    auth_nack.validate_hive()
                case CmdType.sign_ack:
                    sign_ack = SignAckHAS.parse_raw(msg)
                    if sign_ack.broadcast:
                        logger.info(f"Transaction broadcast to Hive: {sign_ack.data}")
                case CmdType.sign_nack:
                    sign_nack = SignNackHAS.parse_raw(msg)
                    sign_nack.validate_hive()
                case CmdType.sign_err:
                    logger.info("Sign Error")
                    sign_err = SignErrHAS.parse_raw(msg)
                    sign_err.validate_hive()
                    logger.info(f"Sign Error: {sign_err.error}")

            if has_socket.closed:
                break

        except (ValidationError, KeyError) as ex:
            if msg:
                logger.error(f"Message received: {msg}")
            logger.error(ex)
            pass
        except (
            websockets.exceptions.ConnectionClosedError,
            ConnectionError,
            ConnectionResetError,
        ) as ex:
            logger.warning(ex)
            break
        except Exception as ex:
            logger.exception(ex)
            raise


async def execute_tasks(has_socket):
    """Watches the task Queue"""
    while True:
        try:
            msg: HASMessage = await TASK_QUEUE.get()
            logger.info(msg.json(exclude_none=True, models_as_dict=True))
            await has_socket.send(msg.json(exclude_none=True))
            logger.info(f"------> Sent:   {msg.cmd}")
            await asyncio.sleep(0.1)
        except (
            websockets.exceptions.ConnectionClosedError,
            ConnectionError,
            ConnectionResetError,
        ) as ex:
            logger.warning(ex)
            logger.info("Putting the msg back int the Queue")
            await TASK_QUEUE.put(msg)
            break
        except Exception as ex:
            logger.exception(ex)
            raise


async def global_list_purge(
    quit_after_waiting: bool = False, other_tasks: asyncio.TaskGroup = None
) -> bool:
    """
    Check the global list for expired waits.
    If quit_after_waiting is set and no more waiting items,
    this will quit and return True
    """
    await asyncio.sleep(10)
    checks = 0
    while True:
        await asyncio.sleep(1)
        waiting, tokens = GLOBAL_LISTS.purge_expired()
        if waiting == 0:
            checks += 1
        else:
            checks = 0
        if checks > 2 and quit_after_waiting and waiting == 0:
            if other_tasks:
                [task.cancel() for task in other_tasks._tasks]
            return True
        await asyncio.sleep(9)


async def manage_websocket():
    while True:
        async with websockets.connect(HAS_SERVER) as has_socket:
            try:
                async with asyncio.TaskGroup() as tg:
                    listen = tg.create_task(socket_listen(has_socket))
                    execute = tg.create_task(execute_tasks(has_socket))
                    logger.info(f"Finished Listening {listen}")
                    logger.info(f"Finished Exectuing {execute}")
            except (
                websockets.exceptions.ConnectionClosedError,
                ConnectionError,
                ConnectionResetError,
            ) as ex:
                logger.warning(ex)
                break
            except Exception as ex:
                logger.exception(ex)
                break


async def main_listen_send_loop(tasks: List[Awaitable]):
    """Run the main parts for listening to and sending from websockets
    If the main code ends, raises asyncio.CancelledError"""
    async with asyncio.TaskGroup() as tg:
        tg.create_task(manage_websocket(), name="send_listen")
        for task in tasks:
            tg.create_task(task)
        time_to_end = tg.create_task(
            global_list_purge(quit_after_waiting=True, other_tasks=tg)
        )
    if time_to_end.done():
        logging.info("All Done")


async def main_testing_loop():
    try:
        await main_listen_send_loop(
            tasks=[
                test_send_auth_req(),
                test_challenge(),
                # test_send_transaction(),
            ]
        )
    except Exception as ex:
        logging.info(ex)


target = "v4vapp"


async def test_send_auth_req():
    await asyncio.sleep(10)
    for acc in [target]:  # ,'brianoflondon']:
        # await asyncio.sleep(3)
        use_pksa_key = False
        if acc == "v4vapp.dev":
            use_pksa_key = True
        auth_object = AuthSignObject(
            acc_name=acc,
            key_type=KeyType.posting,
            challenge_message=f"{acc} Welcome to the Party!",
            use_pksa_key=use_pksa_key,
        )
        GLOBAL_LISTS.auth_list.append(auth_object)
        await TASK_QUEUE.put(auth_object.auth_req)


async def test_send_transaction():
    await asyncio.sleep(20)
    test_account = target
    # find valid Token
    for i in range(3):
        await asyncio.sleep(5)
        valid_token = GLOBAL_LISTS.find_token_by_account(test_account)
        if valid_token:
            payload = {"HAS": f"{i} - testing", "timestamp": str(datetime.now())}
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
                account=valid_token.acc_name,
                token=valid_token,
                data=sign_data.encrypted_b64(valid_token.auth_key),
            )
            logger.info(sign_req)
            GLOBAL_LISTS.auth_list.append(sign_req)
            await TASK_QUEUE.put(sign_req)
            await asyncio.sleep(60 + i * 10)


async def test_challenge():

    await asyncio.sleep(15)
    while True:
        valid_token = GLOBAL_LISTS.find_token_by_account(target)
        challenge_message = "who let the dogs out?"
        key_type = KeyType.active
        if valid_token:
            auth_sign = AuthSignObject(
                acc_name=target,
                key_type=key_type,
                challenge_message=challenge_message,
                token=valid_token,
            )
            challenge_req = ChallengeReqHAS(
                account=target,
                key_type=key_type,
                token=valid_token,
                challenge_message=challenge_message,
            )
            GLOBAL_LISTS.auth_list.append(auth_sign)
            await TASK_QUEUE.put(challenge_req)
            break
        await asyncio.sleep(5)


GLOBAL_LISTS: AllLists = AllLists()
TASK_QUEUE = asyncio.Queue()
# AUTH_LIST: AuthList = AuthList()
# ACK_WAIT_LIST: List[AuthWaitHAS] = []
# VALID_TOKEN_LIST: List[ValidToken] = []

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
        encoding="utf-8",
        stream=sys.stdout,
    )
    asyncio.run(main_testing_loop())
