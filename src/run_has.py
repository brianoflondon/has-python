import asyncio
import logging
from datetime import datetime, timezone

from pydantic import AnyUrl
from websockets import connect

from has_python.has import (
    HAS_SERVER,
    HASAuthentication,
    HASAuthenticationRefused,
    HASAuthenticationTimeout,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
    # format="{asctime} {levelname} {module} {lineno:>5} : {message}",
    # datefmt="%Y-%m-%dT%H:%M:%S,uuu",
)


async def connect_and_challenge(acc_name: str, has_server: AnyUrl = HAS_SERVER):

    has = HASAuthentication(
        hive_acc=acc_name,
        uri=has_server,
        challenge_message="Any string message goes here",
    )
    try:
        async with connect(uri=has.uri) as websocket:
            has.websocket = websocket
            time_to_wait = await has.connect_with_challenge()
            img = await has.get_qrcode()
            img.show()
            logging.info(f"PKSA needs to show: {has.auth_wait.uuid}")
            logging.info(f"QR-Code as text {'*'*40} \n\n{has.qr_text}\n\n{'*'*40}")
            await has.waiting_for_challenge_response(time_to_wait)

            logging.info(has.auth_ack_data.token)
            token_life = has.auth_ack_data.expire - datetime.now(tz=timezone.utc)
            logging.info(f"✅ Token: ********************** | Expires in : {token_life}")
            logging.info(has.app_session_id)

    except HASAuthenticationRefused:
        logging.info("❌ Authentication was refused")
    except HASAuthenticationTimeout:
        logging.info("❌ Timeout Waiting for PKSA Authentication")
        pass

    return


if __name__ == "__main__":
    try:
        asyncio.run(connect_and_challenge("v4vapp.dev", HAS_SERVER))
        asyncio.run(connect_and_challenge(acc_name="brianoflondon"))
    except KeyboardInterrupt:
        logging.info("Ctrl-C pressed, bye bye!")

    except Exception as ex:
        logging.exception(ex)
        logging.info("Quits")
