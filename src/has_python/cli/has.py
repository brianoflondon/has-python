import asyncio
import logging
import os
import sys
from datetime import datetime, timezone

import typer
from pydantic import AnyUrl
from websockets import connect as ws_connect

from has_python.has_errors import HASAuthenticationFailure
from has_python.has_lib import HAS_SERVER, HASAuthentication, KeyType

app = typer.Typer()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
    # format="{asctime} {levelname} {module} {lineno:>5} : {message}",
    # datefmt="%Y-%m-%dT%H:%M:%S,uuu",
)


async def connect_and_challenge(
    acc_name: str,
    key_type: KeyType = KeyType.posting,
    token: str = None,
    has_server: AnyUrl = HAS_SERVER,
):
    has = HASAuthentication(
        hive_acc=acc_name,
        uri=has_server,
        challenge_message="Any string message goes here",
        key_type=key_type,
        token=token,
    )
    try:
        async with ws_connect(has.uri) as websocket:
            has.websocket = websocket
            time_to_wait = await has.connect_with_challenge()
            img = await has.get_qrcode()
            img.show()
            logging.info(f"PKSA needs to show: {has.auth_wait.uuid}")
            logging.info(f"QR-Code as text {'*'*40} \n\n{has.qr_text}\n\n{'*'*40}")
            await has.waiting_for_challenge_response(time_to_wait)

            token_life = has.auth_ack_data.expire - datetime.now(tz=timezone.utc)
            logging.info(
                f"✅ Token: {has.auth_ack_data.token} | Expires in : {token_life}"
            )
            logging.info(f"Session ID: {has.app_session_id}")

    except HASAuthenticationFailure as ex:
        logging.info(f"{ex.message}")
        sys.exit(os.EX_UNAVAILABLE)

    return


@app.command()
def connect(hive_account: str, key_type: KeyType = KeyType.posting, token: str = None):
    """Start a new connection to
    Hive Authentication Services (HAS)
    from the Hive Account ACC_Name"""
    try:
        asyncio.run(
            connect_and_challenge(acc_name=hive_account, key_type=key_type, token=token)
        )
        print("all done")
    except KeyboardInterrupt:
        logging.info("Ctrl-C pressed, bye bye!")
    except Exception as ex:
        logging.exception(ex)
        logging.info("Quits")


if __name__ == "__main__":
    app()
