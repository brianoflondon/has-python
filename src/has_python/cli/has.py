import asyncio
import logging
import sys

import typer

from has_python.has_lib import (
    GLOBAL_LISTS,
    TASK_QUEUE,
    AuthSignObject,
    KeyType,
    main_listen_send_loop,
)

logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
    encoding="utf-8",
    stream=sys.stderr,
)

app = typer.Typer()
logging.getLogger("has_python.has_lib2").setLevel(logging.ERROR)
logging.getLogger("beemapi.graphenerpc").setLevel(logging.ERROR)
logging.getLogger("beemapi.node").setLevel(logging.ERROR)


async def connect_and_challenge(
    acc_name: str,
    key_type: KeyType = KeyType.posting,
    token: str = None,
    display: bool = True,
    challenge_message: str = "Any string message goes here",
):
    """
    Creats a HAS Authentiction connection and (option `display`) shows a QR code.
    """

    use_pksa_key = False
    if acc_name == "v4vapp.dev":
        use_pksa_key = True
    auth_object = AuthSignObject(
        acc_name=acc_name,
        key_type=key_type,
        challenge_message=challenge_message,
        use_pksa_key=use_pksa_key,
    )
    GLOBAL_LISTS.auth_list.append(auth_object)
    tasks = [
        TASK_QUEUE.put(auth_object.auth_req)
    ]
    async with asyncio.TaskGroup() as tg:
        tg.create_task(main_listen_send_loop(tasks=tasks))
    if GLOBAL_LISTS.token_list:
        print(f"Token: {GLOBAL_LISTS.token_list[0].token}")
        print(f"Auth_key: {GLOBAL_LISTS.token_list[0].auth_key}")

@app.command()
def connect(
    hive_account: str = typer.Argument(
        ..., help="The Hive account to perform authentication services against"
    ),
    key_type: KeyType = typer.Option(KeyType.posting, help="Hive Key type"),
    token: str = typer.Option(None, help="Token from a previous authentication"),
    display: bool = typer.Option(True, help="Displays a QR Code in a pop up window"),
):
    """Start a new connection to
    Hive Authentication Services (HAS)
    from the Hive Account ACC_Name"""

    try:
        asyncio.run(
            # test_transaction_request(),
            connect_and_challenge(
                acc_name=hive_account, key_type=key_type, token=token, display=display
            )
        )
        if GLOBAL_LISTS.find_token_by_account(hive_account):
            print("Authorisation Granted ✅")
        else:
            print("Authorisation denied: ❌")
        print("All Done")
    except KeyboardInterrupt:
        logging.info("Ctrl-C pressed, bye bye!")
    except Exception as ex:
        logging.exception(ex)
        logging.info("Quits")


# async def test_transaction_request():
#     test_account = "brianoflondon"
#     has = HASAuthentication(hive_acc=test_account)
#     async with ws_connect(has.uri) as websocket:
#         has.websocket = websocket
#         time_to_wait = await has.connect_with_challenge()
#         img = await has.get_qrcode()
#         img.show()
#         await has.waiting_for_challenge_response(time_to_wait)
#         assert has.token
#         assert has.expire
#         payload = {"HAS": "testing"}
#         logging.info(has.token)
#         test_ops = [
#             [
#                 "custom_json",
#                 {
#                     "id": "v4vapp_has_testing",
#                     "json": payload,
#                     "required_auths": [],
#                     "required_posting_auths": [test_account],
#                 },
#             ]
#         ]
#         time_to_wait = await has.transaction_request(ops=test_ops)
#         await has.waiting_for_challenge_response(time_to_wait=time_to_wait)


if __name__ == "__main__":
    app()
