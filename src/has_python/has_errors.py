from enum import Enum


class HASErr(int, Enum):
    refused = 0
    refused_bad = 1
    timeout = 2
    no_pksa = 3
    transaction_failed = 4
    other = 10


class HASFailure(Exception):
    message: str
    code: HASErr
    pass

    def __init__(self, message: str, code: HASErr) -> None:
        self.message = f"❌ {message}"
        self.code = code

        super().__init__()
