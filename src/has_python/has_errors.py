from enum import Enum


class HASAuthErr(int, Enum):
    refused = 0
    refused_bad = 1
    timeout = 2
    no_pksa = 3
    other = 4


class HASAuthenticationFailure(Exception):
    message: str
    code: HASAuthErr
    pass

    def __init__(self, message: str, code: HASAuthErr) -> None:
        self.message = f"❌ {message}"
        self.code = code

        super().__init__()
