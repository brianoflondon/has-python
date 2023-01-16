import base64
from hashlib import md5

from Cryptodome import Random
from Cryptodome.Cipher import AES


def pad(data):
    length = AES.block_size - (len(data) % AES.block_size)
    return data + (chr(length) * length).encode()


def unpad(data):
    return data[: -(data[-1] if type(data[-1]) == int else ord(data[-1]))]


def bytes_to_key(data: bytes, salt: bytes, output: int = 48) -> bytes:
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def js_encrypt(message: bytes, passphrase: bytes) -> bytes:
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))


def js_decrypt(encrypted: bytes, passphrase: bytes):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))
