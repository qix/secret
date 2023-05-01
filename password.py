from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import json
import os
from io import BytesIO
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Optional, Tuple

from clide import info, warn
from clide.atomic_write import atomic_write

from trezorlib import misc, ui
from trezorlib.client import TrezorClient
from trezorlib.transport import get_transport
from trezorlib.tools import parse_path


BIP32_PATH = parse_path("10016h/0")
ENC_ENTROPY_BYTES = 12
TAG_BYTES = 16
NONCE_ENTROPY_BYTES = 32

ENV_KEY = "J_STORE_KEY"
STORE_PATH = Path("~/personal/trezor").expanduser()

STORE_KEY = "Unlock j password store?"
STORE_ENTROPY = bytes.fromhex(
"""
    e8ab759b068dd6593e9d67b411ca9c2876d60ddd009499f116eec6a37c88a448
    a22fb317321c723a27edc2ff93c05f3455751a48f14e6d3792aacbb4f21dc9da
"""
)

FILENAME_MESS = b"5f91add3fa1c3c76e90c90a3bd0999e2bd7833d06a483fe884ee60397aca277a"


def _fs_key(name: Optional[str]) -> str:
    return (
        "Unlock j encrypted fs?"
        if name is None
        else ("Unlock j %s fs?" % json.dumps(name))
    )


def key_halves(key: bytes) -> Tuple[bytes, bytes]:
    "Divide a concatenated key into equal halves"
    half = len(key) // 2
    assert half * 2 == len(key), "Expected even length key"
    return (key[:half], key[half:])


def _aes_decrypt_json(f: BytesIO, key: bytes):
    iv = f.read(ENC_ENTROPY_BYTES)
    tag = f.read(TAG_BYTES)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    data = ""
    while True:
        block = f.read(16)
        # data are not authenticated yet
        if block:
            data += decryptor.update(block).decode()
        else:
            break
    # throws exception when the tag is wrong
    data += decryptor.finalize().decode()
    return json.loads(data)


def _aes_encrypt_bytes(data: bytes, *, iv: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + encrypted


def _trezor_client():
    transport = get_transport()
    return TrezorClient(transport=transport, ui=ui.ClickUI())


class Store:
    def __init__(
        self,
        client,
        master_key: bytes,
        *,
        verbose: bool = False,
        test_mode: bool = False
    ):
        self.client = client
        self.master_key = master_key
        self.file_key, self.enc_key = key_halves(master_key)
        self.test_mode = test_mode
        if verbose:
            info("Using store %s" % self.filename)
        if test_mode:
            warn("Test mode is enabled! Confirmations will be skipped")

    def to_env(self):
        assert not self.test_mode
        return (ENV_KEY, self.master_key.hex())

    @staticmethod
    def get_fs_password(*, name=None, test_mode=False):
        client = _trezor_client()

        return misc.encrypt_keyvalue(
            client,
            BIP32_PATH,
            _fs_key(name),
            STORE_ENTROPY,
            False if test_mode else True,
            False if test_mode else True,
        ).hex()

    @staticmethod
    def unlock(*, test_mode=False):
        client = _trezor_client()
        if ENV_KEY in os.environ and not test_mode:
            master_key = bytes.fromhex(os.environ[ENV_KEY])
        else:
            info("Requesting unlock of store...")
            master_key = misc.encrypt_keyvalue(
                client,
                BIP32_PATH,
                STORE_KEY,
                STORE_ENTROPY,
                False if test_mode else True,
                False if test_mode else True,
            )

        return Store(client, master_key, test_mode=test_mode)

    @property
    def filename(self):
        digest = hmac.new(self.file_key, FILENAME_MESS, hashlib.sha256).hexdigest()
        return digest + ".pswd"

    def load(self):
        with open(STORE_PATH / self.filename, "rb") as f:
            return _aes_decrypt_json(f, self.enc_key)

    def write(self, database):
        encoded = json.dumps(database).encode("utf-8")
        iv = os.urandom(ENC_ENTROPY_BYTES)
        encrypted = _aes_encrypt_bytes(encoded, iv=iv, key=self.enc_key)
        atomic_write(STORE_PATH / self.filename, encrypted, chmod=0o600)

    def decrypt(self, nonce, val):
        return _aes_decrypt_json(BytesIO(val), bytes.fromhex(nonce))

    def _enc_key(self, name: str):
        return "Unlock password %s?" % json.dumps(name)

    def decrypt_nonce(self, name, encrypted_nonce_hex):
        info("Requesting decrypt of entry %s..." % name)
        decrypted_nonce = misc.decrypt_keyvalue(
            self.client,
            BIP32_PATH,
            self._enc_key(name),
            bytes.fromhex(encrypted_nonce_hex),
            False,
            False if self.test_mode else True,
        )
        return decrypted_nonce

    def encrypt(self, name: str, data: Any):
        nonce = os.urandom(NONCE_ENTROPY_BYTES)
        encrypted_nonce_hex = misc.encrypt_keyvalue(
            self.client,
            BIP32_PATH,
            self._enc_key(name),
            nonce,
            False,
            False if self.test_mode else True,
        ).hex()

        encrypted = _aes_encrypt_bytes(
            json.dumps(data).encode("utf-8"),
            iv=os.urandom(ENC_ENTROPY_BYTES),
            key=nonce,
        )
        return {
            "name": name,
            "nonce": encrypted_nonce_hex,
            "payload": encrypted.hex(),
        }

    def decrypt(self, name, nonce, payload):
        decrypted_nonce = self.decrypt_nonce(name, nonce)
        return _aes_decrypt_json(BytesIO(bytes.fromhex(payload)), key=decrypted_nonce)
