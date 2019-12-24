from typing import Tuple
import base64
import hmac
from hashlib import sha256
from Crypto.Cipher import AES

from .crypto import CryptoEngine
from .cipher_string import cipher_string_from_protected_key

# support handling the BitWarden CLI's session keys in the following format:
#     - session_key:   base64(<encryption_key:32><mac_key:32>)
#         this value is stored in the ${BW_SESSION} environment variable
#     - protected_key: see bitwarden.pretty.cipher_string_from_protected_key

class SessionKey:
    def __init__(self, session_key: str, protected_key: str):
        self.encryption_key, self.mac_key = self.decode_session_key(session_key)
        self.protected_key = self.decode_protected_key(protected_key)
        self.user_key = self.decrypt_session_keys()

    @staticmethod
    def decode_session_key(key_b64: str) -> Tuple[bytes, bytes]:
        k = base64.b64decode(key_b64)
        assert(len(k) == 64)

        encryption_key = k[:32]
        mac_key        = k[32:]

        return encryption_key, mac_key

    @staticmethod
    def decode_protected_key(key_b64: str) -> Tuple[int, bytes, bytes, bytes]:
        return cipher_string_from_protected_key(key_b64)

    def decrypt_session_keys(self) -> bytes:
        user_key = CryptoEngine.decrypt_cipher_string(self.encryption_key, self.mac_key, self.protected_key)
        assert(len(user_key) == 32)

        return user_key
