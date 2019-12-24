from typing import Tuple
import base64
import hmac
from hashlib import sha256
from Crypto.Cipher import AES

from .crypto import CryptoEngine

# support handling the BitWarden CLI's session keys in the following format:
#     - session_key:   base64(<encryption_key:32><mac_key:32>)
#         this value is stored in the ${BW_SESSION} environment variable
#     - protected_key: base64(<enc_type:1><iv:16><mac:32><data:n>)
#         this value is stored in the user's '~/.config/Bitwarden CLI/data.json' under
#         the path '.__PROTECTED__key'
#
# where <enc_type> is 2, i.e: AesCbc256_HmacSha256_B64 (jslib/src/enums/encryptionType.ts)
# we don't currently support any other modes

class SessionKey:
    def __init__(self, session_key: str, protected_key: str):
        self.encryption_key, self.mac_key = self.decode_session_key(session_key)
        self.enc_type, self.iv, self.mac, self.data = self.decode_protected_key(protected_key)
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
        k = base64.b64decode(key_b64)
        assert(len(k) > 49)

        enc_type = k[0]
        iv       = k[1:17]
        mac      = k[17:49]
        data     = k[49:]

        return enc_type, iv, mac, data

    def decrypt_session_keys(self) -> bytes:
        assert(self.enc_type == 2)

        user_key = CryptoEngine.decrypt_cipher_string(self.encryption_key, self.mac_key, self.iv, self.mac, self.data)
        assert(len(user_key) == 32)

        return user_key
