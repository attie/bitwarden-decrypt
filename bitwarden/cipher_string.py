from typing import Tuple
from base64 import b64decode

# helps to pull apart a BitWarden 'CipherString' in the following format into
# its constituent parts
#     - cipher string: "<enc_type>.<iv>|<data>|<mac>"
#
# where <enc_type> is 2, i.e: AesCbc256_HmacSha256_B64 (jslib/src/enums/encryptionType.ts)
# we don't currently support any other modes

class CipherString:
    def __init__(self, cipher_string: str):
        self.enc_type, self.iv, self.data, self.mac = self.split(cipher_string)

    @staticmethod
    def split(cipher_string: str) -> Tuple[int, bytes, bytes, bytes]:
        enc_type, _ = cipher_string.split('.', 1)
        iv, data, mac = ( b64decode(_) for _ in _.split('|', 2) )
        return int(enc_type), iv, data, mac
