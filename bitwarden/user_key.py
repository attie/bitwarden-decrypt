import hashlib

# support handling the BitWarden user key in the following format:
#     - email:           str
#         this value is stored in the user's '~/.config/Bitwarden CLI/data.json' under
#         the path '.userEmail'
#     - master_password: str
#         this is the user's master password, and should not be persistently stored
#         prompt the user for input
#     - kdf:             int
#         this value is stored in the user's '~/.config/Bitwarden CLI/data.json' under
#         the path '.kdf'
#     - kdf_iteratinos:  int
#         this value is stored in the user's '~/.config/Bitwarden CLI/data.json' under
#         the path '.kdfIterations'

class UserKey:
    def __init__(self, email: str, master_password: str, kdf: int, kdf_iterations: int):
        self.user_key = self.decrypt_user_key(email, master_password, kdf, kdf_iterations)

    def decrypt_user_key(self, email: str, master_password: str, kdf: int, kdf_iterations: int) -> bytes:
        # where <kdf> is 0, i.e: AesCbc256_B64 (jslib/src/enums/encryptionType.ts)
        # we don't currently support any other modes
        assert(kdf == 0)
        kdf = 'sha256'

        # encryption key, no mac key
        #   password   = Master Password
        #   salt       = Email
        #   mode       = Kdf
        #   iterations = KdfIterations
        key = hashlib.pbkdf2_hmac(kdf, master_password, email, kdf_iterations)

        return key
