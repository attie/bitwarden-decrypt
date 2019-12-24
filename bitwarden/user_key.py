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
#
# where <kdf> is 0, i.e: AesCbc256_B64 (jslib/src/enums/encryptionType.ts)
# we don't currently support any other modes

class UserKey:
    def __init__(self, email: str, master_password: str, kdf: int, kdf_iterations: int):
        self.user_key = self.decrypt_user_key(email, master_password, kdf, kdf_iterations)

    def build_user_key(self, password: str, salt: str, mode: str, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac(mode, password, salt, iterations)

    def decrypt_user_key(self, email: str, master_password: str, kdf: int, kdf_iterations: int) -> bytes:
        assert(kdf == 0)
        kdf = 'sha256'

        # encryption key, no mac key
        #   password   = Master Password
        #   salt       = Email
        #   mode       = Kdf
        #   iterations = KdfIterations
        key = self.build_user_key(master_password, email, kdf, kdf_iterations)

        return key
