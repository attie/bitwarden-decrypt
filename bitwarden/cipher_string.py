from collections import namedtuple
from base64 import b64decode

cipher_string_fields = {
    'enc_type': lambda enc_type,iv,mac,data: int(enc_type),
    'iv':       lambda enc_type,iv,mac,data: iv,
    'mac':      lambda enc_type,iv,mac,data: mac,
    'data':     lambda enc_type,iv,mac,data: data,
}
CipherString = namedtuple('CipherString', cipher_string_fields.keys())

# support pulling apart a BitWarden 'CipherString' from the following
#     - cipher string: "<enc_type>.<iv>|<data>|<mac>"
def cipher_string_from_str(cipher_string: str) -> CipherString:
    enc_type, _ = cipher_string.split('.', 1)
    iv, data, mac = ( b64decode(_) for _ in _.split('|', 2) )

    d = { k: fn(enc_type, iv, mac, data) for k,fn in cipher_string_fields.items() }
    return CipherString(**d)

# support pulling apart the BitWarden CLI's protected session key from the following format:
#     - protected_key: base64(<enc_type:1><iv:16><mac:32><data:n>)
#         this value is stored in the user's '~/.config/Bitwarden CLI/data.json' under
#         the path '.__PROTECTED__key'
def cipher_string_from_protected_key(protected_key: str) -> CipherString:
    b = b64decode(protected_key)
    assert(len(b) > 49)

    d = { k: fn(b[0], b[1:17], b[17:49], b[49:]) for k,fn in cipher_string_fields.items() }
    return CipherString(**d)
