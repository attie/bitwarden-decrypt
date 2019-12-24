from typing import Union, Tuple
from hashlib import sha256
from Crypto.Cipher import AES
from hmac import new as hmac_new
from hkdf import hkdf_expand

from .cipher_string import CipherString

# handles expanding and iterating the user's key into both the
# encryption key and message authentication key
# once setup, the class supports decrypting BitWarden 'CipherString'
# data, either presented as a str, or a CipherString

class CryptoEngine:
    def __init__(self, encryption_key: bytes, user_key: Union[str, CipherString]):
        self.key_enc, self.key_mac = self.decrypt_keys(encryption_key, user_key)

    @staticmethod
    def decrypt3(key_enc: bytes, key_mac: bytes, iv: bytes, mac: bytes, data: bytes) -> bytes:
        # verify the MAC
        mac_data = iv + data
        r = hmac_new(key_mac, mac_data, sha256)
        assert(mac == r.digest())

        # decrypt the content
        c = AES.new(key_enc, AES.MODE_CBC, iv)
        plaintext = c.decrypt(data)

        # remove PKCS#7 padding from payload, see RFC 5652
        # https://tools.ietf.org/html/rfc5652#section-6.3
        padding = bytes([ plaintext[-1] ] * plaintext[-1])
        if plaintext[-len(padding):] == padding:
            plaintext = plaintext[:-len(padding)]

        return plaintext

    @classmethod
    def decrypt2(cls, cipher_string: Union[str, CipherString], key_enc: bytes, key_mac: bytes) -> bytes:
        if isinstance(cipher_string, str):
            cipher_string = CipherString(cipher_string)

        assert(isinstance(cipher_string, CipherString))
        assert(cipher_string.enc_type == 2)

        plaintext = cls.decrypt3(key_enc, key_mac, cipher_string.iv, cipher_string.mac, cipher_string.data)
        return plaintext
    
    @classmethod
    def decrypt_keys(cls, encryption_key: bytes, user_key: Union[str, CipherString]) -> Tuple[bytes, bytes]:
        # stretch / expand the encryption key
        tmp_key_enc = hkdf_expand(encryption_key, b'enc', 32, sha256)
        tmp_key_mac = hkdf_expand(encryption_key, b'mac', 32, sha256)

        plaintext = cls.decrypt2(user_key, tmp_key_enc, tmp_key_mac)
        assert(len(plaintext) == 64)

        # split out the real keys
        key_enc = plaintext[:32]
        key_mac = plaintext[32:]

        return key_enc, key_mac

    def decrypt(self, cipher_string: Union[str, CipherString]) -> bytes:
        return self.decrypt2(cipher_string, self.key_enc, self.key_mac)
