#!/usr/bin/env python3

# ref
# - https://help.bitwarden.com/article/what-encryption-is-used/

from bitwarden.util import load_json
from bitwarden.session_key import SessionKey
from bitwarden.user_key import UserKey
from bitwarden.crypto_engine import CryptoEngine

# ---

j = load_json('/tmp/bw/info.json')

master_password = j['master_password'].encode('utf-8')
session_key = j['session_key']
protected_key = j['protected_key']

# ---
# Deal with BitWarden session keys

sk = SessionKey(session_key, protected_key)
encryption_key = sk.user_key

# ---
# Deal with BitWarden master password & encrypted key

user_data = load_json('/tmp/bw/user_data.json')

email = user_data['Email'].encode('utf-8')
kdf = user_data['Kdf']
kdf_iterations = user_data['KdfIterations']
uk = UserKey(email, master_password, kdf, kdf_iterations)
encryption_key2 = uk.user_key

assert(encryption_key == encryption_key2)

# ---
# Setup the CryptoEngine to deal with decrypting the data

ce = CryptoEngine(encryption_key, user_data['Key'])

ciphers = load_json('/tmp/bw/user_ciphers.json')
thing = ciphers[0]['Data']['Name']
plaintext = ce.decrypt(thing)

print('%s' % ( plaintext.decode('utf-8') ))
