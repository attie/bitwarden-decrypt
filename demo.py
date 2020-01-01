#!/usr/bin/env python3

from getpass import getpass

from bitwarden.util import load_user_data
from bitwarden.user_key import UserKey
from bitwarden.crypto_engine import CryptoEngine

user_data = load_user_data()

# gather data
email = user_data['userEmail'].encode('utf-8')
kdf = user_data['kdf']
kdf_iterations = user_data['kdfIterations']
master_password = getpass().encode('utf-8')

# grab a secret
ciphers_key = 'ciphers_%s' % ( user_data['userId'] )
ciphers = iter(user_data[ciphers_key].values())
thing = next(ciphers)['name']

# produce the encryption key
uk = UserKey(email, master_password, kdf, kdf_iterations)
encryption_key = uk.user_key

# decrypt the secret
ce = CryptoEngine(encryption_key, user_data['encKey'])
plaintext = ce.decrypt(thing)
print('%s' % ( plaintext.decode('utf-8') ))
