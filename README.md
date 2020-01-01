# Decrypting Bitwarden Secrets

I've set out to understand how [Bitwarden](https://bitwarden.com/) keeps secrets, with an end goal of decrypting them.
I am working with _my_ secrets, and I obviously know _my_ passphrase - this is not a demonstration of a weakness or vulnerability.
Additionally, I am not a cryptographic expert, so this should not be considered a review for strength or integrity.

You are able to get hold of the encrypted secrets with suitable access to the MSSQL server, and the secrets are held by clients in the same state.
For this reason, I am reviewing the [command line interface](https://github.com/bitwarden/cli) sources - the server has nothing to give on this front.

## Anatomy of a Secret

First of all, we have to understand what a Bitwarden secret looks like - they refer to them as a "_[CipherString](https://github.com/bitwarden/jslib/blob/57e49207e9ad57c71576fc487a38513a4d0fe120/src/models/domain/cipherString.ts)_".

Fundamentally, a `CipherString` contains the following information:

- `encType` - the encryption type used for this secret
    - A numeric ASCII representation of the [`EncryptionType`](https://github.com/bitwarden/jslib/blob/57e49207e9ad57c71576fc487a38513a4d0fe120/src/enums/encryptionType.ts) enum
- `ciphertext` - the encrypted payload
- `iv` - the initialization vector (optional)
- `mac` - the message authentication code (optional)

The `ciphertext`, `iv` and `mac` fields are encoded using base64.

All of my secrets appear to have all of these fields present, I imagine that secrets produced with an older client may not.

The `encType` field is separated from the rest of the string using a period (`.`), while the others are separated from each other using a pipe (`|`).

To get an example `CipherString`, run:

```bash
jq -r '."ciphers_\(.userId)" | to_entries | .[0].value.name' < '~/.config/Bitwarden CLI/data.json'
```

The user's encryption and message authentication keys are also stored in this format:

```bash
jq -r '.encKey' < '~/.config/Bitwarden CLI/data.json'
```

![Anatomy of a Secret](/diagrams/anatomy-of-a-secret.png)

## Protected Session Data

The command line client also stores sensitive run-time data in the JSON datastore using a `__PROTECTED__` prefix (for example `__PROTECTED__key`).

```bash
jq -r '.__PROTECTED__key' < '~/.config/Bitwarden CLI/data.json'
```

This data is the same as the secrets described above, but for some reason has been stored as a base64-encoded blob with the fields shuffled.
Sensitive data stored in this format can be decrypted using keys provided in the `${BW_SESSION}` variable.

![Anatomy of Session Data](/diagrams/anatomy-of-session-data.png)

## Derive / Stretch / Expand the Keys

Before we can go any further, we must produce two keys - the "_Encryption Key_", and the "_Message Authentication Key_".

!!! bug
    At this point, I'd like to voice my opinion that the Bitwarden sources are quite tangled and overly complex.
    This isn't a problem in itself, though does open the possibility for mis-handling data when passing things around the application.
    It took me quite some time to produce a functional model of the procedure, and this wasn't helped by the naming scheme...
    There are a number of "_keys_" coming up, and they do not have clear / unambiguous names in the Bitwarden sources.
    My first attempt to do this a few months ago failed, largely due to this.
    I'll try to keep them clear here.

This write up doesn't cover generating and encrypting the keys to begin with, but does outline the steps required to re-produce the keys.

There are two methods to produce the "_Source Key_" - used to derive keys that provide access to the "_Encryption Key_" and "_Message Authentication Key_".

1. Using `__PROTECTED__key` (see above) and the `${BW_SESSION}` environment variable
   These are setup / provided when you run `bw unlock`, and removed when you run `bw lock`
2. Using the master password, the user's email, and the appropriate Key Derivation Function (KDF)

The following diagram omits verification for brevity.

![Key Flow](/diagrams/key-flow.png)

### Derive "_Source Key_" from Protected Session Data

!!! tip
    Before attempting to follow this, you must run `bw unlock`, and have the `__PROTECTED__key` and `${BW_SESSION}` variables.

The `${BW_SESSION}` variable is a 64-byte value that is encoded using base64 - it holds the intermediate keys that allow access to the data in `__PROTECTED__key`.
The first 32-bytes are the encryption key, the last 32-bytes are the message authentication key.

#### Verify

To verify the session, concatenate the `iv`, and `ciphertext`, and feed it through a HMAC SHA-256, along with the message authentication key.
The output should match the 32-byte message authentication code held in the `__PROTECTED__key`.

![Verify Session](/diagrams/session-verify.png)

#### Decrypt

To Decrypt the "_Source Key_", take the `iv` and `ciphertext`, and feed them into an AES-256 CBC, using the encryption key from `${BW_SESSION}`.
Don't forget to discard the padding.

![Decrypt Session](/diagrams/session-decrypt.png)

### Derive "_Source Key_" from User Data

If you instead have access to the user's master password and email, you can produce the "_Source Key_" from there instead using PBKDF2 / SHA-256.

In this situation, the user's email address is used as the salt, and their master password is used as the passphrase.
The iteration count is stored in the user's data and defaults to 100,000 (but it is configurable).

![User Key](/diagrams/user-key.png)

### Derive Intermediate Keys from "_Source Key_"

Once you've got the "_Source Key_", you must derive the intermediate encryption and message authentication keys.
The keys are derived using the HKDF Expand, with SHA-256, and thus output length of 32-bytes.

- Intermediate encryption key - using an "_info_" input of `b'enc'`
- Intermediate message authentication key - using an "_info_" input of `b'mac'`

![Derive Intermediate Keys](/diagrams/derive-intermediate-keys.png)

### Decrypt the User's Final Keys

Using the intermediate keys produced above, it is possible to decrypt the user's actual keys - both for encryption and message authentication.
The secret (a standard `CipherString`) is stored in the `.encKey` variable of `~/.config/Bitwarden CLI/data.json`.

The procedure is exactly the same as all other secrets, but uses the intermediate keys instead of the user's final keys.

The decrypted value should be 64-bytes in length - a 32-byte encryption key, followed by a 32-byte message authentication key.

![Final Keys](/diagrams/final-keys.png)

## Verify a Secret

To verify a secret, use the appropriate message authentication key, along with the other elements of the `CipherString`.

As before, the IV and Ciphertext should be concatenated.

![Verify a Secret](/diagrams/secret-verify.png)

## Decrypt a Secret

Finally, to decrypt a secret, use the appropriate encryption key, along with the other elements of the `CipherString`.

![Decrypt a Secret](/diagrams/secret-decrypt.png)

## Summary

I have produced a python library to aid in decrypting Bitwarden secrets, available on [GitHub](https://github.com/attie/bitwarden-decrypt).

An example utility to decrypt the name of the first entry is given below:

```python
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
```
