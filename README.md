This is an absolute minimal example of using a nitrokey or similar security key as a license token.

The idea is to ask a smart card to sign a challenge, and to check that the signature it produces is valid. Allowing access to the protected features only after verification is successfull.

# USAGE:

1. edit the nitrokey to select the correct curve
```
gpg --card-edit
gpg/card> admin
gpg/card> key-attr
```
 * select the ed25519 curve

2. generate a new key
```
gpg --card-edit
gpg/card> admin
gpg/card> generate
```
 * follow the prompts
 * do not store a local copy

3. find the fingerprint.
```
gpg --list-keys should now show the key.
the long hex string is the fingerprint
```

4. extract the pubkey from gpg
```
gpg --armor --export <fingerprint> > pub.gpg

cat <<EOF | python3
from pgpy import PGPKey;
pubkey, _ = PGPKey.from_blob(open('pub.gpg').read());
print(','.join([f'0x{b:02x}' for b in pubkey._key.keymaterial.p.x]))
EOF
```

5. test it.
update the pubkey and fingerprint in main.c. recompile and run.
This tool links against curve25519 (https://github.com/msotoodeh/curve25519.git) and winscard (Windows) or pcsclite (Linux).
This tool will find a smartcard and key with the corresponding fingerprint and issue a challenge.
It will then check the response.

* compile with make
* automatically clones curve25519

# TODO

* implement decryption
  - to further increase security you could ask the smartcard to decrypt some data vital to the protected features. fi. a portion of the executable
