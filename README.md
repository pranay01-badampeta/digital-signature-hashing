# Digital Signature System with SHA-256 and RSA

A command-line tool that signs files and verifies their signatures, so you can prove who created a file and detect any change to it.

## How it works

1. **Key generation:** a 2048-bit RSA key pair. The private key can be password-protected.
2. **Hashing:** the file is hashed with SHA-256, so even a one-byte change produces a completely different digest.
3. **Signing:** the digest is signed with the private key using RSA-PSS padding.
4. **Verification:** anyone with the public key can check that the file matches the signature. A changed file, a changed signature or the wrong key all fail.

```
file ──SHA-256──► digest ──RSA sign (private key)──► signature
file + signature ──RSA verify (public key)──► VALID / INVALID
```

## Run it

```bash
pip install -r requirements.txt

python digital_signature.py demo                       # end-to-end demo

python digital_signature.py keygen --out keys/ --password mypass
python digital_signature.py sign   --key keys/private_key.pem --file report.pdf --password mypass
python digital_signature.py verify --key keys/public_key.pem  --file report.pdf --sig report.pdf.sig
```

## Tests

```bash
pytest
```

The tests check that a valid signature verifies, and that tampered data or the wrong key are rejected.

## Tech

Python · `cryptography` (RSA, PSS padding) · `hashlib` (SHA-256) · pytest
