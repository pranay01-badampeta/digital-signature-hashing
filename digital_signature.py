"""Digital signatures with SHA-256 hashing and RSA.

Generates an RSA key pair, signs a file's SHA-256 digest with the private key
(RSA-PSS padding) and verifies the signature with the public key, so any change
to the file or the signature is detected.

Usage:
    python digital_signature.py keygen --out keys/
    python digital_signature.py sign   --key keys/private_key.pem --file contract.pdf
    python digital_signature.py verify --key keys/public_key.pem  --file contract.pdf --sig contract.pdf.sig
    python digital_signature.py demo
"""
import argparse
import hashlib
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_keys(bits: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private_key, private_key.public_key()


def save_keys(private_key, public_key, out_dir: Path, password: bytes | None = None):
    out_dir.mkdir(parents=True, exist_ok=True)
    encryption = (
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    (out_dir / "private_key.pem").write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )
    )
    (out_dir / "public_key.pem").write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def load_private_key(path: Path, password: bytes | None = None):
    return serialization.load_pem_private_key(path.read_bytes(), password=password)


def load_public_key(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def sign(private_key, data: bytes) -> bytes:
    """Sign the SHA-256 hash of the data with RSA-PSS."""
    return private_key.sign(data, PSS, hashes.SHA256())


def verify(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def demo():
    print("1. Generating a 2048-bit RSA key pair")
    priv, pub = generate_keys()
    message = b"Transfer 500 EUR to account FR76 3000 6000 0112 3456 7890 189"
    print(f"2. Message: {message.decode()}")
    print(f"   SHA-256: {hashlib.sha256(message).hexdigest()}")
    sig = sign(priv, message)
    print(f"3. Signature ({len(sig)} bytes): {sig.hex()[:64]}...")
    print(f"4. Verify original message:  {'VALID' if verify(pub, message, sig) else 'INVALID'}")
    tampered = message.replace(b"500", b"900")
    print(f"5. Verify tampered message:  {'VALID' if verify(pub, tampered, sig) else 'INVALID'}")
    other_priv, other_pub = generate_keys()
    print(f"6. Verify with another key:  {'VALID' if verify(other_pub, message, sig) else 'INVALID'}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="create a key pair")
    k.add_argument("--out", default="keys")
    k.add_argument("--bits", type=int, default=2048)
    k.add_argument("--password", default=None, help="encrypt the private key with this password")

    s = sub.add_parser("sign", help="sign a file")
    s.add_argument("--key", required=True)
    s.add_argument("--file", required=True)
    s.add_argument("--password", default=None)

    v = sub.add_parser("verify", help="verify a file's signature")
    v.add_argument("--key", required=True)
    v.add_argument("--file", required=True)
    v.add_argument("--sig", required=True)

    sub.add_parser("demo", help="run an end-to-end demo in memory")
    args = p.parse_args()

    if args.cmd == "keygen":
        priv, pub = generate_keys(args.bits)
        save_keys(priv, pub, Path(args.out), args.password.encode() if args.password else None)
        print(f"Keys written to {args.out}/ (keep private_key.pem secret)")
    elif args.cmd == "sign":
        priv = load_private_key(Path(args.key), args.password.encode() if args.password else None)
        path = Path(args.file)
        sig = sign(priv, path.read_bytes())
        sig_path = path.with_name(path.name + ".sig")
        sig_path.write_bytes(sig)
        print(f"SHA-256 {sha256_file(path)}\nSignature written to {sig_path}")
    elif args.cmd == "verify":
        ok = verify(load_public_key(Path(args.key)), Path(args.file).read_bytes(), Path(args.sig).read_bytes())
        print("VALID: the file is authentic and unchanged." if ok else "INVALID: the file or signature was altered.")
        sys.exit(0 if ok else 1)
    else:
        demo()


if __name__ == "__main__":
    main()
