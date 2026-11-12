from pathlib import Path

from digital_signature import (
    generate_keys,
    load_private_key,
    load_public_key,
    save_keys,
    sign,
    verify,
)


def test_valid_signature():
    priv, pub = generate_keys()
    data = b"hello"
    assert verify(pub, data, sign(priv, data))


def test_tampered_data_fails():
    priv, pub = generate_keys()
    sig = sign(priv, b"hello")
    assert not verify(pub, b"hellO", sig)


def test_wrong_key_fails():
    priv, _ = generate_keys()
    _, other_pub = generate_keys()
    assert not verify(other_pub, b"hello", sign(priv, b"hello"))


def test_keys_round_trip(tmp_path: Path):
    priv, pub = generate_keys()
    save_keys(priv, pub, tmp_path, password=b"secret")
    priv2 = load_private_key(tmp_path / "private_key.pem", b"secret")
    pub2 = load_public_key(tmp_path / "public_key.pem")
    assert verify(pub2, b"data", sign(priv2, b"data"))
