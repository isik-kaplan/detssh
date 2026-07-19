import pytest
from cryptography.hazmat.primitives import serialization

from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.kdf.argon2i import Argon2I
from detssh.backends.kdf.argon2id import Argon2Id
from detssh.backends.kdf.base import KDFError
from detssh.backends.salt import ALGOS as SALT_ALGOS
from detssh.backends.salt.blake2b import Blake2b
from detssh.keygen import keypair_from_seed


def _resolved(seed, label="", **overrides):
    resolved = {
        "seed": seed,
        "label": label,
        "iterations": 1,
        "memory": 8,
        "parallelism": 1,
        "hash_len": 32,
        "salt_digest_size": 16,
    }
    resolved.update(overrides)
    return resolved


def _derive(seed, label="", **overrides):
    resolved = _resolved(seed, label, **overrides)
    salt = Blake2b.digest(resolved["label"], resolved)
    return Argon2Id.run(resolved, salt)


def _raw_private(key):
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _raw_public(key):
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_same_inputs_produce_same_seed():
    a = _derive("correct horse battery staple")
    b = _derive("correct horse battery staple")
    assert a == b


def test_different_label_produces_different_seed():
    a = _derive("correct horse battery staple", label="github")
    b = _derive("correct horse battery staple", label="gitlab")
    assert a != b


def test_different_passphrase_produces_different_seed():
    a = _derive("correct horse battery staple")
    b = _derive("correct horse battery staplf")
    assert a != b


def test_keypair_from_seed_is_deterministic():
    seed = _derive("correct horse battery staple")
    priv1, pub1 = keypair_from_seed(seed)
    priv2, pub2 = keypair_from_seed(seed)

    assert _raw_private(priv1) == _raw_private(priv2)
    assert _raw_public(pub1) == _raw_public(pub2)


def test_keypair_from_seed_rejects_wrong_length():
    with pytest.raises(ValueError):
        keypair_from_seed(b"too-short")


def test_different_argon2_variant_produces_different_seed():
    resolved = _resolved("correct horse battery staple")
    salt = Blake2b.digest(resolved["label"], resolved)
    a = Argon2Id.run(resolved, salt)
    b = Argon2I.run(resolved, salt)
    assert a != b


def test_different_salt_digest_size_produces_different_seed():
    a = _derive("correct horse battery staple", salt_digest_size=16)
    b = _derive("correct horse battery staple", salt_digest_size=32)
    assert a != b


def test_every_kdf_backend_declares_salt_constraints():
    for backend in KDF_BACKENDS.values():
        assert backend.salt_constraints is not None


def test_every_salt_algo_produces_correct_length():
    for algo in SALT_ALGOS.values():
        resolved = {"salt_digest_size": 16}
        digest = algo.digest("some-label", resolved)
        expected = 16 if algo.is_variable() else algo.digest_size
        assert len(digest) == expected


def test_argon2_rejects_too_short_salt():
    assert Argon2Id.salt_constraints.error_for(7) is not None
    assert Argon2Id.salt_constraints.error_for(8) is None


def test_scrypt_and_pbkdf2_accept_any_salt_length():
    scrypt = KDF_BACKENDS["scrypt"]
    pbkdf2 = KDF_BACKENDS["pbkdf2"]
    assert scrypt.salt_constraints.error_for(0) is None
    assert pbkdf2.salt_constraints.error_for(0) is None


def test_scrypt_raises_kdf_error_for_non_power_of_two_cost():
    resolved = _resolved("correct horse battery staple", cost=100, block_size=8, parallelism=1)
    with pytest.raises(KDFError):
        KDF_BACKENDS["scrypt"].run(resolved, b"0" * 16)


def test_argon2_raises_kdf_error_for_memory_too_low():
    resolved = _resolved("correct horse battery staple", memory=1, parallelism=999)
    with pytest.raises(KDFError):
        Argon2Id.run(resolved, b"0" * 16)


def test_pbkdf2_raises_kdf_error_for_non_positive_iterations():
    resolved = _resolved("correct horse battery staple", iterations=-5)
    with pytest.raises(KDFError):
        KDF_BACKENDS["pbkdf2"].run(resolved, b"0" * 16)


def test_bcrypt_pbkdf_raises_kdf_error_for_zero_rounds():
    resolved = _resolved("correct horse battery staple", rounds=0)
    with pytest.raises(KDFError):
        KDF_BACKENDS["bcrypt_pbkdf"].run(resolved, b"0" * 16)
