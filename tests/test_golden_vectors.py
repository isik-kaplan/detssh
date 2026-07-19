import csv
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.salt import ALGOS as SALT_ALGOS
from detssh.keygen import keypair_from_seed


GOLDEN_DIR = Path(__file__).parent / "golden"

SEED_PASSPHRASE = "correct horse battery staple"
LABEL = "golden-vector"
SALT_DIGEST_SIZE = 16
HASH_LEN = 32

FAST_KDF_PARAMS = {
    "argon2id": {"iterations": 1, "memory": 8, "parallelism": 1},
    "argon2i": {"iterations": 1, "memory": 8, "parallelism": 1},
    "argon2d": {"iterations": 1, "memory": 8, "parallelism": 1},
    "scrypt": {"cost": 2, "block_size": 1, "parallelism": 1},
    "pbkdf2": {"iterations": 1},
    "bcrypt_pbkdf": {"rounds": 1},
}


def _read_csv(name):
    with open(GOLDEN_DIR / name, newline="") as f:
        return list(csv.DictReader(f))


VECTORS = _read_csv("vectors.csv")
VARIATIONS = _read_csv("variations.csv")


def test_vectors_cover_every_registered_combination():
    expected = {(kdf_name, salt_name) for kdf_name in KDF_BACKENDS for salt_name in SALT_ALGOS}
    actual = {(row["kdf"], row["salt_algo"]) for row in VECTORS}
    assert actual == expected


@pytest.mark.parametrize("row", VECTORS, ids=lambda row: f"{row['kdf']}-{row['salt_algo']}")
def test_golden_vector(row):
    kdf_cls = KDF_BACKENDS[row["kdf"]]
    salt_cls = SALT_ALGOS[row["salt_algo"]]

    resolved = {
        "seed": SEED_PASSPHRASE,
        "label": LABEL,
        "hash_len": HASH_LEN,
        "salt_digest_size": SALT_DIGEST_SIZE,
    }
    resolved.update(FAST_KDF_PARAMS[row["kdf"]])

    salt = salt_cls.digest(LABEL, resolved)
    seed_bytes = kdf_cls.run(resolved, salt)
    assert seed_bytes.hex() == row["seed_hex"]

    _, public_key = keypair_from_seed(seed_bytes)
    public_key_line = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    assert public_key_line == row["public_key"]


ARGON2_NAMES = ("argon2id", "argon2i", "argon2d")


def _knob_group(kdf_name):
    return "argon2" if kdf_name in ARGON2_NAMES else kdf_name


PARAM_PRESETS = {
    "small": {
        "hash_len": 16,
        "salt_digest_size_choice": "min",
        "argon2": {"iterations": 2, "memory": 16, "parallelism": 1},
        "scrypt": {"cost": 4, "block_size": 2, "parallelism": 1},
        "pbkdf2": {"iterations": 2},
        "bcrypt_pbkdf": {"rounds": 2},
    },
    "large": {
        "hash_len": 64,
        "salt_digest_size_choice": "max",
        "argon2": {"iterations": 3, "memory": 32, "parallelism": 2},
        "scrypt": {"cost": 8, "block_size": 4, "parallelism": 2},
        "pbkdf2": {"iterations": 4},
        "bcrypt_pbkdf": {"rounds": 4},
    },
}


def _salt_digest_size_for(preset, kdf_cls, salt_cls):
    if not salt_cls.is_variable():
        return SALT_DIGEST_SIZE
    choice = preset["salt_digest_size_choice"]
    if choice == "max":
        return salt_cls.max_digest_size
    floor = kdf_cls.salt_constraints.min_size or 0
    return max(salt_cls.min_digest_size, floor)


def test_variations_cover_every_combination():
    expected = {
        (preset_name, kdf_name, salt_name)
        for preset_name in PARAM_PRESETS
        for kdf_name in KDF_BACKENDS
        for salt_name in SALT_ALGOS
    }
    actual = {(row["preset"], row["kdf"], row["salt_algo"]) for row in VARIATIONS}
    assert actual == expected


@pytest.mark.parametrize("row", VARIATIONS, ids=lambda row: f"{row['preset']}-{row['kdf']}-{row['salt_algo']}")
def test_golden_param_variation(row):
    preset = PARAM_PRESETS[row["preset"]]
    kdf_cls = KDF_BACKENDS[row["kdf"]]
    salt_cls = SALT_ALGOS[row["salt_algo"]]

    salt_digest_size = _salt_digest_size_for(preset, kdf_cls, salt_cls)
    assert salt_digest_size == int(row["salt_digest_size"])

    resolved = {
        "seed": SEED_PASSPHRASE,
        "label": LABEL,
        "hash_len": preset["hash_len"],
        "salt_digest_size": salt_digest_size,
    }
    resolved.update(preset[_knob_group(row["kdf"])])

    salt = salt_cls.digest(LABEL, resolved)
    seed_bytes = kdf_cls.run(resolved, salt)
    assert seed_bytes.hex() == row["seed_hex"]
