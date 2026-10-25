import hashlib
import os
import string
import tempfile
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from detssh.backends.base import (
    _display_path,
    confirm_create_parent_dirs,
    confirm_overwrite,
    note_if_exists,
    write_keypair_and_recap,
)
from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.kdf import validate_backends
from detssh.backends.kdf.base import KDFBackend, KDFError, SaltConstraints
from detssh.backends.salt import ALGOS as SALT_ALGOS
from detssh.backends.salt import validate_algos
from detssh.backends.salt.base import SaltAlgo, SaltError
from detssh.cli import main
from detssh.keygen import (
    COMMENT_FORBIDDEN_CHARS,
    ED25519_SEED_LENGTH,
    keypair_from_seed,
    public_key_path,
    ssh_dir,
    write_keypair,
)


FAST_KDF_PARAMS = {
    "argon2id": {"iterations": 1, "memory": 8, "parallelism": 1},
    "argon2i": {"iterations": 1, "memory": 8, "parallelism": 1},
    "argon2d": {"iterations": 1, "memory": 8, "parallelism": 1},
    "scrypt": {"cost": 2, "block_size": 1, "parallelism": 1},
    "pbkdf2": {"iterations": 1},
    "bcrypt_pbkdf": {"rounds": 1},
}

VARIABLE_SALT_ALGOS = [algo for algo in SALT_ALGOS.values() if algo.is_variable()]
FIXED_SALT_ALGOS = [algo for algo in SALT_ALGOS.values() if not algo.is_variable()]


def _resolved(backend_name, seed, hash_len=32):
    resolved = {"seed": seed, "hash_len": hash_len}
    resolved.update(FAST_KDF_PARAMS[backend_name])
    return resolved


@given(size=st.integers(min_value=0, max_value=10**6), min_size=st.integers(min_value=0, max_value=10**6))
@settings(max_examples=8000)
def test_min_size_constraint(size, min_size):
    error = SaltConstraints(min_size=min_size).error_for(size)
    assert (error is not None) == (size < min_size)


@given(size=st.integers(min_value=0, max_value=10**6), max_size=st.integers(min_value=0, max_value=10**6))
@settings(max_examples=8000)
def test_max_size_constraint(size, max_size):
    error = SaltConstraints(max_size=max_size).error_for(size)
    assert (error is not None) == (size > max_size)


@given(size=st.integers(min_value=0, max_value=10**6), exact_size=st.integers(min_value=0, max_value=10**6))
@settings(max_examples=8000)
def test_exact_size_constraint(size, exact_size):
    error = SaltConstraints(exact_size=exact_size).error_for(size)
    assert (error is not None) == (size != exact_size)


@given(
    size=st.integers(min_value=0, max_value=10**6),
    min_size=st.integers(min_value=0, max_value=10**6),
    max_size=st.integers(min_value=0, max_value=10**6),
)
@settings(max_examples=8000)
def test_min_and_max_combine(size, min_size, max_size):
    error = SaltConstraints(min_size=min_size, max_size=max_size).error_for(size)
    assert (error is not None) == (size < min_size or size > max_size)


@given(size=st.integers(min_value=0, max_value=10**6))
@settings(max_examples=3000)
def test_no_constraints_never_errors(size):
    assert SaltConstraints().error_for(size) is None


@given(label=st.text())
@settings(max_examples=3000)
def test_fixed_salt_algo_length_is_constant(label):
    for algo in FIXED_SALT_ALGOS:
        assert len(algo.digest(label, {})) == algo.digest_size


@given(label=st.text())
@settings(max_examples=3000)
def test_variable_salt_algo_length_matches_request(label):
    for algo in VARIABLE_SALT_ALGOS:
        for digest_size in (algo.min_digest_size, algo.max_digest_size):
            resolved = {"salt_digest_size": digest_size}
            assert len(algo.digest(label, resolved)) == digest_size


@given(label=st.text(), digest_size=st.integers(min_value=1, max_value=64))
@settings(max_examples=3000)
def test_variable_salt_algo_length_matches_request_fuzzed(label, digest_size):
    for algo in VARIABLE_SALT_ALGOS:
        size = min(digest_size, algo.max_digest_size)
        resolved = {"salt_digest_size": size}
        assert len(algo.digest(label, resolved)) == size


@given(label=st.text())
@settings(max_examples=3000)
def test_salt_algo_digest_is_deterministic(label):
    resolved = {"salt_digest_size": 16}
    for algo in SALT_ALGOS.values():
        assert algo.digest(label, resolved) == algo.digest(label, resolved)


@given(label_a=st.text(), label_b=st.text())
@settings(max_examples=3000)
def test_different_labels_produce_different_salts(label_a, label_b):
    assume(label_a != label_b)
    resolved = {"salt_digest_size": 16}
    for algo in SALT_ALGOS.values():
        assert algo.digest(label_a, resolved) != algo.digest(label_b, resolved)


@given(label=st.text(), size_a=st.integers(min_value=1, max_value=32), size_b=st.integers(min_value=1, max_value=32))
@settings(max_examples=3000)
def test_different_digest_sizes_produce_different_salts(label, size_a, size_b):
    assume(size_a != size_b)
    for algo in VARIABLE_SALT_ALGOS:
        a = algo.digest(label, {"salt_digest_size": size_a})
        b = algo.digest(label, {"salt_digest_size": size_b})
        assert a != b


@given(label=st.text(), digest_size=st.integers(min_value=-1000, max_value=1000))
@settings(max_examples=1000)
def test_variable_salt_algo_never_leaks_a_raw_exception(label, digest_size):
    resolved = {"salt_digest_size": digest_size}
    for algo in VARIABLE_SALT_ALGOS:
        try:
            result = algo.digest(label, resolved)
        except SaltError:
            continue
        assert len(result) == digest_size


@given(raw_label=st.binary(min_size=0, max_size=20))
@settings(max_examples=500)
def test_every_salt_algo_never_leaks_a_raw_exception_for_argv_like_labels(raw_label):
    label = raw_label.decode("utf-8", "surrogateescape")
    resolved = {"salt_digest_size": 16}
    for algo in SALT_ALGOS.values():
        try:
            algo.digest(label, resolved)
        except SaltError:
            continue


@given(digest_size=st.integers(min_value=1, max_value=32))
@settings(max_examples=500)
def test_salt_algo_recap_reflects_resolved(digest_size):
    resolved = {"salt_digest_size": digest_size}
    for algo in SALT_ALGOS.values():
        recap = dict(algo.recap(resolved))
        if algo.is_variable():
            assert recap["salt-digest-size"] == digest_size
        else:
            assert recap == {}


@given(hash_len=st.integers(min_value=8, max_value=128))
@settings(max_examples=400, deadline=None)
def test_kdf_output_length_matches_hash_len(hash_len):
    salt = b"0" * 16
    for name, backend in KDF_BACKENDS.items():
        resolved = _resolved(name, "correct horse battery staple", hash_len=hash_len)
        assert len(backend.run(resolved, salt)) == hash_len


@given(seed=st.text(min_size=1, max_size=80))
@settings(max_examples=400, deadline=None)
def test_kdf_is_deterministic(seed):
    salt = b"0" * 16
    for name, backend in KDF_BACKENDS.items():
        resolved = _resolved(name, seed)
        assert backend.run(resolved, salt) == backend.run(resolved, salt)


@given(seed_a=st.text(min_size=1, max_size=40), seed_b=st.text(min_size=1, max_size=40))
@settings(max_examples=400, deadline=None)
def test_different_seeds_produce_different_output(seed_a, seed_b):
    assume(seed_a != seed_b)
    salt = b"0" * 16
    for name, backend in KDF_BACKENDS.items():
        a = backend.run(_resolved(name, seed_a), salt)
        b = backend.run(_resolved(name, seed_b), salt)
        assert a != b


@given(salt_a=st.binary(min_size=8, max_size=32), salt_b=st.binary(min_size=8, max_size=32))
@settings(max_examples=400, deadline=None)
def test_different_salts_produce_different_output(salt_a, salt_b):
    assume(salt_a != salt_b)
    for name, backend in KDF_BACKENDS.items():
        resolved = _resolved(name, "correct horse battery staple")
        a = backend.run(resolved, salt_a)
        b = backend.run(resolved, salt_b)
        assert a != b


@given(
    cost_exp=st.integers(min_value=1, max_value=6),
    block_size=st.integers(min_value=1, max_value=8),
    parallelism=st.integers(min_value=1, max_value=4),
)
@settings(max_examples=500, deadline=None)
def test_scrypt_maxmem_formula_never_underestimates(cost_exp, block_size, parallelism):
    scrypt = KDF_BACKENDS["scrypt"]
    resolved = _resolved("scrypt", "correct horse battery staple")
    resolved.update(cost=2**cost_exp, block_size=block_size, parallelism=parallelism)
    assert len(scrypt.run(resolved, b"0" * 16)) == resolved["hash_len"]


ARGON2_BACKENDS = [KDF_BACKENDS["argon2id"], KDF_BACKENDS["argon2i"], KDF_BACKENDS["argon2d"]]


@given(
    iterations=st.integers(min_value=1, max_value=100),
    memory=st.integers(min_value=1, max_value=100),
    parallelism=st.integers(min_value=1, max_value=16),
)
@settings(max_examples=300)
def test_argon2_recap_reflects_resolved_values(iterations, memory, parallelism):
    resolved = {"iterations": iterations, "memory": memory, "parallelism": parallelism}
    for backend in ARGON2_BACKENDS:
        recap = dict(backend.recap(resolved))
        assert recap["iterations"] == iterations
        assert recap["memory"] == f"{memory} MiB"
        assert recap["parallelism"] == parallelism


@given(
    cost=st.integers(min_value=1, max_value=1000),
    block_size=st.integers(min_value=1, max_value=100),
    parallelism=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=300)
def test_scrypt_recap_reflects_resolved_values(cost, block_size, parallelism):
    resolved = {"cost": cost, "block_size": block_size, "parallelism": parallelism}
    recap = dict(KDF_BACKENDS["scrypt"].recap(resolved))
    assert recap["cost (N)"] == cost
    assert recap["block-size (r)"] == block_size
    assert recap["parallelism (p)"] == parallelism


@given(iterations=st.integers(min_value=1, max_value=10**6))
@settings(max_examples=300)
def test_pbkdf2_recap_reflects_resolved_values(iterations):
    recap = dict(KDF_BACKENDS["pbkdf2"].recap({"iterations": iterations}))
    assert recap["iterations"] == iterations
    assert recap["prf"] == "sha256"


@given(rounds=st.integers(min_value=1, max_value=100))
@settings(max_examples=300)
def test_bcrypt_pbkdf_recap_reflects_resolved_values(rounds):
    recap = dict(KDF_BACKENDS["bcrypt_pbkdf"].recap({"rounds": rounds}))
    assert recap["rounds"] == rounds


@given(
    iterations=st.integers(min_value=-5, max_value=10),
    memory=st.integers(min_value=-5, max_value=64),
    parallelism=st.integers(min_value=-5, max_value=8),
)
@settings(max_examples=500, deadline=None)
def test_argon2_backends_never_leak_a_raw_exception(iterations, memory, parallelism):
    resolved = {
        "seed": "correct horse battery staple",
        "hash_len": 32,
        "iterations": iterations,
        "memory": memory,
        "parallelism": parallelism,
    }
    for backend in ARGON2_BACKENDS:
        try:
            result = backend.run(resolved, b"0" * 16)
        except KDFError:
            continue
        assert len(result) == 32


@given(
    cost=st.integers(min_value=-5, max_value=64),
    block_size=st.integers(min_value=-5, max_value=16),
    parallelism=st.integers(min_value=-5, max_value=4),
)
@settings(max_examples=500, deadline=None)
def test_scrypt_never_leaks_a_raw_exception(cost, block_size, parallelism):
    resolved = {
        "seed": "correct horse battery staple",
        "hash_len": 32,
        "cost": cost,
        "block_size": block_size,
        "parallelism": parallelism,
    }
    try:
        result = KDF_BACKENDS["scrypt"].run(resolved, b"0" * 16)
    except KDFError:
        return
    assert len(result) == 32


@given(iterations=st.integers(min_value=-5, max_value=50))
@settings(max_examples=300, deadline=None)
def test_pbkdf2_never_leaks_a_raw_exception(iterations):
    resolved = {"seed": "correct horse battery staple", "hash_len": 32, "iterations": iterations}
    try:
        result = KDF_BACKENDS["pbkdf2"].run(resolved, b"0" * 16)
    except KDFError:
        return
    assert len(result) == 32


@given(rounds=st.integers(min_value=-5, max_value=20))
@settings(max_examples=300, deadline=None)
def test_bcrypt_pbkdf_never_leaks_a_raw_exception(rounds):
    resolved = {"seed": "correct horse battery staple", "hash_len": 32, "rounds": rounds}
    try:
        result = KDF_BACKENDS["bcrypt_pbkdf"].run(resolved, b"0" * 16)
    except KDFError:
        return
    assert len(result) == 32


def test_scrypt_passes_the_exact_maxmem_formula_to_hashlib(monkeypatch):
    captured = {}

    def fake_scrypt(password, *, salt, n, r, p, maxmem, dklen):
        captured["maxmem"] = maxmem
        return b"0" * dklen

    monkeypatch.setattr(hashlib, "scrypt", fake_scrypt)
    resolved = _resolved("scrypt", "correct horse battery staple")
    resolved.update(cost=16, block_size=8, parallelism=2)

    KDF_BACKENDS["scrypt"].run(resolved, b"0" * 16)

    assert captured["maxmem"] == 128 * 8 * (16 + 2 + 2) * 2


def test_scrypt_preserves_the_original_error_message():
    resolved = _resolved("scrypt", "correct horse battery staple")
    resolved.update(cost=3, block_size=8, parallelism=1)  # 3 is not a power of two
    # The wording is CPython's and changes between versions (3.15 dropped the trailing period).
    with pytest.raises(ValueError) as original:
        hashlib.scrypt(b"x", salt=b"0" * 16, n=3, r=8, p=1, dklen=32)
    with pytest.raises(KDFError) as raised:
        KDF_BACKENDS["scrypt"].run(resolved, b"0" * 16)
    assert str(raised.value) == str(original.value)


def test_pbkdf2_preserves_the_original_error_message():
    resolved = _resolved("pbkdf2", "correct horse battery staple")
    resolved["iterations"] = 0
    with pytest.raises(KDFError, match=r"^iteration value must be greater than 0\.$"):
        KDF_BACKENDS["pbkdf2"].run(resolved, b"0" * 16)


def test_bcrypt_pbkdf_preserves_the_original_error_message():
    resolved = _resolved("bcrypt_pbkdf", "correct horse battery staple")
    resolved["rounds"] = 0
    with pytest.raises(KDFError, match=r"^rounds must be 1 or more$"):
        KDF_BACKENDS["bcrypt_pbkdf"].run(resolved, b"0" * 16)


@pytest.mark.parametrize("backend_name", ["argon2id", "argon2i", "argon2d"])
def test_argon2_preserves_the_original_error_message(backend_name):
    resolved = _resolved(backend_name, "correct horse battery staple")
    resolved["iterations"] = 0
    with pytest.raises(KDFError, match=r"^Time cost is too small$"):
        KDF_BACKENDS[backend_name].run(resolved, b"0" * 16)


@given(raw_seed=st.binary(min_size=0, max_size=20))
@settings(max_examples=500, deadline=None)
def test_every_kdf_backend_never_leaks_a_raw_exception_for_argv_like_seeds(raw_seed):
    seed = raw_seed.decode("utf-8", "surrogateescape")
    salt = b"0" * 16
    for name, backend in KDF_BACKENDS.items():
        try:
            backend.run(_resolved(name, seed), salt)
        except KDFError:
            continue


@given(comment=st.text())
@settings(max_examples=300, deadline=None)
def test_write_keypair_comment_never_corrupts_pub_file_format(comment):
    private_key, public_key = keypair_from_seed(b"0" * 32)

    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = Path(tmp_dir) / "key"

        if any(char in comment for char in COMMENT_FORBIDDEN_CHARS):
            with pytest.raises(ValueError):
                write_keypair(private_key, public_key, key_path, comment=comment)
            return

        _, pub_path = write_keypair(private_key, public_key, key_path, comment=comment)
        content = pub_path.read_text()
        assert content.count("\n") == 1
        assert content.endswith("\n")


@given(name=st.text(alphabet=string.ascii_letters + string.digits + "-_.", min_size=1, max_size=20))
@settings(max_examples=500)
def test_public_key_path_appends_pub_to_name_only(name):
    original = Path("/some/dir") / name
    result = public_key_path(original)
    assert result.parent == original.parent
    assert result.name == original.name + ".pub"


@given(seed=st.binary(min_size=32, max_size=32))
@settings(max_examples=2000)
def test_keypair_from_seed_is_deterministic_for_any_32_byte_seed(seed):
    priv1, _ = keypair_from_seed(seed)
    priv2, _ = keypair_from_seed(seed)
    assert priv1.private_bytes_raw() == priv2.private_bytes_raw()


def test_write_keypair_leaves_key_unencrypted_when_no_passphrase_given():
    from cryptography.hazmat.primitives import serialization

    private_key, public_key = keypair_from_seed(b"\x01" * 32)
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "id_ed25519"
        write_keypair(private_key, public_key, output, key_passphrase="")
        loaded = serialization.load_ssh_private_key(output.read_bytes(), password=None)
        assert loaded.private_bytes_raw() == private_key.private_bytes_raw()


def test_write_keypair_encrypts_when_passphrase_given_and_requires_it_to_load():
    from cryptography.exceptions import InvalidKey
    from cryptography.hazmat.primitives import serialization

    private_key, public_key = keypair_from_seed(b"\x02" * 32)
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "id_ed25519"
        write_keypair(private_key, public_key, output, key_passphrase="hunter2")
        data = output.read_bytes()

        with pytest.raises((TypeError, InvalidKey)):
            serialization.load_ssh_private_key(data, password=None)

        loaded = serialization.load_ssh_private_key(data, password=b"hunter2")
        assert loaded.private_bytes_raw() == private_key.private_bytes_raw()


@given(seed=st.binary(min_size=0, max_size=64).filter(lambda s: len(s) != 32))
@settings(max_examples=2000)
def test_keypair_from_seed_rejects_any_non_32_byte_seed(seed):
    with pytest.raises(ValueError):
        keypair_from_seed(seed)


def test_keypair_from_seed_rejects_wrong_length_with_the_lengths_in_the_message():
    with pytest.raises(ValueError, match=f"Ed25519 seed must be {ED25519_SEED_LENGTH} bytes, got 5"):
        keypair_from_seed(b"\x00" * 5)


def test_write_keypair_comment_defaults_to_empty():
    from cryptography.hazmat.primitives import serialization

    private_key, public_key = keypair_from_seed(b"\x03" * 32)
    public_bytes = public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    with tempfile.TemporaryDirectory() as tmp:
        # No comment argument at all - the pub key line must be exactly the key, nothing
        # appended after it (an empty default of "" and one of "XXXX" both end without a
        # trailing space, so only an exact-content check tells them apart).
        _, pub_path = write_keypair(private_key, public_key, Path(tmp) / "key")
        assert pub_path.read_bytes() == public_bytes + b"\n"


def test_write_keypair_key_passphrase_defaults_to_empty():
    from cryptography.hazmat.primitives import serialization

    private_key, public_key = keypair_from_seed(b"\x04" * 32)
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "key"
        # No key_passphrase argument at all - the key must load with no password.
        write_keypair(private_key, public_key, output)
        loaded = serialization.load_ssh_private_key(output.read_bytes(), password=None)
        assert loaded.private_bytes_raw() == private_key.private_bytes_raw()


def test_write_keypair_create_parent_dirs_defaults_to_false():
    private_key, public_key = keypair_from_seed(b"\x05" * 32)
    with tempfile.TemporaryDirectory() as tmp:
        # No create_parent_dirs argument, and a parent that's neither pre-existing nor
        # ssh_dir() - the write must fail instead of silently creating it.
        output = Path(tmp) / "missing" / "key"
        with pytest.raises(OSError):
            write_keypair(private_key, public_key, output)


def test_write_keypair_comment_suffix_is_exact():
    from cryptography.hazmat.primitives import serialization

    private_key, public_key = keypair_from_seed(b"\x06" * 32)
    public_bytes = public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    with tempfile.TemporaryDirectory() as tmp:
        _, empty = write_keypair(private_key, public_key, Path(tmp) / "empty", comment="")
        assert empty.read_bytes() == public_bytes + b"\n"

        _, commented = write_keypair(private_key, public_key, Path(tmp) / "commented", comment="my comment")
        assert commented.read_bytes() == public_bytes + b" my comment\n"


def test_write_keypair_mkdir_is_idempotent_for_an_already_existing_parent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    ssh_dir().mkdir(mode=0o700)
    private_key, public_key = keypair_from_seed(b"\x07" * 32)

    # ssh_dir() already exists (created above) - write_keypair's own mkdir(..., exist_ok=?)
    # call for it must not raise just because it's already there.
    write_keypair(private_key, public_key, ssh_dir() / "id_ed25519")


@given(
    name=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10),
    overwrite_files=st.booleans(),
)
@settings(max_examples=500)
def test_confirm_overwrite_never_raises_for_a_nonexistent_path(name, overwrite_files):
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / f"nonexistent-{name}"
        confirm_overwrite(path, overwrite_files)


def test_confirm_overwrite_prompts_with_the_exact_message_when_only_the_private_key_exists(monkeypatch, tmp_path):
    output = tmp_path / "key"
    output.write_text("x")
    seen = {}
    monkeypatch.setattr(click, "confirm", lambda message: seen.setdefault("message", message) or True)

    confirm_overwrite(output, overwrite_files=False)

    assert seen["message"] == f"{output} already exists. Overwrite?"


def test_confirm_overwrite_prompts_when_only_the_public_key_exists(monkeypatch, tmp_path):
    output = tmp_path / "key"
    (tmp_path / "key.pub").write_text("x")
    seen = {}
    monkeypatch.setattr(click, "confirm", lambda message: seen.setdefault("message", message) or True)

    confirm_overwrite(output, overwrite_files=False)

    assert seen["message"] == f"{output} already exists. Overwrite?"


def test_confirm_create_parent_dirs_is_a_noop_when_the_parent_already_exists(monkeypatch, tmp_path):
    monkeypatch.setattr(click, "confirm", lambda *a, **k: pytest.fail("should not prompt"))
    assert confirm_create_parent_dirs(tmp_path / "key", create_parent_dirs=True, interactive=True) is True


def test_confirm_create_parent_dirs_is_a_noop_for_the_ssh_dir_itself(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: pytest.fail("should not prompt"))
    result = confirm_create_parent_dirs(tmp_path / ".ssh" / "id_ed25519", create_parent_dirs=True, interactive=True)
    assert result is True


def test_confirm_create_parent_dirs_skips_the_prompt_for_a_path_under_ssh_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: pytest.fail("should not prompt"))
    result = confirm_create_parent_dirs(tmp_path / ".ssh" / "label" / "key", create_parent_dirs=True, interactive=True)
    assert result is True


def test_confirm_create_parent_dirs_skips_the_prompt_when_not_interactive_and_flag_is_on(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: pytest.fail("should not prompt"))
    result = confirm_create_parent_dirs(tmp_path / "elsewhere" / "key", create_parent_dirs=True, interactive=False)
    assert result is True


def test_confirm_create_parent_dirs_fails_fast_when_not_interactive_and_flag_is_off(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(click.UsageError) as exc_info:
        confirm_create_parent_dirs(tmp_path / "elsewhere" / "key", create_parent_dirs=False, interactive=False)
    assert str(exc_info.value) == "~/elsewhere doesn't exist. Pass --create-parent-dirs to create it."


def test_confirm_create_parent_dirs_proceeds_when_confirmed_outside_ssh(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: True)
    result = confirm_create_parent_dirs(tmp_path / "elsewhere" / "key", create_parent_dirs=True, interactive=True)
    assert result is True
    assert capsys.readouterr().out == "Warning: ~/elsewhere is outside ~/.ssh.\n"


def test_confirm_create_parent_dirs_aborts_when_declined_outside_ssh(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
    with pytest.raises(click.Abort):
        confirm_create_parent_dirs(tmp_path / "elsewhere" / "key", create_parent_dirs=True, interactive=True)


def test_confirm_create_parent_dirs_prompts_when_interactive_and_flag_is_off(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    seen = {}

    def fake_confirm(question, default=None):
        seen["question"], seen["default"] = question, default
        return True

    monkeypatch.setattr(click, "confirm", fake_confirm)
    result = confirm_create_parent_dirs(tmp_path / ".ssh" / "label" / "key", create_parent_dirs=False, interactive=True)

    assert result is True
    assert seen["question"] == "~/.ssh/label doesn't exist. Create it?"
    assert seen["default"] is True


def test_confirm_create_parent_dirs_aborts_when_declined_and_flag_is_off(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
    with pytest.raises(click.Abort):
        confirm_create_parent_dirs(tmp_path / ".ssh" / "label" / "key", create_parent_dirs=False, interactive=True)


def test_confirm_create_parent_dirs_warns_when_interactive_flag_off_and_outside_ssh(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    seen = {}

    def fake_confirm(question, default=None):
        seen["question"], seen["default"] = question, default
        return True

    monkeypatch.setattr(click, "confirm", fake_confirm)
    result = confirm_create_parent_dirs(tmp_path / "elsewhere" / "key", create_parent_dirs=False, interactive=True)

    assert result is True
    assert seen["question"] == "Create it anyway?"
    assert seen["default"] is False
    assert capsys.readouterr().out == "Warning: ~/elsewhere is outside ~/.ssh.\n"


_PATH_SEGMENT = st.text(alphabet=string.ascii_letters + string.digits + "_-.", min_size=1, max_size=8).filter(
    lambda s: s not in (".", "..")
)


@given(segments=st.lists(_PATH_SEGMENT, min_size=1, max_size=3))
@settings(max_examples=500)
def test_display_path_collapses_paths_under_home(segments):
    name = "/".join(segments)
    with tempfile.TemporaryDirectory() as home_dir, patch.dict(os.environ, {"HOME": home_dir}):
        path = Path.home() / name
        assert _display_path(path) == f"~/{name}"


@given(name=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=20))
@settings(max_examples=200)
def test_display_path_leaves_paths_outside_home_untouched(name):
    with (
        tempfile.TemporaryDirectory() as home_dir,
        tempfile.TemporaryDirectory() as other_dir,
        patch.dict(os.environ, {"HOME": home_dir}),
    ):
        path = Path(other_dir) / name
        assert _display_path(path) == str(path)
        assert not _display_path(path).startswith("~")


def test_write_keypair_and_recap_converts_value_error_to_usage_error(tmp_path):
    with pytest.raises(click.UsageError, match="newline"):
        write_keypair_and_recap(b"\x00" * 32, tmp_path / "key", comment="bad\ncomment", recap=(), key_passphrase="")
    assert not (tmp_path / "key").exists()


def test_write_keypair_and_recap_converts_os_error_to_click_exception(tmp_path):
    missing_dir_output = tmp_path / "nonexistent_dir" / "key"
    with pytest.raises(click.ClickException) as exc_info:
        write_keypair_and_recap(b"\x00" * 32, missing_dir_output, comment="", recap=(), key_passphrase="")
    assert str(exc_info.value) == f"couldn't write {missing_dir_output}: No such file or directory"
    assert not missing_dir_output.exists()


def test_write_keypair_and_recap_key_passphrase_defaults_to_empty(tmp_path, capsys):
    from cryptography.hazmat.primitives import serialization

    priv_path, _ = write_keypair_and_recap(b"\x08" * 32, tmp_path / "key", comment="", recap=())

    assert "(encrypted)" not in capsys.readouterr().out
    serialization.load_ssh_private_key(priv_path.read_bytes(), password=None)


def test_write_keypair_and_recap_prints_the_exact_recap(tmp_path, capsys):
    priv_path, pub_path = write_keypair_and_recap(
        b"\x09" * 32, tmp_path / "key", comment="", recap=(("kdf", "argon2id"),), key_passphrase=""
    )

    assert capsys.readouterr().out == (
        f"Wrote private key: {priv_path}\n"
        f"Wrote public key:  {pub_path}\n"
        "\n"
        "To recreate this exact key, remember your passphrase (keep it secret) plus:\n"
        f"  {'kdf':<18} argon2id\n"
        f"  {'algorithm':<18} ed25519\n"
    )


def test_write_keypair_and_recap_marks_the_private_key_encrypted_when_passphrase_given(tmp_path, capsys):
    priv_path, _ = write_keypair_and_recap(
        b"\x0a" * 32, tmp_path / "key", comment="", recap=(), key_passphrase="hunter2"
    )
    assert capsys.readouterr().out.splitlines()[0] == f"Wrote private key: {priv_path} (encrypted)"


def test_kdf_backend_base_run_is_not_implemented():
    with pytest.raises(NotImplementedError):
        KDFBackend.run(resolved={}, salt=b"")


def test_kdf_backend_base_recap_is_empty_by_default():
    assert KDFBackend.recap(resolved={}) == ()


def test_salt_algo_base_digest_is_not_implemented():
    with pytest.raises(NotImplementedError):
        SaltAlgo.digest(label="x", resolved={})


def test_validate_backends_accepts_the_real_registry():
    validate_backends(KDF_BACKENDS)


def test_validate_backends_rejects_a_backend_whose_name_doesnt_match_its_registry_key():
    class Mismatched:
        name = "wrong"
        salt_constraints = SaltConstraints()

    with pytest.raises(TypeError, match="must equal its registry key"):
        validate_backends({"right": Mismatched})


def test_validate_backends_rejects_a_backend_without_salt_constraints():
    class Unconstrained:
        name = "unconstrained"
        salt_constraints = None

    with pytest.raises(TypeError, match="must set salt_constraints"):
        validate_backends({"unconstrained": Unconstrained})


def test_validate_algos_accepts_the_real_registry():
    validate_algos(SALT_ALGOS)


def test_validate_algos_rejects_an_algo_whose_name_doesnt_match_its_registry_key():
    class Mismatched:
        name = "wrong"
        digest_size = 32
        min_digest_size = None
        max_digest_size = None

    with pytest.raises(TypeError, match="must equal its registry key"):
        validate_algos({"right": Mismatched})


def test_validate_algos_rejects_a_variable_algo_missing_its_size_bounds():
    class Unbounded:
        name = "unbounded"
        digest_size = None
        min_digest_size = None
        max_digest_size = None

    with pytest.raises(TypeError, match="must set digest_size"):
        validate_algos({"unbounded": Unbounded})


def test_validate_algos_rejects_a_variable_algo_with_only_one_bound_set():
    # min_digest_size and max_digest_size are both required once digest_size is unset -
    # having only one of the two is exactly as broken as having neither.
    class HalfBounded:
        name = "half"
        digest_size = None
        min_digest_size = 1
        max_digest_size = None

    with pytest.raises(TypeError, match="must set digest_size"):
        validate_algos({"half": HalfBounded})


def test_all_salt_algos_preserve_the_original_error_message():
    bad_label = "\ud800"  # an unpaired surrogate: .encode("utf-8") raises UnicodeEncodeError
    with pytest.raises(ValueError) as exc_info:
        bad_label.encode("utf-8")
    expected = str(exc_info.value)

    for algo in SALT_ALGOS.values():
        with pytest.raises(SaltError) as exc_info:
            algo.digest(bad_label, {"salt_digest_size": 16})
        assert str(exc_info.value) == expected


def test_cli_wraps_a_salt_backend_error_as_a_clean_usage_error(monkeypatch, tmp_path):
    from detssh.backends.salt.blake2b import Blake2b

    def broken_digest(cls, label, resolved):
        raise SaltError("boom")

    monkeypatch.setattr(Blake2b, "digest", classmethod(broken_digest))

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--kdf", "pbkdf2", "--salt-algo", "blake2b", "--seed", "x", "--output", str(tmp_path / "key")],
    )

    assert result.exit_code != 0
    assert "blake2b: boom" in result.output


def test_cli_rejects_a_salt_shorter_than_the_kdfs_minimum(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "argon2id",
            "--salt-algo",
            "blake2s",
            "--salt-digest-size",
            "4",
            "--seed",
            "x",
            "--output",
            str(tmp_path / "key"),
        ],
    )

    assert result.exit_code != 0
    assert "argon2id needs a salt of at least 8 bytes, got 4" in result.output


def test_cli_key_passphrase_encrypts_the_written_private_key(tmp_path):
    from cryptography.hazmat.primitives import serialization

    key_path = tmp_path / "key"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "pbkdf2",
            "--seed",
            "x",
            "--output",
            str(key_path),
            "--key-passphrase",
            "hunter2",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "(encrypted)" in result.output
    with pytest.raises(TypeError):
        serialization.load_ssh_private_key(key_path.read_bytes(), password=None)
    serialization.load_ssh_private_key(key_path.read_bytes(), password=b"hunter2")


def test_note_if_exists_warns_when_the_default_output_already_exists(tmp_path, capsys):
    default = tmp_path / "id_ed25519"
    default.write_text("existing key")

    note_if_exists(default)

    assert capsys.readouterr().out == f"Note: {default} already exists - enter a different path to avoid this.\n"


def test_note_if_exists_warns_when_only_the_public_counterpart_exists(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    default = tmp_path / ".ssh" / "id_ed25519"
    default.parent.mkdir()
    (default.parent / "id_ed25519.pub").write_text("existing pub key")

    note_if_exists(default)

    assert capsys.readouterr().out == "Note: ~/.ssh/id_ed25519 already exists - enter a different path to avoid this.\n"


def test_note_if_exists_says_nothing_for_a_free_path_or_no_default(tmp_path, capsys):
    note_if_exists(tmp_path / "id_ed25519")
    note_if_exists(None)

    assert capsys.readouterr().out == ""
