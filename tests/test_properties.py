import os
import string
import tempfile
from pathlib import Path
from unittest.mock import patch

import click
import pytest
import questionary
from click.testing import CliRunner
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from detssh.backends.base import (
    Field,
    _display_path,
    build_options,
    confirm_create_parent_dirs,
    confirm_overwrite,
    is_interactive,
    resolve_fields,
    write_keypair_and_recap,
)
from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.kdf import validate_backends
from detssh.backends.kdf.base import KDFBackend, KDFError, SaltConstraints
from detssh.backends.salt import ALGOS as SALT_ALGOS
from detssh.backends.salt import validate_algos
from detssh.backends.salt.base import SaltAlgo, SaltError
from detssh.cli import KDFSaltCommand, _fields_for, _peek, main
from detssh.keygen import COMMENT_FORBIDDEN_CHARS, keypair_from_seed, public_key_path, write_keypair


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


_PEEK_TOKEN = st.text(alphabet=st.characters(blacklist_characters="="), min_size=1, max_size=8)


@st.composite
def _peek_scenario(draw):
    flag = "--kdf"
    default = "unset-default"
    n_occurrences = draw(st.integers(min_value=0, max_value=5))
    values = draw(st.lists(_PEEK_TOKEN, min_size=n_occurrences, max_size=n_occurrences))
    use_equals = draw(st.lists(st.booleans(), min_size=n_occurrences, max_size=n_occurrences))
    n_noise = draw(st.integers(min_value=0, max_value=5))

    chunks = [
        [f"{flag}={value}"] if equals else [flag, value] for value, equals in zip(values, use_equals, strict=True)
    ]
    chunks += [["--noise"] for _ in range(n_noise)]

    order = draw(st.permutations(range(len(chunks))))
    argv = [token for i in order for token in chunks[i]]
    expected = default
    for i in order:
        if i < n_occurrences:
            expected = values[i]

    return argv, flag, default, expected


@given(scenario=_peek_scenario())
@settings(max_examples=1000)
def test_peek_always_returns_the_last_occurrence(scenario):
    argv, flag, default, expected = scenario
    assert _peek(argv, flag, default) == expected


@given(kdf_name=st.sampled_from(list(KDF_BACKENDS)), salt_name=st.sampled_from(list(SALT_ALGOS)))
@settings(max_examples=100)
def test_fields_for_has_no_key_collisions(kdf_name, salt_name):
    kdf_cls = KDF_BACKENDS[kdf_name]
    salt_cls = SALT_ALGOS[salt_name]
    fields = _fields_for(kdf_cls, salt_cls)
    common_keys = {"seed", "label", "output", "comment", "key_passphrase"}
    assert common_keys <= fields.keys()
    assert len(fields) == len(common_keys) + len(kdf_cls.fields) + len(salt_cls.fields)


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


@given(default_value=st.integers())
@settings(max_examples=3000)
def test_resolve_fields_uses_default_when_not_interactive(default_value):
    fields = {"x": Field("X", kind="int")}
    resolved = resolve_fields(fields, {"x": None}, {"x": default_value}, interactive=False)
    assert resolved["x"] == default_value


@given(passed_value=st.integers(), default_value=st.integers())
@settings(max_examples=3000)
def test_resolve_fields_prefers_passed_value_over_default(passed_value, default_value):
    fields = {"x": Field("X", kind="int")}
    resolved = resolve_fields(fields, {"x": passed_value}, {"x": default_value}, interactive=False)
    assert resolved["x"] == passed_value


@given(value=st.one_of(st.none(), st.just("")))
@settings(max_examples=10)
def test_resolve_fields_rejects_missing_or_empty_required_field(value):
    fields = {"seed": Field("Seed", kind="secret", required=True)}
    with pytest.raises(click.UsageError):
        resolve_fields(fields, {"seed": value}, {}, interactive=False)


@given(text=st.text(min_size=1))
@settings(max_examples=3000)
def test_resolve_fields_accepts_any_non_empty_required_value(text):
    fields = {"seed": Field("Seed", kind="secret", required=True)}
    resolved = resolve_fields(fields, {"seed": text}, {}, interactive=False)
    assert resolved["seed"] == text


@given(value=st.one_of(st.just(""), st.just(0), st.just(False), st.text()))
@settings(max_examples=1000)
def test_resolve_fields_accepts_any_value_when_not_required(value):
    fields = {"x": Field("X", kind="text")}
    resolved = resolve_fields(fields, {"x": value}, {}, interactive=False)
    assert resolved["x"] == value


def test_optional_secret_ask_defaults_to_empty_so_it_can_be_skipped(monkeypatch):
    captured = {}

    def fake_prompt(message, **kwargs):
        captured.update(kwargs)
        return kwargs.get("default")

    monkeypatch.setattr(click, "prompt", fake_prompt)
    field = Field("Key passphrase", kind="secret", required=False)
    assert field.ask(default="ignored") == ""
    assert captured["default"] == ""
    assert captured["confirmation_prompt"] is True
    assert captured["hide_input"] is True


def test_required_secret_ask_has_no_default_so_empty_input_reprompts(monkeypatch):
    captured = {}

    def fake_prompt(message, **kwargs):
        captured.update(kwargs)
        return "whatever"

    monkeypatch.setattr(click, "prompt", fake_prompt)
    field = Field("Seed passphrase", kind="secret", required=True)
    field.ask(default="ignored")
    assert "default" not in captured


@given(values=st.dictionaries(st.text(min_size=1, max_size=5), st.one_of(st.none(), st.integers(), st.text())))
@settings(max_examples=1000)
def test_is_interactive_iff_every_value_is_none(values):
    assert is_interactive(values) == all(v is None for v in values.values())


@given(
    name=st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=10),
    kind=st.sampled_from(["text", "int", "path", "secret"]),
    default_value=st.one_of(st.none(), st.integers(), st.text(min_size=1)),
)
@settings(max_examples=500)
def test_build_options_default_is_always_the_none_sentinel(name, kind, default_value):
    fields = {name: Field(f"{name} message", kind=kind)}
    options = build_options(fields, {name: default_value})
    assert len(options) == 1
    option = options[0]
    assert option.default is None
    assert option.opts == [f"--{name.replace('_', '-')}"]


@given(
    name=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10),
    overwrite_files=st.booleans(),
)
@settings(max_examples=500)
def test_confirm_overwrite_never_raises_for_a_nonexistent_path(name, overwrite_files):
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / f"nonexistent-{name}"
        confirm_overwrite(path, overwrite_files)


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
    with pytest.raises(click.UsageError, match="--create-parent-dirs"):
        confirm_create_parent_dirs(tmp_path / "elsewhere" / "key", create_parent_dirs=False, interactive=False)


def test_confirm_create_parent_dirs_proceeds_when_confirmed_outside_ssh(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: True)
    result = confirm_create_parent_dirs(tmp_path / "elsewhere" / "key", create_parent_dirs=True, interactive=True)
    assert result is True
    assert "outside ~/.ssh" in capsys.readouterr().out


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
    assert "doesn't exist. Create it?" in seen["question"]
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
    assert "outside ~/.ssh" in capsys.readouterr().out


@given(
    value=st.integers(min_value=-(10**6), max_value=10**6),
    min_value=st.integers(min_value=-(10**6), max_value=10**6),
    max_value=st.integers(min_value=-(10**6), max_value=10**6),
)
@settings(max_examples=2000)
def test_field_hard_error_for_matches_min_max(value, min_value, max_value):
    field = Field("x", kind="int", min_value=min_value, max_value=max_value)
    error = field.hard_error_for(value)
    assert (error is not None) == (value < min_value or value > max_value)


@given(value=st.integers(min_value=0, max_value=10**9), soft_max=st.integers(min_value=0, max_value=10**9))
@settings(max_examples=2000)
def test_field_soft_error_for_matches_soft_max(value, soft_max):
    field = Field("x", kind="int", soft_max=soft_max)
    error = field.soft_error_for(value)
    assert (error is not None) == (value > soft_max)


@given(value=st.integers())
@settings(max_examples=500)
def test_field_without_constraints_never_errors(value):
    field = Field("x", kind="int")
    assert field.hard_error_for(value) is None
    assert field.soft_error_for(value) is None
    assert field.hint() == ""


def test_resolve_fields_defers_soft_violations_to_one_consolidated_confirm(monkeypatch, capsys):
    fields = {
        "a": Field("A", kind="int", soft_max=10),
        "b": Field("B", kind="int", soft_max=10),
    }
    values = {"a": None, "b": None}
    defaults = {"a": 1, "b": 1}

    asked_values = iter([50, 60])
    monkeypatch.setattr(Field, "ask", lambda self, default: next(asked_values))

    confirm_calls = []
    monkeypatch.setattr(click, "confirm", lambda message: confirm_calls.append(message) or True)

    resolved = resolve_fields(fields, values, defaults, interactive=True)

    assert resolved == {"a": 50, "b": 60}
    assert len(confirm_calls) == 1
    output = capsys.readouterr().out
    assert "--a" in output
    assert "--b" in output


def test_resolve_fields_aborts_if_consolidated_confirm_declined(monkeypatch):
    fields = {"a": Field("A", kind="int", soft_max=10)}
    values = {"a": None}
    defaults = {"a": 1}

    monkeypatch.setattr(Field, "ask", lambda self, default: 50)
    monkeypatch.setattr(click, "confirm", lambda message: False)

    with pytest.raises(click.Abort):
        resolve_fields(fields, values, defaults, interactive=True)


def test_resolve_fields_hard_violations_still_reask_immediately_in_interactive_mode(monkeypatch):
    fields = {"a": Field("A", kind="int", max_value=10)}
    values = {"a": None}
    defaults = {"a": 1}

    asked_values = iter([50, 5])
    monkeypatch.setattr(Field, "ask", lambda self, default: next(asked_values))

    resolved = resolve_fields(fields, values, defaults, interactive=True)
    assert resolved == {"a": 5}


def test_resolve_fields_never_confirms_in_non_interactive_mode(monkeypatch):
    fields = {"a": Field("A", kind="int", soft_max=10)}
    values = {"a": 50}
    defaults = {"a": 1}

    monkeypatch.setattr(click, "confirm", lambda message: pytest.fail("should not prompt in flag mode"))

    with pytest.raises(click.UsageError, match="force-allow-soft-constraints"):
        resolve_fields(fields, values, defaults, interactive=False)


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


def test_hint_shows_only_a_floor_when_theres_no_ceiling():
    field = Field("x", kind="int", min_value=5)
    assert field.hint() == " (>= 5)"


def test_hint_shows_only_a_ceiling_when_theres_no_floor():
    field = Field("x", kind="int", max_value=5)
    assert field.hint() == " (<= 5)"


def test_hard_error_for_passes_none_through_without_checking_bounds():
    field = Field("x", kind="int", min_value=5, max_value=10)
    assert field.hard_error_for(None) is None


def test_ask_int_delegates_to_click_prompt_with_int_type(monkeypatch):
    captured = {}
    monkeypatch.setattr(click, "prompt", lambda message, **kwargs: captured.update(kwargs) or 7)
    field = Field("Count", kind="int")
    assert field.ask(default=3) == 7
    assert captured["type"] is int
    assert captured["default"] == 3


def test_ask_path_shows_the_default_in_the_message_when_one_is_set(monkeypatch):
    captured = {}

    def fake_prompt(message, **kwargs):
        captured["message"] = message
        captured.update(kwargs)
        return Path("/chosen")

    monkeypatch.setattr(click, "prompt", fake_prompt)
    field = Field("Output path", kind="path")
    assert field.ask(default=Path("/default/key")) == Path("/chosen")
    assert "/default/key" in captured["message"]
    assert captured["show_default"] is False


def test_ask_path_warns_when_the_default_output_already_exists(monkeypatch, tmp_path, capsys):
    default = tmp_path / "id_ed25519"
    default.write_text("existing key")
    monkeypatch.setattr(click, "prompt", lambda message, **kwargs: Path("/chosen"))

    field = Field("Output path", kind="path")
    field.ask(default=default)

    assert "already exists" in capsys.readouterr().out


def test_ask_path_warns_when_only_the_public_counterpart_exists(monkeypatch, tmp_path, capsys):
    default = tmp_path / "id_ed25519"
    (tmp_path / "id_ed25519.pub").write_text("existing pub key")
    monkeypatch.setattr(click, "prompt", lambda message, **kwargs: Path("/chosen"))

    field = Field("Output path", kind="path")
    field.ask(default=default)

    assert "already exists" in capsys.readouterr().out


def test_ask_path_omits_the_bracketed_default_when_there_is_none(monkeypatch):
    captured = {}

    def fake_prompt(message, **kwargs):
        captured["message"] = message
        return Path("/chosen")

    monkeypatch.setattr(click, "prompt", fake_prompt)
    field = Field("Output path", kind="path")
    field.ask(default=None)
    assert "[" not in captured["message"]


def test_ask_select_returns_the_chosen_answer(monkeypatch):
    monkeypatch.setattr(
        questionary, "select", lambda message, choices, default: type("Q", (), {"ask": lambda self: "b"})()
    )
    field = Field("Backend", kind="select", choices=("a", "b"))
    assert field.ask(default="a") == "b"


def test_ask_select_aborts_when_the_user_cancels(monkeypatch):
    monkeypatch.setattr(
        questionary, "select", lambda message, choices, default: type("Q", (), {"ask": lambda self: None})()
    )
    field = Field("Backend", kind="select", choices=("a", "b"))
    with pytest.raises(click.Abort):
        field.ask(default="a")


def test_ask_falls_back_to_plain_prompt_for_text_kind(monkeypatch):
    captured = {}

    def fake_prompt(message, **kwargs):
        captured.update(kwargs)
        return "typed"

    monkeypatch.setattr(click, "prompt", fake_prompt)
    field = Field("Label", kind="text")
    assert field.ask(default="fallback") == "typed"
    assert captured["default"] == "fallback"
    assert captured["show_default"] is True


def test_resolve_fields_calls_a_callable_default_in_interactive_mode(monkeypatch):
    fields = {"output": Field("Output", kind="path")}
    calls = []

    def callable_default():
        calls.append(1)
        return Path("/computed/default")

    monkeypatch.setattr(Field, "ask", lambda self, default: default)
    resolved = resolve_fields(fields, {"output": None}, {"output": callable_default}, interactive=True)
    assert resolved["output"] == Path("/computed/default")
    assert calls == [1]


def test_write_keypair_and_recap_converts_value_error_to_usage_error(tmp_path):
    with pytest.raises(click.UsageError, match="newline"):
        write_keypair_and_recap(b"\x00" * 32, tmp_path / "key", comment="bad\ncomment", recap=(), key_passphrase="")
    assert not (tmp_path / "key").exists()


def test_write_keypair_and_recap_converts_os_error_to_click_exception(tmp_path):
    missing_dir_output = tmp_path / "nonexistent_dir" / "key"
    with pytest.raises(click.ClickException, match="couldn't write"):
        write_keypair_and_recap(b"\x00" * 32, missing_dir_output, comment="", recap=(), key_passphrase="")
    assert not missing_dir_output.exists()


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


def test_format_options_is_a_no_op_when_the_command_has_no_options():
    cmd = KDFSaltCommand(name="detssh-test", params=[])
    ctx = click.Context(cmd, info_name="detssh-test", help_option_names=[])
    formatter = click.HelpFormatter()

    cmd.format_options(ctx, formatter)

    assert formatter.getvalue() == ""


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
