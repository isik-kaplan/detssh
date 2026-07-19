import os
import string
import tempfile
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from detssh.backends.base import Field, _display_path, build_options, confirm_overwrite, is_interactive, resolve_fields
from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.kdf.base import KDFError, SaltConstraints
from detssh.backends.salt import ALGOS as SALT_ALGOS
from detssh.backends.salt.base import SaltError
from detssh.cli import _fields_for, _peek
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
    common_keys = {"seed", "label", "output", "comment"}
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
