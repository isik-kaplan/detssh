import pytest
from click.testing import CliRunner

from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.salt import ALGOS as SALT_ALGOS
from detssh.cli import main


ARGON2_NAMES = ("argon2id", "argon2i", "argon2d")


def _knob_group(kdf_name):
    return "argon2" if kdf_name in ARGON2_NAMES else kdf_name


COST_KNOB_PRESETS = {
    "small": {
        "argon2": {"iterations": 2, "memory": 16, "parallelism": 1},
        "scrypt": {"cost": 4, "block_size": 2, "parallelism": 1},
        "pbkdf2": {"iterations": 2},
        "bcrypt_pbkdf": {"rounds": 2},
    },
    "large": {
        "argon2": {"iterations": 3, "memory": 32, "parallelism": 2},
        "scrypt": {"cost": 8, "block_size": 4, "parallelism": 2},
        "pbkdf2": {"iterations": 4},
        "bcrypt_pbkdf": {"rounds": 4},
    },
}
SALT_DIGEST_SIZE_CHOICE = {"small": "min", "large": "max"}


def _salt_digest_size_for(preset_name, kdf_cls, salt_cls):
    if not salt_cls.is_variable():
        return None
    if SALT_DIGEST_SIZE_CHOICE[preset_name] == "max":
        return salt_cls.max_digest_size
    floor = kdf_cls.salt_constraints.min_size or 0
    return max(salt_cls.min_digest_size, floor)


def _args_for(kdf_name, salt_name, preset_name, output_path):
    kdf_cls = KDF_BACKENDS[kdf_name]
    salt_cls = SALT_ALGOS[salt_name]
    preset = COST_KNOB_PRESETS[preset_name][_knob_group(kdf_name)]

    args = [
        "--kdf",
        kdf_name,
        "--salt-algo",
        salt_name,
        "--seed",
        "correct horse battery staple",
        "--label",
        "cli-combinations-test",
        "--output",
        str(output_path),
        "--overwrite-files",
    ]
    for field_name, value in preset.items():
        args += [f"--{field_name.replace('_', '-')}", str(value)]

    digest_size = _salt_digest_size_for(preset_name, kdf_cls, salt_cls)
    if digest_size is not None:
        args += ["--salt-digest-size", str(digest_size)]

    return args


COMBINATIONS = [
    (kdf_name, salt_name, preset_name)
    for kdf_name in KDF_BACKENDS
    for salt_name in SALT_ALGOS
    for preset_name in COST_KNOB_PRESETS
]


@pytest.mark.parametrize(
    "kdf_name,salt_name,preset_name",
    COMBINATIONS,
    ids=[f"{kdf_name}-{salt_name}-{preset_name}" for kdf_name, salt_name, preset_name in COMBINATIONS],
)
def test_cli_succeeds_for_combination(kdf_name, salt_name, preset_name, tmp_path):
    output_path = tmp_path / "key"
    args = _args_for(kdf_name, salt_name, preset_name, output_path)

    result = CliRunner().invoke(main, args)

    assert result.exit_code == 0, result.output
    assert output_path.exists()
    assert (tmp_path / "key.pub").exists()
