"""Pins every default that feeds key derivation, against tests/golden/defaults.json.

The key vectors in test_golden_vectors.py run at tiny fixed cost settings to stay fast,
so they never see the real defaults - and those defaults are class attributes, which
mutmut doesn't mutate. Without this, changing e.g. scrypt's default cost would pass
every other test while silently giving anyone who relies on defaults a different key.

A failing test here means the same as a failing vector (see tests/golden/README.md).
Regenerate deliberately with:
    uv run python -c "
    import json
    from tests.test_golden_defaults import current_defaults
    open('tests/golden/defaults.json', 'w').write(json.dumps(current_defaults(), indent=2, sort_keys=True) + '\\n')
    "
"""

import json
from pathlib import Path

from detssh import cli
from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.salt import ALGOS as SALT_ALGOS


GOLDEN = Path(__file__).parent / "golden" / "defaults.json"


def current_defaults():
    return {
        "kdf": cli.DEFAULT_KDF,
        "salt_algo": cli.DEFAULT_SALT_ALGO,
        "hash_len": cli.HASH_LEN,
        "kdf_defaults": {name: cls.defaults for name, cls in KDF_BACKENDS.items()},
        "salt_defaults": {name: cls.defaults for name, cls in SALT_ALGOS.items()},
    }


def test_derivation_defaults_match_the_golden_file():
    assert current_defaults() == json.loads(GOLDEN.read_text())


def test_cli_defaults_are_the_ones_pinned():
    # The CLI builds its defaults from the same constants; make sure it still does.
    assert cli.DEFAULTS["kdf"] == cli.DEFAULT_KDF
    assert cli.DEFAULTS["salt_algo"] == cli.DEFAULT_SALT_ALGO
