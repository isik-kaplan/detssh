# Golden vectors

`vectors.csv` (48 rows) and `variations.csv` (96 rows) pin the exact
seed/key output of every `--kdf` × `--salt-algo` combination at fixed
inputs. `../test_golden_vectors.py` loads and checks them.

`help_default.txt` and `help_pbkdf2_sha256.txt` are unrelated: exact
`detssh --help` snapshots for two `--kdf`/`--salt-algo` combinations, checked
by `../test_help_text.py`. Regenerate them (see that file's docstring) after
any deliberate change to an option's `help=` text, `_help_note`, or
`KDFSaltCommand.format_options`' wrapping - diff before committing, same as
the vectors below.

Not a correctness test (see `test_properties.py` / `test_determinism.py`) -
it catches any change that silently makes the same inputs produce a
*different* key.

Determinism holds **within a major version**: same params → same key across
any release sharing that major number, once we reach 1.0. Only a major
version bump may change derivation - that's what the version number is for.
We're still on 0.x, so this doesn't apply yet.

A failing test means one of:
- a new backend was added → add rows, don't touch existing ones
- a deliberate breaking change to defaults/formula → requires a major bump
  (once past 0.x) - update rows, call it out
- an actual bug was fixed → rare, flag it loudly
- a dependency silently changed behavior → investigate, don't just regenerate

Regenerate only once you've confirmed new values are correct, then diff the
CSV before committing - the diff is your changelog. `vectors.csv`:

```python
import csv
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from detssh.backends.kdf import BACKENDS as KDF_BACKENDS
from detssh.backends.salt import ALGOS as SALT_ALGOS
from detssh.keygen import keypair_from_seed
from tests.test_golden_vectors import SEED_PASSPHRASE, LABEL, HASH_LEN, SALT_DIGEST_SIZE, FAST_KDF_PARAMS

with open("tests/golden/vectors.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["kdf", "salt_algo", "seed_hex", "public_key"])
    for kdf_name, kdf_cls in sorted(KDF_BACKENDS.items()):
        for salt_name, salt_cls in sorted(SALT_ALGOS.items()):
            resolved = {
                "seed": SEED_PASSPHRASE, "label": LABEL,
                "hash_len": HASH_LEN, "salt_digest_size": SALT_DIGEST_SIZE,
            }
            resolved.update(FAST_KDF_PARAMS[kdf_name])
            salt = salt_cls.digest(LABEL, resolved)
            seed_bytes = kdf_cls.run(resolved, salt)
            _, pub = keypair_from_seed(seed_bytes)
            pub_line = pub.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
            w.writerow([kdf_name, salt_name, seed_bytes.hex(), pub_line])
```

For `variations.csv`, loop over `PARAM_PRESETS` too and use
`_salt_digest_size_for`/`_knob_group` from `test_golden_vectors.py` to build
`resolved` the same way the test does (no public key column - `hash_len`
isn't always 32 there, and Ed25519 needs exactly a 32-byte seed).
