# Backends

- `--kdf`: `argon2id` (default), `argon2i`, `argon2d`, `scrypt`, `pbkdf2`, `bcrypt_pbkdf`
- `--salt-algo`: `blake2b` (default), `blake2s`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_384`, `sha3_512`

Each combination has its own options (cost knobs, salt digest size, etc.),
with their valid ranges shown in both `--help` and the interactive prompts.
See them with:
```
detssh --kdf <kdf> --salt-algo <salt-algo> --help
```

| Backend | Option | Default | Soft max |
|---|---|---|---|
| `argon2id`, `argon2i`, `argon2d` | `--iterations` | 10 | 100 |
| | `--memory` (MiB) | 1024 | 2048 |
| | `--parallelism` | 4 | 16 |
| `scrypt` | `--cost` (N, a power of two) | 16384 | 262144 |
| | `--block-size` (r) | 8 | 16 |
| | `--parallelism` (p) | 1 | 8 |
| `pbkdf2` (HMAC-SHA256) | `--iterations` | 600000 | 50000000 |
| `bcrypt_pbkdf` | `--rounds` | 16 | 2000 |
| `blake2b` salt | `--salt-digest-size` (bytes, 1-64) | 16 | |
| `blake2s` salt | `--salt-digest-size` (bytes, 1-32) | 16 | |

The `sha*` salt algorithms have no options. Argon2 needs a salt of at
least 8 bytes, so `--salt-digest-size` below 8 is rejected with it.

We recommend sticking with the defaults (`argon2id`, memory-hard with a high
cost) unless you have a specific reason not to - they make brute-forcing your
passphrase significantly more expensive than faster KDFs like `pbkdf2`.

Cost knobs (iterations, memory, cost, rounds, ...) also carry a soft safety
limit meant to catch typos before they cost you minutes of derivation time.
In interactive mode, going over one doesn't interrupt you - everything you
exceeded is summarized in one confirmation at the very end. In flag mode, it
fails immediately unless you pass `--force-allow-soft-constraints`.
