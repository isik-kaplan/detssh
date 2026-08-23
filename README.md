# detssh

Deterministic Ed25519 SSH key generation from a seed passphrase. Same
passphrase + same parameters → same keypair, every time, on any machine -
nothing to back up but what's in your head.

```
detssh
```
Prompts for everything (passphrase hidden + confirmed) and writes to the
same place `ssh-keygen` would: `~/.ssh/id_ed25519` / `~/.ssh/id_ed25519.pub`
(mode 600/700, `~/.ssh` created if missing). Pass `--output` to write
somewhere else instead.

Non-interactively:
```
detssh --kdf argon2id --salt-algo blake2b --seed "..." --label github --overwrite-files
```
Any flag switches to non-interactive mode: missing optional fields fall back
to their defaults, `--seed` is the only required one. Passing `--seed` on the
command line puts it in your shell history and process list (`ps aux`) - fine
for local scripting, but prefer the interactive prompt when that matters.

By default the private key file is written unencrypted, like `ssh-keygen -N
""`. Pass `--key-passphrase` (or leave it blank at the interactive prompt to
skip) to encrypt it at rest instead - anyone who gets the file will still
need that passphrase to use it. This is unrelated to the seed passphrase: it
never touches key derivation, so it doesn't need to be remembered to
*recreate* the key, only to unlock the file you already have. Same caveat as
`--seed` applies if passed as a flag.

## Using the key with `ssh`

`ssh` only auto-offers keys with default filenames (`id_rsa`, `id_ed25519`, ...)
sitting directly in `~/.ssh/` - a key written under `--output` or a per-label
subdirectory needs either `-i <path>`, a hand-written `Host` block in
`~/.ssh/config`, or `ssh-add`ing it to your agent.

`detssh ssh` automates the config-file route:
```
detssh ssh register isik:personal:contabo root@contabo.com --key ~/.ssh/isik:personal:contabo/id_ed25519
```
This records the label in `~/.config/detssh/config`, generates a `Host` block
for it in a detssh-managed file, and adds a single `Include` line to
`~/.ssh/config` (once, at the top) that pulls it in. After that,
`ssh isik:personal:contabo` just works - through real `ssh`, nothing routed
through detssh at connect time.

```
detssh ssh list              # show registered labels
detssh ssh forget <label>    # remove a label (never deletes the key file)
```

## Backends

- `--kdf`: `argon2id` (default), `argon2i`, `argon2d`, `scrypt`, `pbkdf2`, `bcrypt_pbkdf`
- `--salt-algo`: `blake2b` (default), `blake2s`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_384`, `sha3_512`

Each combination has its own options (cost knobs, salt digest size, etc.),
with their valid ranges shown in both `--help` and the interactive prompts.
See them with:
```
detssh --kdf <kdf> --salt-algo <salt-algo> --help
```

We recommend sticking with the defaults (`argon2id`, memory-hard with a high
cost) unless you have a specific reason not to - they make brute-forcing your
passphrase significantly more expensive than faster KDFs like `pbkdf2`.

Cost knobs (iterations, memory, cost, rounds, ...) also carry a soft safety
limit meant to catch typos before they cost you minutes of derivation time.
In interactive mode, going over one doesn't interrupt you - everything you
exceeded is summarized in one confirmation at the very end. In flag mode, it
fails immediately unless you pass `--force-allow-soft-constraints`.

## Determinism guarantee

Same explicit parameters → same key, across any release sharing the same
major version - only a major version bump may change key derivation. That
guarantee starts at 1.0; we're still on 0.x, so it doesn't apply yet (see
`tests/golden/README.md`).

## Development

```
uv sync
uv run pytest
uv run ruff check .
```

`pytest` runs with coverage on by default (`[tool.pytest.ini_options]` in
`pyproject.toml`) and fails under 100% line+branch coverage - same gate
locally and in CI, nothing extra to remember to pass.
