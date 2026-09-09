# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-09-09

### Added

- The interactive run now offers to register the key it just wrote, so
  generating a key and getting `ssh <label>` to use it is one command
  instead of two. The label doubles as the `Host` name; declining leaves
  the key exactly as written.
- `--register <user>@<host>` and `--register-port` do the same in flag mode.
  `--register` needs `--label`, since the label names the `Host` block. Both
  are validated before key derivation starts, so a typo doesn't cost you a
  minute of argon2 first.

### Changed

- `detssh ssh register --port` now rejects non-numeric and out-of-range
  ports up front instead of writing them into the generated `Host` block.
- Registered `IdentityFile` paths are stored absolute. A relative `--key`
  used to be recorded as given, which `ssh` would then resolve against
  whatever directory it happened to be run from.

## [0.3.0] - 2026-08-23

### Added

- `detssh ssh register <label> <user>@<host> --key <path>`: records the
  label in `~/.config/detssh/config`, generates a `Host` block for it, and
  wires it into `~/.ssh/config` via a single `Include` line - so plain
  `ssh <label>` connects with the right key afterward, no `-i` or
  hand-written config needed. Also `detssh ssh list` and
  `detssh ssh forget <label>` (never deletes the key file itself).
- `--create-parent-dirs`: create the output path's missing parent
  directories, including outside `~/.ssh` (with one interactive
  confirmation first in that case). Previously only `~/.ssh` itself was
  ever auto-created.
- The interactive output-path prompt now notes when the default location is
  already occupied, before you type anything.

## [0.2.0] - 2026-08-04

### Added

- `--key-passphrase` option, with a matching interactive prompt (skippable
  by leaving it blank), to encrypt the private key file at rest - like
  `ssh-keygen -N`. Independent of the seed passphrase: it never touches key
  derivation, so it doesn't change the key produced for a given seed, only
  how the file sits on disk.
- 100% line+branch test coverage, enforced both locally and in CI via
  `pytest-cov` - `uv run pytest` fails under 100%, no separate command to
  remember.

## [0.1.0] - 2026-07-19

### Added

- Deterministic Ed25519 SSH key generation from a seed passphrase: same
  passphrase and parameters produce the same keypair on any machine.
- KDF backends: `argon2id` (default), `argon2i`, `argon2d`, `scrypt`,
  `pbkdf2`, `bcrypt_pbkdf`.
- Salt hash algorithm backends: `blake2b` (default), `blake2s`, `sha256`,
  `sha384`, `sha512`, `sha3_256`, `sha3_384`, `sha3_512`.
- Interactive mode (prompts for everything, passphrase hidden and confirmed)
  and non-interactive flag mode, selected automatically by whether any flag
  is passed.
- `ssh-keygen`-style default output path (`~/.ssh/id_ed25519` /
  `.pub`), created with the same file/directory permissions (600/700) and
  the same overwrite confirmation.
- Soft safety limits on cost knobs (iterations, memory, cost, rounds, ...)
  that catch typos before they cost minutes of derivation time - summarized
  in one confirmation in interactive mode, or bypassable with
  `--force-allow-soft-constraints` in flag mode.
- Per-backend `--help` showing the valid options and ranges for a given
  `--kdf`/`--salt-algo` combination.
