# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0] - 2026-10-30

### Changed

- The seed prompts show nothing as you type: no `*` per character for your
  own seed and its confirmation, and generated words are typed back hidden
  too, like the key file's passphrase already was.
- docs/security.md says what does and doesn't show on screen, and what can
  still keep a secret: terminal logs, scrollback, typing before a prompt is
  up, and secrets passed as flags.

## [0.11.0] - 2026-10-28

### Added

- Interactive mode asks how you want the seed: type your own, with a
  strength meter that redraws as you type (`[█████░░░░░] 5/10 · ~52 bits`,
  red below what the weak-seed check accepts), or have detssh generate
  random words and type them back to show you saved them, after which
  they're erased from the screen. Without a terminal it's the hidden,
  confirmed prompt as before.
- `detssh seed [--words N]`: prints a seed of N random words (default 6,
  5-20) from the EFF large wordlist, picked with `secrets`, and derives
  nothing. The wordlist ships with detssh, byte for byte as the EFF
  publishes it (CC BY 3.0 US).

### Changed

- Needs `isik[cli]>=0.39.0`, whose `prompt=` lets the seed question be
  asked by detssh. isik 0.38.0's pytest plugin broke any project without
  Django; 0.39.0 fixes that.

## [0.10.0] - 2026-10-26

### Added

- detssh now stops before deriving from a seed that looks weak, rated by
  zxcvbn (a new dependency) as fewer than about 2^50 guesses. Interactive
  mode warns and asks, defaulting to no; flag mode fails unless you pass
  `--accept-weak-seed`. Separators aren't counted and the label and comment
  count as known, so neither can pad a weak seed past it. It catches common
  passwords, patterns and short famous phrases, but can't tell a quote or a
  sentence from random words: passing it doesn't make a seed strong.
- `docs/security.md`: how strong the seed needs to be against offline
  guessing, why a long quote isn't strong, what makes a self-written
  sentence weak, where the numbers come from, and what the weak-seed check
  does and doesn't catch. Also what's public: the label and KDF settings
  aren't secret, and the public key's comment is empty unless you pass
  `--comment`.

### Changed

- Flag-mode scripts using a weak seed now fail until they pass
  `--accept-weak-seed` or use a stronger seed. Derived keys are unchanged.
- Releases wait for the tests: the publish workflow now runs the test and
  mutation jobs first and only publishes if they pass.

## [0.9.0] - 2026-10-25

### Added

- Before asking for the seed, detssh now hardens its own process,
  best-effort: core dumps are off; on Linux the process is undumpable, so
  other processes running as your user can't attach or read its memory, and
  its memory is locked against swapping when the memlock limit is
  unlimited; on macOS debuggers are refused. `detssh ssh` subcommands, which
  never see a seed, are left alone.
- `docs/security.md`: where to run detssh and what the hardening does and
  doesn't cover. `--authorize` still computes the private key in memory, so
  the docs now say to use it only on trusted machines and to copy the
  public key to the rest.

## [0.8.0] - 2026-10-25

### Changed

- Options, questions and their checks now come from one declaration per
  setting, built on `isik[cli]` (a new dependency). `--help`, every flag,
  every question and every derived key are unchanged.
- In interactive mode, `--overwrite-files` with "Only add the public key" is
  now refused, as it already was with `--authorize`. Before, it was quietly
  ignored.

## [0.7.0] - 2026-10-05

### Added

- `--authorize`: derive the key, but only append its public half to
  `~/.ssh/authorized_keys` (or `--authorized-keys FILE`), the way
  `ssh-copy-id` would. No private key is written, so a machine you only want
  to log *into* never holds one. A key that's already in the file (under any
  comment or options) is left alone, and an existing file keeps its mode; a
  new one is created 600 inside a 700 `~/.ssh`.
- Interactive mode now opens by asking whether to generate a keypair or only
  add the public key. Generating stays the default. `detssh --authorize`
  skips that question and still prompts for everything else, so the seed
  passphrase never has to go on the command line.

### Changed

- `--create-parent-dirs` applies to the `--authorized-keys` file's parent too.

## [0.6.0] - 2026-09-19

### Added

- Mutation testing via `mutmut`, gating CI: it rewrites the source one small
  change at a time and reruns the suite, catching cases where 100% line
  coverage still let a real behavior change through untested. Started at
  300+ surviving mutants (from a from-scratch first run); closed all but
  40, each confirmed genuinely equivalent - the mutated code is provably
  indistinguishable from the original for every input (e.g. `"utf-8"` vs
  `"UTF-8"` as a codec name, which Python's codec lookup can't tell apart)
  - and documented one by one in `tests/mutmut_known_equivalents.txt`,
  which CI diffs new runs against.
- `ruff format --check` now runs in CI alongside `ruff check`.

No application behavior changed in this release - every one of the ~260
mutants closed was a test that was missing or checking too loosely (an
exact-message assertion where only a substring was checked before, an edge
case like a trailing `--kdf` flag with nothing after it, a permission check
on a directory that already existed rather than one the call under test
actually creates). The code they exercise was already correct.

## [0.5.0] - 2026-09-19

### Added

- Interactive mode now offers to create a missing output-path parent
  directory itself, instead of requiring `--create-parent-dirs` up front.
  It defaults to yes for a path under `~/.ssh` and to no (with a warning)
  for one outside it - the same rule `--create-parent-dirs` already used.

### Changed

- Flag mode now fails fast with a clear error when the output path's
  parent is missing and `--create-parent-dirs` wasn't passed, instead of
  running key derivation first and then failing on a raw `OSError`.

### Fixed

- `--kdf`/`--salt-algo` backend detection (used to decide which options to
  show before click's real parsing runs) could misread a flag's own value
  as a second occurrence of the flag when the value happened to equal the
  flag string itself (e.g. `--kdf --kdf`).

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
