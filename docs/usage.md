# Usage

## Interactive mode

```
detssh
```
Prompts for everything (passphrase hidden + confirmed) and writes to the
same place `ssh-keygen` would: `~/.ssh/id_ed25519` / `~/.ssh/id_ed25519.pub`
(mode 600/700, `~/.ssh` created if missing). Pass `--output` to write
somewhere else instead.

The seed comes first after the KDF choices, two ways:

- **Type my own**: hidden as you type, with a meter above it that redraws
  on every keystroke - `[█████░░░░░] 5/10 · ~52 bits`, a point per 10 bits
  of the [weak-seed check](security.md#the-weak-seed-check)'s estimate,
  red below the 5 it accepts without asking. Then it's asked once more to
  confirm.
- **Generate random words**: detssh picks 6 words (or as many as you ask
  for, 5-20) from the EFF large wordlist with Python's `secrets`, shows them
  with what they're worth (~78 bits for 6), and has you type them back to
  show you wrote them down. Once they match, they're erased from the
  screen. The seed is the words, one space between each.

Without a terminal (input piped in), the seed is a plain hidden prompt,
asked twice.

## Generating a seed on its own

```
detssh seed              # 6 words
detssh seed --words 7
```
Prints a random seed and derives nothing, so you can write it down before
running `detssh`. Only the words go to stdout (`detssh seed | pbcopy`); the
estimate and a reminder go to stderr.

## Flag mode

```
detssh --kdf argon2id --salt-algo blake2b --seed "..." --label isik:home:laptop --overwrite-files
```
Passing almost any flag switches to flag mode (the [flag reference](reference.md)
lists the exceptions): missing optional fields fall back to their defaults,
and `--seed` is the only required one. Passing `--seed` on the
command line puts it in your shell history and process list (`ps aux`) - fine
for local scripting, but prefer the interactive prompt when that matters.

## Encrypting the private key file

By default the private key file is written unencrypted, like `ssh-keygen -N
""`. Pass `--key-passphrase` (or leave it blank at the interactive prompt to
skip) to encrypt it at rest instead - anyone who gets the file will still
need that passphrase to use it. This is unrelated to the seed passphrase: it
never touches key derivation, so it doesn't need to be remembered to
*recreate* the key, only to unlock the file you already have. Same caveat as
`--seed` applies if passed as a flag.

To install only the public key on a machine you log into, see
[authorize.md](authorize.md). To make `ssh <label>` work, see [ssh.md](ssh.md).
