# Usage

## Interactive mode

```
detssh
```
Prompts for everything (passphrase hidden + confirmed) and writes to the
same place `ssh-keygen` would: `~/.ssh/id_ed25519` / `~/.ssh/id_ed25519.pub`
(mode 600/700, `~/.ssh` created if missing). Pass `--output` to write
somewhere else instead.

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
