# Only installing the public key

Because the same seed and parameters always give the same key, a machine
you only want to log *into* doesn't need the private key at all. Run this
on that machine instead:
```
detssh --authorize
```
It prompts for the same seed, label and backend settings as a normal run,
then appends the public key to `~/.ssh/authorized_keys`, `ssh-copy-id`
style. No private key is written. If the key is already there, the file is
left untouched, so running it twice is harmless. The interactive wizard
asks about this up front too ("Only add the public key to an
authorized_keys file").

In flag mode, add `--authorize` to the usual flags, plus `--authorized-keys
FILE` for a file other than `~/.ssh/authorized_keys`. `--output`,
`--key-passphrase`, `--register` and `--overwrite-files` are rejected
alongside it, because they only apply when a private key is written.
