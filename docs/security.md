# Security model

All of a key's security rests on the seed passphrase. Anyone who has it can
derive every key you've made with it, under every label, so where you type
it matters more than anything detssh does.

## Where to run detssh

Only run detssh, `--authorize` included, on a machine you trust. Getting
even just the public key means computing the private key first, so the
machine running detssh has both the seed and the private key in memory,
even when no private key is written to disk. Someone with root or malware
on that machine can read them, or simply log the passphrase as you type it,
and nothing a program does can stop that.

A machine you only log into and don't fully trust never needs detssh. The
public key isn't secret, so get it there instead:
```
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host   # run on a machine you trust
```
or paste the `.pub` line into that machine's `~/.ssh/authorized_keys`. For a
new cloud VM, the provider's "SSH keys" field does this for you.

## What detssh does about leaks

Before asking for the seed, detssh hardens its own process, best-effort:

- Core dumps are off, so a crash can't write the seed to disk.
- On Linux, the process is marked undumpable: other processes running as
  your user can't attach to it or read its memory. On macOS, debuggers are
  refused.
- On Linux, memory is locked against swapping when the memlock limit is
  unlimited (e.g. as root). Under a limit it isn't, because a locked process
  fails every allocation past the limit, and a large Argon2 memory cost
  would hit it. Keep swap encrypted instead; macOS always does.

None of this holds against root. The seed also passes through Python
strings, which can't be wiped, so it stays in memory until the process
exits and the memory is reused.
