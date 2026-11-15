# detssh

Deterministic Ed25519 SSH keys from a passphrase: same passphrase, same key,
on any machine. Nothing to back up.

```
uv tool install detssh
detssh
```

`detssh` asks for everything it needs, and can pick a strong seed for you
(`detssh seed` prints one on its own).

I name labels after the machine the key logs into, as
`<owner>:<site>:<machine>`, e.g. `isik:hetzner:web` or `client:aws:db`
([more](https://github.com/isik-kaplan/detssh/blob/master/docs/labels.md)).

See the [docs](https://github.com/isik-kaplan/detssh/tree/master/docs) for
flags and everything else.
