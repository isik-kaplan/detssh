# detssh

Deterministic Ed25519 SSH keys from a passphrase: same passphrase, same key,
on any machine. Nothing to back up.

```
uv tool install detssh
detssh
```

`detssh` asks for everything it needs.

I name labels `<owner>:<site>:<machine>`, e.g. `isik:home:laptop` or
`client:cloud:web1`
([more](https://github.com/isik-kaplan/detssh/blob/master/docs/labels.md)).

See the [docs](https://github.com/isik-kaplan/detssh/tree/master/docs) for
flags and everything else.
