# detssh docs

- [Usage](usage.md): interactive and flag mode, output paths, encrypting the key file
- [Only installing the public key](authorize.md): `--authorize`, for machines you only log into
- [Using the key with `ssh`](ssh.md): `ssh <label>` via `~/.ssh/config`, and `detssh ssh`
- [Naming labels](labels.md): a label convention, and why labels are safe to share
- [Backends](backends.md): KDFs, salt algorithms, their options and limits
- [Flag reference](reference.md): every flag and subcommand
- [Determinism guarantee](determinism.md): when the same input stops giving the same key
- [Development](development.md): tests, coverage, mutation testing
