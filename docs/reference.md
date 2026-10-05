# Flag reference

Every option of `detssh` itself, besides the [backend options](backends.md).
Passing any of them except `--authorize`, `--authorized-keys`, `--overwrite-files`
and `--create-parent-dirs` switches to flag mode.

| Flag | Default | What it does |
|---|---|---|
| `--kdf` | `argon2id` | Key derivation backend. |
| `--salt-algo` | `blake2b` | Hash that turns the label into the salt. |
| `--seed` | required | Seed passphrase. Prefer the interactive prompt ([why](usage.md#flag-mode)). |
| `--label` | empty | Derivation label: the salt input, and the `Host` name for `--register`. |
| `--output` | `~/.ssh/id_ed25519` | Private key path; the public key goes next to it as `.pub`. |
| `--comment` | empty | Comment at the end of the public key line. No newlines. |
| `--key-passphrase` | empty | Encrypts the private key file at rest. Doesn't affect derivation. |
| `--authorize` | off | Only append the public key to an authorized_keys file. Writes no private key. |
| `--authorized-keys` | `~/.ssh/authorized_keys` | File `--authorize` appends to. Needs `--authorize`. |
| `--overwrite-files` | off | Replace existing key files without asking. |
| `--create-parent-dirs` | off | Create a missing parent directory of `--output` / `--authorized-keys`. Not needed when that parent is `~/.ssh` itself, which is always created; interactive mode asks instead. |
| `--register USER@HOST` | off | Register the key for `ssh <label>`. Needs `--label`. |
| `--register-port` | 22 | Port for `--register`. |
| `--force-allow-soft-constraints` | off | Allow cost options above their soft max in flag mode. |
| `-h`, `--help` | | Help for the chosen `--kdf` / `--salt-algo`. |

`--authorize` can't be combined with `--output`, `--key-passphrase`,
`--overwrite-files`, `--register` or `--register-port`.

`detssh ssh` subcommands:

| Command | What it does |
|---|---|
| `detssh ssh register LABEL USER@HOST --key FILE [--port PORT]` | Make `ssh LABEL` connect to `USER@HOST` with that key. `--key` is required. |
| `detssh ssh list` | Show registered labels. |
| `detssh ssh forget LABEL` | Remove a label. Never deletes the key file. |
