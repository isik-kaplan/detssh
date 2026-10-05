# Using the key with `ssh`

`ssh` only auto-offers keys with default filenames (`id_rsa`, `id_ed25519`, ...)
sitting directly in `~/.ssh/` - a key written under `--output` or a per-label
subdirectory needs either `-i <path>`, a hand-written `Host` block in
`~/.ssh/config`, or `ssh-add`ing it to your agent.

The interactive run offers to do this for you at the end, right after it
writes the key:
```
Register this key so `ssh isik:cloud:master` connects with it? [Y/n]: y
Destination (user@host): root@server.example.com
Non-default ssh port:

Registered isik:cloud:master -> root@server.example.com
Run: ssh isik:cloud:master
```
The label you derived the key with doubles as the `Host` name, so there's
nothing extra to type. In flag mode, `--register root@server.example.com` (plus
`--register-port` when it isn't 22) does the same thing, and needs `--label`
for that reason. Declining changes nothing about the key that was written.

For a key you already have, `detssh ssh register` reaches the same end state:
```
detssh ssh register isik:cloud:master root@server.example.com --key ~/.ssh/isik:cloud:master/id_ed25519
```
Either route records the label in `~/.config/detssh/config`, generates a `Host` block
for it in a detssh-managed file, and adds a single `Include` line to
`~/.ssh/config` (once, at the top) that pulls it in. After that,
`ssh isik:cloud:master` just works - through real `ssh`, nothing routed
through detssh at connect time.

```
detssh ssh list              # show registered labels
detssh ssh forget <label>    # remove a label (never deletes the key file)
```
