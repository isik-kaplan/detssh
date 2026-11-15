# Naming labels

The label is free text, but because it doubles as the `ssh` name, a fixed
shape pays off once you have more than a handful. This is the one I use:
```
<owner>:<site>:<machine>
```
A label names the machine you log *into* with the key - the one whose
`authorized_keys` holds the public key, and where `ssh <label>` takes you.
It never names where the private key is kept: you can derive it on any
machine you trust, so that isn't worth naming. `isik:hetzner:web` is the key
for isik's web server at Hetzner, wherever you `ssh` from.

- **owner** - whose machine you log into: your own name for yours, the
  client's name for theirs.
- **site** - where that machine is: a hosting provider (`hetzner`, `aws`),
  a place (`home`), or an organisation's network (`work`). Name the
  provider rather than just `cloud`, so servers at two providers don't
  collide.
- **machine** - what it is: a role for servers (`master`, `web1`, `db`), the
  device for personal machines (`laptop`, `desktop`, `nas`). Number
  duplicates (`web1`, `web2`) and fold environments in (`web-staging`)
  rather than adding a fourth segment.

```
isik:hetzner:master     # log into my master server at Hetzner
isik:home:nas           # log into the NAS at home
isik:work:laptop        # log into my work laptop (from my desktop, say)
client:aws:web1
client:aws:db
```

One key you put on every machine you log into isn't for any one machine;
`global` as the site says so, e.g. `isik:global:master`. Don't `--register`
it: one label is one `ssh` name, which can only point at one `user@host`.

Lowercase, hyphens inside a segment, same order every time, so `detssh ssh
list` and `ctrl-r ssh client:` group sensibly. The label doesn't imply a
user: that's the separate `user@host` you register, so the same box under
two users is two labels (`client:aws:web1`, `client:aws:web1-deploy`).

The label is also the salt, so it's part of what derives the key: renaming
one means a different key. It's safe to share - a salt isn't a secret, and
a guessable label like these adds nothing an attacker doesn't already
assume. All of the key's security rests on the seed passphrase - see
[how strong it should be](security.md#how-strong-the-seed-should-be).
