# Naming labels

The label is free text, but because it doubles as the `ssh` name, a fixed
shape pays off once you have more than a handful. This is the one I use:
```
<owner>:<site>:<machine>
```
- **owner** - whose machine it is: your own name for yours, the client's
  name for theirs.
- **site** - where it lives: a hosting provider (`cloud`), a place
  (`home`), or an organisation's network (`work`).
- **machine** - what it is: a role for servers (`master`, `web1`, `db`), the
  device for personal machines (`laptop`, `desktop`, `nas`). Number
  duplicates (`web1`, `web2`) and fold environments in (`web-staging`)
  rather than adding a fourth segment.

```
isik:cloud:master
isik:home:laptop
isik:work:laptop
client:cloud:web1
client:cloud:db
```

Lowercase, hyphens inside a segment, same order every time, so `detssh ssh
list` and `ctrl-r ssh client:` group sensibly. The label doesn't imply a
user: that's the separate `user@host` you register, so the same box under
two users is two labels (`client:cloud:web1`, `client:cloud:web1-deploy`).

The label is also the salt, so it's part of what derives the key: renaming
one means a different key. It's safe to share - a salt isn't a secret, and
a guessable label like these adds nothing an attacker doesn't already
assume. All of the key's security rests on the seed passphrase.
