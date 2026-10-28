# Security model

All of a key's security rests on the seed passphrase. Anyone who has it can
derive every key you've made with it, under every label, so where you type
it matters more than anything detssh does.

## How strong the seed should be

Your public key is public by design: it's in every `authorized_keys` you
add it to, on `github.com/<you>.keys`, and every server you log into sees
it. The label isn't secret either. So anyone can guess a seed, derive a key
from it with your label, and compare it to your public key - offline, as
fast as their hardware goes, with nothing to slow them down or notice.

The KDF is what makes each guess expensive. With the defaults (argon2id,
10 passes over 1 GiB), one guess takes about 1.5 seconds on an M4 Pro, and
even a top GPU manages only on the order of 100 a second, where a plain hash
would do billions. On rented GPUs that's very roughly $0.00001 a guess, so
what it costs to find your seed comes down to how many seeds it could have
been:

| Seed | Could be one of about | Cost to try them all |
|---|---|---|
| A famous quote, lyric or saying | 2^20 - 2^30 | under $10,000 |
| Any line from any film's subtitles, a little changed | 2^35 - 2^40 | $300,000 - $10 million |
| 5 random diceware words | 2^65 | ~$300 trillion |
| 6 random diceware words | 2^78 | ~$2 quintillion |

These are orders of magnitude, and hardware only gets cheaper, so leave
headroom. Use at least 5 words, 6 for a seed that guards anything that
matters, picked with dice, `detssh seed`, or a password manager's
passphrase generator from a list like the
[EFF large wordlist](https://www.eff.org/dice), where each word adds about
13 bits. Words you choose yourself aren't random, even
when they feel like it.

The 2^65 is a promise about the dice, not about every roll: dice can land
on something that reads like a sentence, or on the same word twice, and an
attacker trying human-looking seeds first would get to it early. It's
astronomically unlikely, but if the words read like a phrase, roll again -
throwing that sliver away costs nothing.

Only the 1.5 seconds above is measured. The GPU rate is an upper bound from
memory bandwidth (each guess moves about 30 GiB through memory; a top GPU
moves about 3 TB a second), the price is about $2-3 an hour for a rented
GPU, and the quote and subtitle counts are rough sizes of the lists an
attacker would try, plus variations. The diceware rows are exact: 7776^5
and 7776^6. Being off by 10x anywhere doesn't change the answer, since the
rows are billions of times apart.

Length isn't strength. A 15-word movie quote is long, but nobody guesses it
letter by letter: an attacker tries every line in quote collections and
subtitle archives, with the usual capitalization and punctuation variations,
so its strength is how many lines are in those lists, however long yours
is. The same goes for lyrics, scripture, book passages and anything else
that's been written down before. Swapping a word or two adds a few bits,
not the 50 or so it's missing.

A sentence nobody has written before does better, since no list has it: an
attacker has to generate it, most likely sentences first. Its strength is
in the words they couldn't have predicted, not its length:

- Grammar and stock frames ("I can't stand ... but I love ...", "with
  love", "and what") are nearly free to guess.
- Fixed pairs count once: after "ubiquitous", "presence" is a given.
- Fancy words come from a small, well-known set - "ineffable" and
  "ubiquitous" top every list of favorites.
- Personal facts (foods, pets, places, people) are the first thing someone
  targeting you tries.
- Each word that's ordinary but unrelated to the others ("garlic", "trees",
  "shrink") adds roughly 10-15 bits.

Most self-written sentences land somewhere between 2^30 and 2^60, and
there's no telling where from the inside - every sentence feels
unpredictable to whoever wrote it. If you'd rather remember a sentence than
a list of words, add 2-3 diceware words to it: the sentence makes it
memorable, and the dice give it a floor you can count on.

Raising the cost options helps less than it looks. Going from 10 to 100
iterations makes each guess 10 times dearer, which is about 3 bits, and
doubling the memory adds 1. One more diceware word adds 13, and costs you
nothing at derivation time. Keep the defaults and make the seed stronger.

### The weak-seed check

Before deriving, detssh rates the seed with
[zxcvbn](https://github.com/dwolfhub/zxcvbn-python) and stops if it would
take fewer than about 2^50 guesses. Interactive mode warns and asks whether
to go on, defaulting to no; flag mode fails unless you pass
`--accept-weak-seed`. Spaces and other separators are left out of the
rating, since guessers try them anyway, and the label and comment count as
known to the attacker, so a seed built from them rates low.

It catches common passwords, keyboard runs, repeats, dates and short famous
phrases - "may the force be with you" rates about 2^42. Five random
diceware words rate about 2^55 and pass. But zxcvbn rates each word on its
own, so it has no idea when words belong together: it rates the
self-written sentences above around 2^90-2^115, far above what they're
worth. Passing the check means the seed isn't obviously weak, not that it's
strong.

The meter on the interactive seed prompt shows the same estimate as you
type, a point per 10 bits: 4/10 and under is what the check stops, 5/10 is
the least it accepts. A seed from `detssh seed` or the wizard's "Generate
random words" doesn't need it - its strength is exact - and rates well above
the cutoff anyway (5 words never came in under 2^53 in 3000 tries).

## What's public

The label is the salt. It makes each label's key different, and since a
guess has to be derived again for every label, it keeps one derivation from
testing a guess against everyone's keys at once. Its job never needed it to
be secret, so you don't have to hide it: knowing your label tells an
attacker nothing about your seed, and they'd try the obvious ones anyway.
The same goes for the KDF and its settings. Two people sharing a label (say
`github`) do share a salt, so one derivation tests a guess against both;
namespaced labels like `isik:global:master` avoid that.

The label doesn't end up in the key either. A public key line ends in a
comment, which detssh leaves empty unless you pass `--comment`. It's free
text that takes no part in derivation or logging in, so you can change or
delete it in the `.pub` file or in `authorized_keys` whenever you like and
the key keeps working.

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
