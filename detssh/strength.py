"""Warn before deriving from a seed that looks weak.

Anyone with a public key can guess seeds offline, so a weak seed is the one way to lose
a detssh key without anyone touching your machine. zxcvbn estimates how many guesses a
seed takes. It spots common passwords, keyboard runs, repeats, dates and short famous
phrases, so a low estimate is worth stopping for. It rates each word on its own,
though, so a quote or a sentence comes out far stronger than it is: a seed that passes
isn't strong, only not obviously weak. docs/security.md has what makes one strong.
"""

import math
import re

import click
from zxcvbn import zxcvbn


# 5 random diceware words, what docs/security.md asks for, rate about 2^55 here. 4 rate below
# 2^50, along with famous quotes and anything built on a common password.
WEAK_SEED_BITS = 50
SECURITY_DOCS = "https://github.com/isik-kaplan/detssh/blob/master/docs/security.md#how-strong-the-seed-should-be"
MAX_SCORE = 10
BITS_PER_POINT = 10
# zxcvbn rates each separator as a random character, so "may the force be with you" would pass
# where "maytheforcebewithyou" doesn't. Guessers try the usual separators anyway: rate without them.
SEPARATORS = re.compile(r"[\s\-_.,]+")
# zxcvbn refuses longer input. A seed longer than this is rated by its start, which can only
# make it look weaker than it is, never stronger.
ZXCVBN_MAX_LENGTH = 72


def seed_bits(seed, user_inputs=()):
    """About how many bits of guessing zxcvbn thinks the seed takes. `user_inputs` are
    strings an attacker knows - the label, the comment - so a seed built from them rates low."""
    rated = SEPARATORS.sub("", seed)[:ZXCVBN_MAX_LENGTH]
    return math.log2(zxcvbn(rated, user_inputs=list(user_inputs))["guesses"])


def score(bits):
    """1-10, a point per 10 bits: the weak cutoff falls between 4 and 5, and 10 is 100 bits."""
    return max(1, min(MAX_SCORE, math.floor(bits / BITS_PER_POINT)))


def meter(bits):
    """`[█████░░░░░] 5/10 · ~52 bits` - what the seed prompt shows as you type."""
    points = score(bits)
    return f"[{'█' * points}{'░' * (MAX_SCORE - points)}] {points}/{MAX_SCORE} · ~{bits:.0f} bits"


def _known_words(label, comment):
    return [part for text in (label, comment) for part in (text, *re.split(r"[:\-_./@\s]+", text)) if part]


def confirm_seed_strength(seed, label, comment, accept_weak_seed, interactive):
    """Stop on a seed that looks weak, before any derivation. Flag mode fails unless
    --accept-weak-seed is passed; interactive mode warns and asks, defaulting to no."""
    if accept_weak_seed:
        return
    bits = seed_bits(seed, _known_words(label, comment))
    if bits >= WEAK_SEED_BITS:
        return

    problem = (
        f"The seed looks weak: about 2^{bits:.0f} guesses would find it, and anyone with your public key "
        f"can try them offline. Aim for 5-6 random diceware words: {SECURITY_DOCS}"
    )
    if not interactive:
        raise click.UsageError(f"{problem} Pass --accept-weak-seed to use it anyway.")
    click.echo(f"Warning: {problem}")
    if not click.confirm("Use it anyway?", default=False):
        raise click.Abort()
