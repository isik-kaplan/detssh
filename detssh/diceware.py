"""Generate a seed of random words: `detssh seed`.

A seed you pick yourself follows patterns an attacker can guess; one picked by a
cryptographic random number generator doesn't, so its strength is exact - about 12.9
bits a word from the EFF large wordlist's 7776 (docs/security.md). Words come from
`secrets`, never `random`.
"""

import math
import secrets
from functools import cache
from importlib.resources import files

import click


WORDLIST = "wordlists/eff_large_wordlist.txt"
WORDLIST_SIZE = 7776  # 6^5: five dice
BITS_PER_WORD = math.log2(WORDLIST_SIZE)
DEFAULT_WORDS = 6
# 5 words is what docs/security.md asks for at least; past 20 nobody types it back right.
MIN_WORDS = 5
MAX_WORDS = 20


@cache
def wordlist():
    """The EFF large wordlist's words, in roll order. Each line is `<five dice> <TAB> <word>`."""
    lines = files("detssh").joinpath(WORDLIST).read_text(encoding="ascii").splitlines()
    return tuple(line.split("\t")[1] for line in lines)


def generate(count=DEFAULT_WORDS):
    words = wordlist()
    return [secrets.choice(words) for _ in range(count)]


def seed_from(words):
    """The seed a list of words makes: lowercase, one space between each - what you type later."""
    return " ".join(words)


def strength_line(count):
    return f"~{count * BITS_PER_WORD:.0f} bits: {count} random words from the EFF large wordlist ({WORDLIST_SIZE})"


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--words",
    type=click.IntRange(MIN_WORDS, MAX_WORDS),
    default=DEFAULT_WORDS,
    show_default=True,
    help="How many words.",
)
def seed(words):
    """Print a random seed to use with detssh: words from the EFF large wordlist, picked with
    Python's `secrets`. Derives nothing, so you can write it down first.

    The seed is the words exactly as printed, one space between each. Only the words go to
    stdout, so `detssh seed | pbcopy` copies just the seed.
    """
    click.echo(seed_from(generate(words)))
    click.echo(strength_line(words), err=True)
    click.echo("Write it down: it's the only way to get your keys back. Run again for a different one.", err=True)
