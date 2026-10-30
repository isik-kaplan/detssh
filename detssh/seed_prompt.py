"""The seed question in interactive mode: type your own, with a strength meter that redraws as
you type, or have detssh generate random words and type them back to show you saved them.

isik asks every other question; this one is the seed Setting's `prompt=`, so isik still
decides when it's asked and checks the answer. Hiding the passphrase and asking for it twice
are this module's job, since it replaces isik's own prompt. Nothing typed shows - no `*`
either - like isik's other secret questions.
"""

import sys

import click
import questionary
from prompt_toolkit import PromptSession
from prompt_toolkit.application.current import get_app
from prompt_toolkit.layout.processors import PasswordProcessor
from prompt_toolkit.styles import Style

from detssh.diceware import BITS_PER_WORD, DEFAULT_WORDS, MAX_WORDS, MIN_WORDS, generate, seed_from, strength_line
from detssh.strength import WEAK_SEED_BITS, meter, seed_bits


TYPE_OWN = "Type my own"
GENERATE = "Generate random words"
# Green from here up: about what 6 random words rate, the most docs/security.md asks for.
GOOD_SEED_BITS = 70
STYLE = Style.from_dict({"weak": "fg:ansired", "fair": "fg:ansiyellow", "good": "fg:ansigreen", "hint": "fg:ansigray"})
# Nothing for each typed character, not even prompt_toolkit's `*`, which would show the length.
HIDE_INPUT = PasswordProcessor(char="")


def _hidden(message, erase=False):
    """One line that shows nothing as it's typed, `message` redrawn on every keystroke when it's a
    function. With `erase`, the line and its message are erased from the screen once answered."""
    try:
        return PromptSession(erase_when_done=erase).prompt(message, input_processors=[HIDE_INPUT], style=STYLE)
    except (KeyboardInterrupt, EOFError):
        raise click.Abort() from None


def _strength_class(bits):
    if bits < WEAK_SEED_BITS:
        return "class:weak"
    return "class:fair" if bits < GOOD_SEED_BITS else "class:good"


def meter_message(question, typed):
    """The question with a meter for what's typed so far, the input on the line below."""
    if not typed:
        status = [("class:hint", "type to see how strong it is")]
    else:
        bits = seed_bits(typed)
        status = [(_strength_class(bits), meter(bits))]
    return [("", f"{question}  "), *status, ("", "\n› ")]


def _typed_so_far():
    return get_app().current_buffer.text


def ask_own(question):
    while True:
        typed = _hidden(lambda: meter_message(question, _typed_so_far()))
        if not typed:
            click.echo("Error: the seed can't be empty.")
            continue
        if _hidden("Repeat for confirmation: ") == typed:
            return typed
        click.echo("Error: The two entered values do not match.")


def type_back_message(seed, count, missed):
    """The generated words, what they're worth, and the question to type them back - one message,
    so the prompt erases all of it once they're typed back right."""
    message = [
        ("", "\n  "),
        ("bold", seed),
        ("", f"\n\n  {strength_line(count)}\n"),
        ("", "  Write these down now: they're the only way to get this key back. The seed is the words,\n"),
        ("", "  one space between each.\n\n"),
    ]
    if missed:
        message.append(("class:weak", "That doesn't match - check each word against what you wrote down.\n"))
    message.append(("", "Type them back to confirm you saved them: "))
    return message


def ask_generated():
    count = click.prompt("How many words?", default=DEFAULT_WORDS, type=click.IntRange(MIN_WORDS, MAX_WORDS))
    seed = seed_from(generate(count))
    missed = False
    while True:
        # Erased once answered, so the words don't stay on the screen.
        typed = _hidden(type_back_message(seed, count, missed), erase=True)
        if " ".join(typed.lower().split()) == seed:
            click.echo(f"Seed confirmed: {count} words, ~{count * BITS_PER_WORD:.0f} bits.")
            return seed
        missed = True


def ask_seed(question, default):
    """The seed Setting's `prompt=`. Without a terminal - piped input, a test's runner - it's the
    hidden, confirmed line isik would have asked."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return click.prompt(question, hide_input=True, confirmation_prompt=True)
    choice = questionary.select("Seed:", choices=[TYPE_OWN, GENERATE], default=TYPE_OWN).ask()
    if choice is None:  # questionary's answer to Ctrl-C
        raise click.Abort()
    return ask_own(question) if choice == TYPE_OWN else ask_generated()
