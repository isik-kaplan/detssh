import io

import click
import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.output.vt100 import Vt100_Output

from detssh import seed_prompt
from detssh.seed_prompt import (
    GENERATE,
    HIDE_INPUT,
    STYLE,
    TYPE_OWN,
    _hidden,
    _typed_so_far,
    ask_generated,
    ask_own,
    ask_seed,
    meter_message,
    type_back_message,
)


class Replies:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.messages = []
        self.keywords = []

    def __call__(self, message, **keywords):
        self.messages.append(message)
        self.keywords.append(keywords)
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


def _select(answer):
    return lambda message, choices, default: type("Q", (), {"ask": lambda self: answer})()


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)


def test_without_a_terminal_it_asks_a_hidden_confirmed_line(monkeypatch):
    asked = []
    monkeypatch.setattr(click, "prompt", lambda message, **keywords: asked.append((message, keywords)) or "s")

    assert ask_seed("Seed passphrase", None) == "s"
    assert asked == [("Seed passphrase", {"hide_input": True, "confirmation_prompt": True})]


@pytest.mark.parametrize(("stdin", "stdout"), [(True, False), (False, True)])
def test_both_ends_must_be_a_terminal_for_the_live_prompt(monkeypatch, stdin, stdout):
    monkeypatch.setattr("sys.stdin.isatty", lambda: stdin)
    monkeypatch.setattr("sys.stdout.isatty", lambda: stdout)
    monkeypatch.setattr(click, "prompt", lambda message, **keywords: "plain")
    monkeypatch.setattr(seed_prompt.questionary, "select", lambda *a, **k: pytest.fail("asked the live prompt"))

    assert ask_seed("Seed passphrase", None) == "plain"


def test_the_choice_offers_own_first_then_generated(monkeypatch, terminal):
    asked = []

    def select(message, choices, default):
        asked.append((message, choices, default))
        return type("Q", (), {"ask": lambda self: TYPE_OWN})()

    monkeypatch.setattr(seed_prompt.questionary, "select", select)
    monkeypatch.setattr(seed_prompt, "ask_own", lambda question: "own")

    ask_seed("Seed passphrase", None)

    assert asked == [("Seed:", ["Type my own", "Generate random words"], "Type my own")]


def test_in_a_terminal_it_asks_own_or_generated_first(monkeypatch, terminal):
    monkeypatch.setattr(seed_prompt, "ask_own", lambda question: f"own: {question}")
    monkeypatch.setattr(seed_prompt, "ask_generated", lambda: "generated")

    monkeypatch.setattr(seed_prompt.questionary, "select", _select(TYPE_OWN))
    assert ask_seed("Seed passphrase", None) == "own: Seed passphrase"

    monkeypatch.setattr(seed_prompt.questionary, "select", _select(GENERATE))
    assert ask_seed("Seed passphrase", None) == "generated"


def test_ctrl_c_at_the_choice_aborts(monkeypatch, terminal):
    monkeypatch.setattr(seed_prompt.questionary, "select", _select(None))
    with pytest.raises(click.Abort):
        ask_seed("Seed passphrase", None)


def test_the_meter_message_hints_until_something_is_typed():
    assert meter_message("Seed passphrase", "") == [
        ("", "Seed passphrase  "),
        ("class:hint", "type to see how strong it is"),
        ("", "\n› "),
    ]


@pytest.mark.parametrize(
    ("bits", "style"),
    [(49.99, "class:weak"), (50, "class:fair"), (69.99, "class:fair"), (70, "class:good")],
)
def test_the_meter_turns_yellow_at_the_weak_cutoff_and_green_at_70_bits(monkeypatch, bits, style):
    monkeypatch.setattr(seed_prompt, "seed_bits", lambda typed: bits)
    _, (status_style, _), _ = meter_message("Seed passphrase", "x")
    assert status_style == style


@pytest.mark.parametrize(
    ("typed", "style"),
    [
        ("password", "class:weak"),
        ("letterbeginbeyondwatchgrief", "class:fair"),
        ("letter begin beyond watch grief tumble", "class:good"),
    ],
)
def test_the_meter_is_colored_by_strength(typed, style):
    _, (status_style, status), _ = meter_message("Seed passphrase", typed)
    assert status_style == style
    assert "/10 · ~" in status


def test_own_seed_is_hidden_metered_and_confirmed(monkeypatch):
    hidden = Replies("a seed", "a seed")
    monkeypatch.setattr(seed_prompt, "_hidden", hidden)
    monkeypatch.setattr(seed_prompt, "_typed_so_far", lambda: "")

    assert ask_own("Seed passphrase") == "a seed"
    assert hidden.messages[0]()[0] == ("", "Seed passphrase  ")
    assert hidden.messages[1] == "Repeat for confirmation: "


def test_own_seed_meters_what_has_been_typed_so_far(monkeypatch):
    hidden = Replies("a seed", "a seed")
    monkeypatch.setattr(seed_prompt, "_hidden", hidden)
    monkeypatch.setattr(seed_prompt, "_typed_so_far", lambda: "password")

    ask_own("Seed passphrase")

    assert hidden.messages[0]() == meter_message("Seed passphrase", "password")


def test_own_seed_asks_again_when_empty_or_not_confirmed(monkeypatch, capsys):
    monkeypatch.setattr(seed_prompt, "_hidden", Replies("", "one", "two", "three", "three"))

    assert ask_own("Seed passphrase") == "three"
    assert capsys.readouterr().out.splitlines() == [
        "Error: the seed can't be empty.",
        "Error: The two entered values do not match.",
    ]


def _session(calls, reply="typed"):
    def session(**keywords):
        calls.append(keywords)

        def prompt(self, message, **keywords):
            calls.append((message, keywords))
            if isinstance(reply, BaseException):
                raise reply
            return reply

        return type("Session", (), {"prompt": prompt})()

    return session


@pytest.mark.parametrize("erase", [False, True])
def test_the_hidden_prompt_hides_the_input_and_colors_the_meter(monkeypatch, erase):
    calls = []
    monkeypatch.setattr(seed_prompt, "PromptSession", _session(calls))

    assert _hidden("Seed: ", erase=erase) == "typed"
    assert calls == [{"erase_when_done": erase}, ("Seed: ", {"input_processors": [HIDE_INPUT], "style": STYLE})]


def test_the_hidden_prompt_stays_on_screen_unless_asked_to_erase(monkeypatch):
    calls = []
    monkeypatch.setattr(seed_prompt, "PromptSession", _session(calls))

    _hidden("Seed: ")

    assert calls[0] == {"erase_when_done": False}


def test_hiding_shows_nothing_for_each_character():
    assert HIDE_INPUT.char == ""


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), EOFError()])
@pytest.mark.parametrize("erase", [False, True])
def test_ctrl_c_or_ctrl_d_while_typing_aborts(monkeypatch, interrupt, erase):
    monkeypatch.setattr(seed_prompt, "PromptSession", _session([], reply=interrupt))
    with pytest.raises(click.Abort):
        _hidden("Seed passphrase", erase=erase)


@pytest.mark.parametrize("erase", [False, True])
def test_the_hidden_prompt_draws_neither_what_is_typed_nor_stars(erase):
    screen = io.StringIO()
    output = Vt100_Output(screen, lambda: Size(rows=24, columns=80))
    with create_pipe_input() as pipe, create_app_session(input=pipe, output=output):
        pipe.send_text("plaza cobweb\r")
        assert _hidden("Type them back: ", erase=erase) == "plaza cobweb"

    drawn = screen.getvalue()
    assert "Type them back:" in drawn
    assert "plaza" not in drawn
    assert "cobweb" not in drawn
    assert "*" not in drawn


def test_the_hidden_prompt_redraws_its_message_with_each_keystroke():
    seen = []
    with create_pipe_input() as pipe, create_app_session(input=pipe, output=DummyOutput()):
        pipe.send_text("abc")
        pipe.send_text("\r")
        typed = _hidden(lambda: seen.append(_typed_so_far()) or "Seed: ")

    assert typed == "abc"
    assert seen[0] == ""
    assert seen[-1] == "abc"


def test_generated_words_are_typed_back_hidden_in_a_prompt_that_erases_itself(monkeypatch, capsys):
    monkeypatch.setattr(click, "prompt", lambda message, **keywords: 5)
    monkeypatch.setattr(seed_prompt, "generate", lambda count: ["plaza", "cobweb", "untried", "mutt", "repave"])
    typed = Replies("plaza cobweb", "  Plaza  COBWEB untried mutt repave ")
    monkeypatch.setattr(seed_prompt, "_hidden", typed)

    assert ask_generated() == "plaza cobweb untried mutt repave"
    assert typed.messages == [
        type_back_message("plaza cobweb untried mutt repave", 5, missed=False),
        type_back_message("plaza cobweb untried mutt repave", 5, missed=True),
    ]
    assert typed.keywords == [{"erase": True}, {"erase": True}]
    assert capsys.readouterr().out == "Seed confirmed: 5 words, ~65 bits.\n"


def test_the_type_back_message_shows_the_words_bold_and_any_miss():
    first = type_back_message("plaza cobweb", 5, missed=False)
    again = type_back_message("plaza cobweb", 5, missed=True)

    assert first == [
        ("", "\n  "),
        ("bold", "plaza cobweb"),
        ("", "\n\n  ~65 bits: 5 random words from the EFF large wordlist (7776)\n"),
        ("", "  Write these down now: they're the only way to get this key back. The seed is the words,\n"),
        ("", "  one space between each.\n\n"),
        ("", "Type them back to confirm you saved them: "),
    ]
    assert again[:-1] == [
        *first[:-1],
        ("class:weak", "That doesn't match - check each word against what you wrote down.\n"),
    ]


def test_ctrl_c_while_typing_the_words_back_aborts(monkeypatch):
    monkeypatch.setattr(click, "prompt", lambda message, **keywords: 5)
    monkeypatch.setattr(seed_prompt, "_hidden", Replies(click.Abort()))
    with pytest.raises(click.Abort):
        ask_generated()


def test_the_word_count_question_offers_six_and_takes_five_to_twenty(monkeypatch):
    asked = []
    monkeypatch.setattr(click, "prompt", lambda message, **keywords: asked.append((message, keywords)) or 6)
    monkeypatch.setattr(seed_prompt, "_hidden", Replies(click.Abort()))

    with pytest.raises(click.Abort):
        ask_generated()

    ((message, keywords),) = asked
    assert message == "How many words?"
    assert keywords["default"] == 6
    assert (keywords["type"].min, keywords["type"].max) == (5, 20)
