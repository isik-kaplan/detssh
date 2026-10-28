import hashlib
from importlib.resources import files

import pytest
from click.testing import CliRunner

from detssh import diceware
from detssh.cli import run
from detssh.diceware import (
    BITS_PER_WORD,
    MAX_WORDS,
    MIN_WORDS,
    WORDLIST,
    WORDLIST_SIZE,
    generate,
    seed,
    seed_from,
    strength_line,
    wordlist,
)
from detssh.strength import WEAK_SEED_BITS


EFF_LARGE_WORDLIST_SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"


def test_the_bundled_wordlist_is_the_eff_large_wordlist_byte_for_byte():
    data = files("detssh").joinpath(WORDLIST).read_bytes()
    assert hashlib.sha256(data).hexdigest() == EFF_LARGE_WORDLIST_SHA256


def test_the_wordlist_has_7776_distinct_words_in_roll_order():
    words = wordlist()
    assert len(words) == len(set(words)) == WORDLIST_SIZE == 6**5
    assert (words[0], words[-1]) == ("abacus", "zoom")
    assert all(word.islower() and "\t" not in word for word in words)


def test_each_word_is_worth_about_12_9_bits():
    assert BITS_PER_WORD == pytest.approx(12.925, abs=0.001)


def test_words_are_picked_with_secrets(monkeypatch):
    picked = []
    monkeypatch.setattr(diceware.secrets, "choice", lambda words: picked.append(words) or words[len(picked)])

    assert generate(3) == ["abdomen", "abdominal", "abide"]
    assert picked == [wordlist()] * 3


def test_generate_makes_six_words_by_default():
    assert len(generate()) == 6


def test_a_seed_is_its_words_one_space_apart():
    assert seed_from(["plaza", "cobweb", "t-shirt"]) == "plaza cobweb t-shirt"


def test_the_fewest_words_allowed_are_above_the_weak_cutoff():
    assert MIN_WORDS * BITS_PER_WORD >= WEAK_SEED_BITS


def test_strength_line_says_bits_words_and_list():
    assert strength_line(6) == "~78 bits: 6 random words from the EFF large wordlist (7776)"


def test_the_seed_command_prints_only_the_words_on_stdout(monkeypatch):
    monkeypatch.setattr(diceware, "generate", lambda count: ["word"] * count)

    result = CliRunner().invoke(seed, ["--words", "5"])

    assert result.exit_code == 0, result.output
    assert result.stdout == "word word word word word\n"
    assert "~65 bits: 5 random words" in result.stderr
    assert "Write it down" in result.stderr


def test_the_seed_command_defaults_to_six_words():
    result = CliRunner().invoke(seed, [])

    assert result.exit_code == 0, result.output
    assert len(result.stdout.split()) == 6


@pytest.mark.parametrize("count", [MIN_WORDS - 1, MAX_WORDS + 1])
def test_the_seed_command_refuses_too_few_or_too_many_words(count):
    result = CliRunner().invoke(seed, ["--words", str(count)])

    assert result.exit_code == 2
    assert "--words" in result.output


def test_run_hardens_the_process_then_dispatches_seed(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr("detssh.cli.harden", lambda: calls.append("harden"))
    monkeypatch.setattr("sys.argv", ["detssh", "seed", "--words", "5"])

    with pytest.raises(SystemExit) as exit_info:
        run()

    assert exit_info.value.code == 0
    assert calls == ["harden"]
    assert len(capsys.readouterr().out.split()) == 5


def test_run_passes_the_seed_prog_name_through(monkeypatch, capsys):
    # sys.argv[0] isn't "detssh", so "Usage: detssh seed" can only come from prog_name=.
    monkeypatch.setattr("detssh.cli.harden", lambda: None)
    monkeypatch.setattr("sys.argv", ["not-detssh", "seed", "--help"])

    with pytest.raises(SystemExit) as exit_info:
        run()

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.splitlines()[0] == "Usage: detssh seed [OPTIONS]"
