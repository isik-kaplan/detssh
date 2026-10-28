import click
import pytest
from click.testing import CliRunner

from detssh.cli import main
from detssh.strength import (
    BITS_PER_POINT,
    MAX_SCORE,
    WEAK_SEED_BITS,
    ZXCVBN_MAX_LENGTH,
    _known_words,
    confirm_seed_strength,
    meter,
    score,
    seed_bits,
)


pytestmark = pytest.mark.seed_strength

WEAK = "maytheforcebewithyou"
STRONG = "letter begin beyond watch grief tumble"


@pytest.mark.parametrize(
    "seed",
    ["password", "hunter2", "qwertyuiopasdfghjkl", "aaaaaaaaaaaaaaaaaaaaaaaa", "correcthorsebatterystaple", WEAK],
)
def test_common_passwords_patterns_and_famous_phrases_rate_weak(seed):
    assert seed_bits(seed) < WEAK_SEED_BITS


@pytest.mark.parametrize("seed", ["may the force be with you", "you-can't-handle-the-truth", "to.infinity.and.beyond"])
def test_separators_dont_make_a_famous_phrase_pass(seed):
    assert seed_bits(seed) < WEAK_SEED_BITS


@pytest.mark.parametrize("seed", ["letterbeginbeyondwatchgrief", STRONG])
def test_five_or_more_random_words_rate_strong_enough(seed):
    assert seed_bits(seed) >= WEAK_SEED_BITS


def test_a_seed_built_from_the_label_rates_lower_than_the_same_seed_alone():
    seed = "kittiwake quorum ostrich"
    assert seed_bits(seed) >= WEAK_SEED_BITS
    assert seed_bits(seed, _known_words("kittiwake:quorum:ostrich", "")) < WEAK_SEED_BITS
    assert seed_bits(seed, _known_words("", "kittiwake-quorum ostrich")) < WEAK_SEED_BITS


def test_known_words_are_the_label_and_comment_whole_and_split_into_parts():
    assert _known_words("isik:home-laptop", "me@work") == [
        "isik:home-laptop",
        "isik",
        "home",
        "laptop",
        "me@work",
        "me",
        "work",
    ]
    assert _known_words("", "") == []


def test_a_seed_longer_than_zxcvbn_takes_is_rated_by_its_start():
    start = "a" * ZXCVBN_MAX_LENGTH
    assert seed_bits(start + "letterbeginbeyond") == seed_bits(start)


def test_the_length_limit_counts_after_separators_are_dropped():
    # 73 characters with the spaces, 37 without: rated whole, so it stays well above the cutoff.
    assert seed_bits(" " * 36 + "letterbeginbeyondwatchgrieftumble") == seed_bits("letterbeginbeyondwatchgrieftumble")


def test_a_strong_seed_goes_through_without_a_word(capsys):
    confirm_seed_strength(STRONG, "", "", accept_weak_seed=False, interactive=True)
    assert capsys.readouterr().out == ""


def test_a_seed_right_at_the_cutoff_passes_and_one_just_below_it_doesnt(monkeypatch):
    monkeypatch.setattr("detssh.strength.seed_bits", lambda seed, user_inputs: WEAK_SEED_BITS)
    confirm_seed_strength("at", "", "", accept_weak_seed=False, interactive=False)

    monkeypatch.setattr("detssh.strength.seed_bits", lambda seed, user_inputs: WEAK_SEED_BITS - 0.01)
    with pytest.raises(click.UsageError):
        confirm_seed_strength("below", "", "", accept_weak_seed=False, interactive=False)


def test_accept_weak_seed_skips_the_check_entirely(monkeypatch):
    monkeypatch.setattr("detssh.strength.zxcvbn", lambda *args, **kwargs: pytest.fail("rated the seed"))
    confirm_seed_strength(WEAK, "", "", accept_weak_seed=True, interactive=False)


def test_interactive_mode_warns_and_goes_on_when_told_to(monkeypatch, capsys):
    asked = []
    monkeypatch.setattr(click, "confirm", lambda message, default: asked.append((message, default)) or True)

    confirm_seed_strength(WEAK, "", "", accept_weak_seed=False, interactive=True)

    assert asked == [("Use it anyway?", False)]
    out = capsys.readouterr().out
    assert out.startswith("Warning: The seed looks weak: about 2^")
    assert "github.com/isik-kaplan/detssh/blob/master/docs/security.md#how-strong-the-seed-should-be" in out


def test_interactive_mode_aborts_when_declined(monkeypatch):
    monkeypatch.setattr(click, "confirm", lambda message, default: False)
    with pytest.raises(click.Abort):
        confirm_seed_strength(WEAK, "", "", accept_weak_seed=False, interactive=True)


def _flag_run(tmp_path, seed, *extra):
    return CliRunner().invoke(
        main,
        ["--kdf", "pbkdf2", "--iterations", "2", "--seed", seed, "--output", str(tmp_path / "key"), *extra],
    )


def test_flag_mode_refuses_a_weak_seed_before_deriving(tmp_path):
    result = _flag_run(tmp_path, WEAK)

    assert result.exit_code == 2
    assert "The seed looks weak" in result.output
    assert "Pass --accept-weak-seed to use it anyway." in result.output
    assert "Deriving key" not in result.output
    assert not (tmp_path / "key").exists()


def test_flag_mode_takes_a_weak_seed_with_accept_weak_seed(tmp_path):
    result = _flag_run(tmp_path, WEAK, "--accept-weak-seed")

    assert result.exit_code == 0, result.output
    assert (tmp_path / "key").exists()


def test_flag_mode_takes_a_strong_seed_without_the_flag(tmp_path):
    result = _flag_run(tmp_path, STRONG)

    assert result.exit_code == 0, result.output
    assert "weak" not in result.output


def test_the_check_counts_the_label_against_the_seed(tmp_path):
    seed = "kittiwake quorum ostrich"  # about 2^56 alone, 2^27 knowing the label
    alone = _flag_run(tmp_path, seed)
    with_label = _flag_run(tmp_path, seed, "--label", "kittiwake:quorum:ostrich", "--overwrite-files")

    assert alone.exit_code == 0, alone.output
    assert with_label.exit_code == 2
    assert "The seed looks weak" in with_label.output


def test_authorize_checks_the_seed_too(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            "--kdf",
            "pbkdf2",
            "--iterations",
            "2",
            "--seed",
            WEAK,
            "--authorize",
            "--authorized-keys",
            str(tmp_path / "ak"),
        ],
    )

    assert result.exit_code == 2
    assert "The seed looks weak" in result.output
    assert not (tmp_path / "ak").exists()


def test_a_full_interactive_run_can_decline_a_weak_seed(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        "questionary.select",
        lambda message, choices, default: type("Q", (), {"ask": lambda self: default})(),
    )
    answers = [
        WEAK,  # seed passphrase
        WEAK,  # ... confirmed
        "",  # label
        "",  # argon2 iterations
        "",  # argon2 memory
        "",  # argon2 parallelism
        "",  # salt digest size
        str(tmp_path / "key"),  # output path
        "",  # comment
        "",  # key passphrase: none
        "",  # ... confirmed
        "",  # use it anyway? default: no
    ]

    result = CliRunner().invoke(main, [], input="\n".join(answers) + "\n")

    assert result.exit_code == 1
    assert "Warning: The seed looks weak" in result.output
    assert "Deriving key" not in result.output
    assert not (tmp_path / "key").exists()


@pytest.mark.parametrize(
    ("bits", "points"), [(0, 1), (19.9, 1), (20, 2), (49.9, 4), (50, 5), (99.9, 9), (100, 10), (300, 10)]
)
def test_score_is_a_point_per_ten_bits_from_one_to_ten(bits, points):
    assert score(bits) == points


def test_the_weak_cutoff_falls_between_two_scores():
    assert WEAK_SEED_BITS % BITS_PER_POINT == 0
    assert score(WEAK_SEED_BITS - 0.01) < score(WEAK_SEED_BITS)


def test_the_meter_draws_the_score_and_the_estimate():
    assert meter(52.4) == "[█████░░░░░] 5/10 · ~52 bits"
    assert meter(0) == f"[█{'░' * (MAX_SCORE - 1)}] 1/10 · ~0 bits"
    assert meter(120) == "[██████████] 10/10 · ~120 bits"
