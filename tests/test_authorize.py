import stat

import click
import pytest
import questionary
from click.testing import CliRunner

from detssh.backends.base import authorize_and_recap
from detssh.cli import AUTHORIZE_MODE, GENERATE_MODE, main
from detssh.keygen import (
    authorize_public_key,
    default_authorized_keys_path,
    keypair_from_seed,
    public_key_line,
)


SEED = b"\x01" * 32
OTHER_SEED = b"\x02" * 32
FLAG_RUN = ["--kdf", "pbkdf2", "--iterations", "2", "--seed", "s", "--label", "work"]


def _public_key(seed=SEED):
    return keypair_from_seed(seed)[1]


def _blob(seed=SEED):
    return public_key_line(_public_key(seed)).rstrip(b"\n")


def _fake_select(answer_for_mode):
    """Pick `answer_for_mode` at the mode question and pbkdf2 at the KDF picker, recording
    every question asked so tests can check which ones came up."""
    asked = []

    def select(message, choices, default):
        asked.append((message, tuple(choices), default))
        if message == "What do you want to do?":
            answer = answer_for_mode
        else:
            answer = "pbkdf2" if "pbkdf2" in choices else default
        return type("Q", (), {"ask": lambda self: answer})()

    return select, asked


def test_default_authorized_keys_path_is_in_ssh_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_authorized_keys_path() == tmp_path / ".ssh" / "authorized_keys"


def test_public_key_line_is_type_blob_comment_newline():
    line = public_key_line(_public_key(), "me@work laptop")
    key_type, blob, comment = line.decode("utf-8").rstrip("\n").split(" ", 2)
    assert (key_type, comment) == ("ssh-ed25519", "me@work laptop")
    assert line == f"ssh-ed25519 {blob} me@work laptop\n".encode()


def test_public_key_line_without_comment_has_no_trailing_space():
    assert public_key_line(_public_key()) == _blob() + b"\n"
    assert not _blob().endswith(b" ")


def test_public_key_line_rejects_a_comment_with_a_newline():
    with pytest.raises(ValueError, match="^comment must not contain newlines$"):
        public_key_line(_public_key(), "a\nb")


def test_authorize_creates_ssh_dir_and_file_with_private_modes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / ".ssh" / "authorized_keys"

    assert authorize_public_key(_public_key(), path, comment="c") is True

    assert path.read_bytes() == _blob() + b" c\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_authorize_appends_after_existing_keys(tmp_path):
    path = tmp_path / "authorized_keys"
    path.write_bytes(_blob(OTHER_SEED) + b" other\n")

    assert authorize_public_key(_public_key(), path) is True

    assert path.read_bytes() == _blob(OTHER_SEED) + b" other\n" + _blob() + b"\n"


def test_authorize_adds_the_missing_newline_before_appending(tmp_path):
    path = tmp_path / "authorized_keys"
    path.write_bytes(b"ssh-rsa AAAA old")

    authorize_public_key(_public_key(), path)

    assert path.read_bytes() == b"ssh-rsa AAAA old\n" + _blob() + b"\n"


def test_authorize_into_an_empty_file_adds_no_leading_newline(tmp_path):
    path = tmp_path / "authorized_keys"
    path.write_bytes(b"")

    authorize_public_key(_public_key(), path)

    assert path.read_bytes() == _blob() + b"\n"


def test_authorize_skips_a_key_already_present_under_other_options_and_comment(tmp_path):
    path = tmp_path / "authorized_keys"
    original = b'from="10.0.0.1" ' + _blob() + b" old comment\n"
    path.write_bytes(original)

    assert authorize_public_key(_public_key(), path, comment="new comment") is False

    assert path.read_bytes() == original


def test_authorize_only_matches_the_whole_key_blob_not_a_substring(tmp_path):
    path = tmp_path / "authorized_keys"
    key_blob = _blob().split()[1]
    path.write_bytes(b"ssh-ed25519 " + key_blob + b"XYZ\n")

    assert authorize_public_key(_public_key(), path) is True


def test_authorize_keeps_an_existing_files_mode(tmp_path):
    path = tmp_path / "authorized_keys"
    path.write_bytes(b"")
    path.chmod(0o640)

    authorize_public_key(_public_key(), path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_authorize_outside_ssh_dir_needs_create_parent_dirs(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / "elsewhere" / "authorized_keys"

    with pytest.raises(FileNotFoundError):
        authorize_public_key(_public_key(), path)

    assert authorize_public_key(_public_key(), path, create_parent_dirs=True) is True
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def _invoke_recap(path):
    @click.command()
    def cmd():
        authorize_and_recap(SEED, path, "c", recap=(("kdf", "pbkdf2"),))

    return CliRunner().invoke(cmd)


def test_authorize_and_recap_reports_the_added_line_then_the_recap(tmp_path):
    path = tmp_path / "authorized_keys"

    result = _invoke_recap(path)

    assert result.exit_code == 0, result.output
    assert result.output == (
        f"Added public key to {path}:\n"
        f"  {_blob().decode()} c\n"
        "\n"
        "To recreate this exact key, remember your passphrase (keep it secret) plus:\n"
        "  kdf                pbkdf2\n"
        "  algorithm          ed25519\n"
    )


def test_authorize_and_recap_says_when_the_key_was_already_there(tmp_path):
    path = tmp_path / "authorized_keys"
    path.write_bytes(_blob() + b"\n")

    result = _invoke_recap(path)

    assert result.output.splitlines()[:2] == [
        f"Public key already in {path}, left it unchanged:",
        f"  {_blob().decode()} c",
    ]


def test_authorize_and_recap_turns_os_errors_into_a_clean_message(tmp_path):
    path = tmp_path / "authorized_keys"
    path.mkdir()

    result = _invoke_recap(path)

    assert result.exit_code == 1
    assert result.exc_info[0] is SystemExit
    assert result.output == f"Error: couldn't write {path}: Is a directory\n"


def test_flag_mode_authorizes_the_same_public_key_a_full_run_writes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    pair = tmp_path / "pair" / "id_ed25519"

    full = CliRunner().invoke(main, [*FLAG_RUN, "--output", str(pair), "--create-parent-dirs"])
    authorized = CliRunner().invoke(main, [*FLAG_RUN, "--authorize"])

    assert full.exit_code == 0, full.output
    assert authorized.exit_code == 0, authorized.output
    ssh_dir = tmp_path / ".ssh"
    assert (ssh_dir / "authorized_keys").read_bytes() == (tmp_path / "pair" / "id_ed25519.pub").read_bytes()
    assert sorted(p.name for p in ssh_dir.iterdir()) == ["authorized_keys"]
    assert f"Added public key to {ssh_dir / 'authorized_keys'}:" in authorized.output
    assert "Wrote private key" not in authorized.output


def test_flag_mode_appends_to_an_existing_authorized_keys_without_asking(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / ".ssh" / "authorized_keys"
    path.parent.mkdir()
    path.write_bytes(b"ssh-rsa AAAA old\n")

    result = CliRunner().invoke(main, [*FLAG_RUN, "--authorize", "--comment", "work"])

    assert result.exit_code == 0, result.output
    assert "Overwrite?" not in result.output
    lines = path.read_bytes().splitlines()
    assert lines[0] == b"ssh-rsa AAAA old"
    assert lines[1].endswith(b" work")


def test_flag_mode_expands_tilde_in_authorized_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    result = CliRunner().invoke(
        main, [*FLAG_RUN, "--authorize", "--authorized-keys", "~/.ssh/other_keys", "--create-parent-dirs"]
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / ".ssh" / "other_keys").exists()


def test_flag_mode_requires_create_parent_dirs_outside_ssh_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / "srv" / "authorized_keys"

    refused = CliRunner().invoke(main, [*FLAG_RUN, "--authorize", "--authorized-keys", str(path)])
    allowed = CliRunner().invoke(
        main, [*FLAG_RUN, "--authorize", "--authorized-keys", str(path), "--create-parent-dirs"]
    )

    assert refused.exit_code == 2
    assert "~/srv doesn't exist. Pass --create-parent-dirs to create it." in refused.output
    assert allowed.exit_code == 0, allowed.output
    assert path.exists()


def test_authorized_keys_needs_authorize(tmp_path):
    result = CliRunner().invoke(main, [*FLAG_RUN, "--authorized-keys", str(tmp_path / "k")])

    assert result.exit_code == 2
    assert "Error: --authorized-keys needs --authorize" in result.output
    assert "Deriving key" not in result.output


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--overwrite-files"], "--overwrite-files can't be used with --authorize: it only appends"),
        (["--output", "k"], "--output can't be used with --authorize: no private key is written"),
        (["--key-passphrase", "p"], "--key-passphrase can't be used with --authorize: no private key is written"),
        (["--register", "a@b"], "--register can't be used with --authorize: no private key is written"),
        (["--register-port", "22"], "--register-port can't be used with --authorize: no private key is written"),
    ],
)
def test_authorize_rejects_keypair_only_flags_before_deriving(extra, message):
    result = CliRunner().invoke(main, [*FLAG_RUN, "--authorize", *extra])

    assert result.exit_code == 2
    assert f"Error: {message}" in result.output
    assert "Deriving key" not in result.output


def _interactive_answers(*after_comment):
    return (
        "\n".join(
            [
                "s",  # seed passphrase
                "s",  # ... confirmed
                "work",  # label
                "2",  # pbkdf2 iterations
                "",  # salt digest size: default
                "",  # comment
                *after_comment,
            ]
        )
        + "\n"
    )


def test_interactive_mode_question_defaults_to_generating_a_keypair(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    select, asked = _fake_select(GENERATE_MODE)
    monkeypatch.setattr(questionary, "select", select)

    CliRunner().invoke(main, [], input="\n")

    assert asked[0] == ("What do you want to do?", (GENERATE_MODE, AUTHORIZE_MODE), GENERATE_MODE)
    assert GENERATE_MODE == "Generate a keypair (private + public key)"
    assert AUTHORIZE_MODE == "Only add the public key to an authorized_keys file"


def test_interactive_authorize_skips_private_key_prompts_and_registration(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    select, _ = _fake_select(AUTHORIZE_MODE)
    monkeypatch.setattr(questionary, "select", select)

    result = CliRunner().invoke(main, [], input=_interactive_answers(""))

    assert result.exit_code == 0, result.output
    assert "authorized_keys file to add the public key to [~/.ssh/authorized_keys]: " in result.output
    assert "Output path" not in result.output
    assert "Passphrase to encrypt" not in result.output
    assert "Register this key" not in result.output
    path = tmp_path / ".ssh" / "authorized_keys"
    assert path.read_bytes().startswith(b"ssh-ed25519 ")
    assert sorted(p.name for p in path.parent.iterdir()) == ["authorized_keys"]


def test_interactive_authorize_expands_tilde_and_asks_before_creating_parent_dirs(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    select, _ = _fake_select(AUTHORIZE_MODE)
    monkeypatch.setattr(questionary, "select", select)

    result = CliRunner().invoke(main, [], input=_interactive_answers("~/srv/authorized_keys", "y"))

    assert result.exit_code == 0, result.output
    assert "Warning: ~/srv is outside ~/.ssh." in result.output
    assert (tmp_path / "srv" / "authorized_keys").exists()


def test_authorize_flag_alone_stays_interactive_without_the_mode_question(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    select, asked = _fake_select(GENERATE_MODE)
    monkeypatch.setattr(questionary, "select", select)

    result = CliRunner().invoke(main, ["--authorize"], input=_interactive_answers(""))

    assert result.exit_code == 0, result.output
    assert [message for message, _, _ in asked] == ["KDF backend", "Salt hash algorithm"]
    assert (tmp_path / ".ssh" / "authorized_keys").exists()
    assert not (tmp_path / ".ssh" / "id_ed25519").exists()


def test_authorized_keys_flag_skips_its_prompt_in_interactive_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    select, _ = _fake_select(GENERATE_MODE)
    monkeypatch.setattr(questionary, "select", select)
    path = tmp_path / "keys"

    result = CliRunner().invoke(main, ["--authorize", "--authorized-keys", str(path)], input=_interactive_answers())

    assert result.exit_code == 0, result.output
    assert "authorized_keys file to add" not in result.output
    assert path.exists()


def test_authorize_creates_every_missing_parent_level(tmp_path):
    path = tmp_path / "a" / "b" / "authorized_keys"

    assert authorize_public_key(_public_key(), path, create_parent_dirs=True) is True
    assert path.exists()


def test_authorize_and_recap_does_not_create_parent_dirs_unless_asked(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / "missing" / "authorized_keys"

    result = _invoke_recap(path)

    assert result.exit_code == 1
    assert result.output == f"Error: couldn't write {path}: No such file or directory\n"


def test_authorized_keys_flag_rejects_a_directory(tmp_path):
    result = CliRunner().invoke(main, [*FLAG_RUN, "--authorize", "--authorized-keys", str(tmp_path)])

    assert result.exit_code == 2
    assert "is a directory" in result.output


def test_interactive_authorized_keys_prompt_rejects_a_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    select, _ = _fake_select(AUTHORIZE_MODE)
    monkeypatch.setattr(questionary, "select", select)
    path = tmp_path / "keys"

    result = CliRunner().invoke(main, [], input=_interactive_answers(str(tmp_path), str(path)))

    assert result.exit_code == 0, result.output
    assert "is a directory" in result.output
    assert path.exists()
