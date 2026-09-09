import os
import stat
from unittest.mock import patch

import click
import pytest
import questionary
from click.testing import CliRunner

from detssh.backends.base import confirm_overwrite
from detssh.cli import _peek, _register_interactively, main, run
from detssh.keygen import default_output_path, keypair_from_seed, write_keypair
from detssh.registry import load_registry


def test_confirm_overwrite_accepts_plain_string_path(tmp_path):
    confirm_overwrite(str(tmp_path / "nonexistent"), overwrite_files=False)


def test_write_keypair_rejects_comment_with_newline(tmp_path):
    private_key, public_key = keypair_from_seed(b"0" * 32)
    key_path = tmp_path / "key"

    for bad_comment in ("line1\nline2", "line1\rline2"):
        with pytest.raises(ValueError, match="newline"):
            write_keypair(private_key, public_key, key_path, comment=bad_comment)

    assert not key_path.exists()


def test_missing_output_directory_gives_a_clean_error_not_a_traceback(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--kdf", "pbkdf2", "--seed", "x", "--output", str(tmp_path / "nonexistent_dir" / "key"), "--overwrite-files"],
    )

    assert result.exit_code != 0
    assert result.exc_info[0] is SystemExit
    assert "No such file or directory" in result.output


def test_scrypt_bad_cost_gives_a_clean_error_not_a_traceback(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--kdf", "scrypt", "--seed", "x", "--cost", "100", "--output", str(tmp_path / "key"), "--overwrite-files"],
    )

    assert result.exit_code != 0
    assert result.exc_info[0] is SystemExit
    assert "scrypt:" in result.output


def test_argon2_memory_too_low_gives_a_clean_error_not_a_traceback(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "argon2id",
            "--seed",
            "x",
            "--memory",
            "0",
            "--parallelism",
            "1",
            "--output",
            str(tmp_path / "key"),
            "--overwrite-files",
        ],
    )

    assert result.exit_code != 0
    assert result.exc_info[0] is SystemExit
    assert "argon2id:" in result.output


def test_pbkdf2_negative_iterations_gives_a_clean_error_not_a_traceback(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "pbkdf2",
            "--seed",
            "x",
            "--iterations",
            "-5",
            "--output",
            str(tmp_path / "key"),
            "--overwrite-files",
        ],
    )

    assert result.exit_code != 0
    assert result.exc_info[0] is SystemExit
    assert "pbkdf2:" in result.output


def test_bcrypt_pbkdf_zero_rounds_gives_a_clean_error_not_a_traceback(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "bcrypt_pbkdf",
            "--seed",
            "x",
            "--rounds",
            "0",
            "--output",
            str(tmp_path / "key"),
            "--overwrite-files",
        ],
    )

    assert result.exit_code != 0
    assert result.exc_info[0] is SystemExit
    assert "bcrypt_pbkdf:" in result.output


def test_peek_takes_last_occurrence_of_a_repeated_flag():
    args = ["--kdf", "argon2id", "--kdf", "pbkdf2"]
    assert _peek(args, "--kdf", "default") == "pbkdf2"


def test_peek_takes_last_occurrence_with_equals_form():
    args = ["--kdf=argon2id", "--kdf=pbkdf2"]
    assert _peek(args, "--kdf", "default") == "pbkdf2"


def test_repeated_kdf_flag_rejects_options_irrelevant_to_the_resolved_backend(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "argon2id",
            "--kdf",
            "pbkdf2",
            "--memory",
            "999",
            "--seed",
            "x",
            "--output",
            str(tmp_path / "key"),
            "--overwrite-files",
        ],
    )
    assert result.exit_code != 0
    assert "No such option" in result.output


def test_default_output_path_is_ssh_keygen_style(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_output_path() == tmp_path / ".ssh" / "id_ed25519"


def test_default_invocation_writes_to_ssh_dir_with_correct_permissions(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "pbkdf2", "--seed", "correct horse battery staple"])

    assert result.exit_code == 0, result.output
    key_path = tmp_path / ".ssh" / "id_ed25519"
    pub_path = tmp_path / ".ssh" / "id_ed25519.pub"
    assert key_path.exists()
    assert pub_path.exists()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / ".ssh").stat().st_mode) == 0o700


def test_overwriting_a_key_never_exposes_content_at_the_old_permissions(tmp_path):
    key_path = tmp_path / "key"
    key_path.write_text("stale content")
    key_path.chmod(0o644)

    private_key, public_key = keypair_from_seed(b"0" * 32)

    observed_modes = []
    real_fdopen = os.fdopen

    def spy_fdopen(fd, *args, **kwargs):
        observed_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return real_fdopen(fd, *args, **kwargs)

    with patch("os.fdopen", side_effect=spy_fdopen):
        write_keypair(private_key, public_key, key_path)

    assert observed_modes
    assert all(mode == 0o600 for mode in observed_modes)


def test_explicit_output_path_is_used_as_is(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    custom = tmp_path / "somewhere" / "mykey"
    custom.parent.mkdir()
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "pbkdf2", "--seed", "x", "--output", str(custom)])

    assert result.exit_code == 0, result.output
    assert custom.exists()
    assert not (tmp_path / ".ssh").exists()


def test_tilde_in_output_path_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "somewhere").mkdir()
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "pbkdf2", "--seed", "x", "--output", "~/somewhere/mykey"])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "somewhere" / "mykey").exists()


def test_hash_len_is_always_32(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "pbkdf2", "--seed", "x", "--output", str(tmp_path / "key")])

    assert result.exit_code == 0, result.output
    assert "hash-len           32" in result.output


def test_hash_len_is_not_a_cli_option(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(
        main, ["--kdf", "pbkdf2", "--seed", "x", "--output", str(tmp_path / "key"), "--hash-len", "16"]
    )

    assert result.exit_code != 0
    assert "No such option" in result.output


def test_comment_with_newline_is_rejected_and_writes_nothing(tmp_path):
    key_path = tmp_path / "key"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "pbkdf2",
            "--seed",
            "x",
            "--output",
            str(key_path),
            "--comment",
            "line1\nEvilEntry",
            "--overwrite-files",
        ],
    )

    assert result.exit_code != 0
    assert "comment must not contain newlines" in result.output
    assert not key_path.exists()
    assert not (tmp_path / "key.pub").exists()


def test_declining_overwrite_prompt_preserves_the_existing_key(tmp_path):
    key_path = tmp_path / "key"
    pub_path = tmp_path / "key.pub"
    key_path.write_text("original private key")
    pub_path.write_text("original public key")

    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "pbkdf2", "--seed", "x", "--output", str(key_path)], input="n\n")

    assert result.exit_code != 0
    assert key_path.read_text() == "original private key"
    assert pub_path.read_text() == "original public key"


def test_accepting_overwrite_prompt_replaces_the_existing_key(tmp_path):
    key_path = tmp_path / "key"
    pub_path = tmp_path / "key.pub"
    key_path.write_text("original private key")
    pub_path.write_text("original public key")

    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "pbkdf2", "--seed", "x", "--output", str(key_path)], input="y\n")

    assert result.exit_code == 0, result.output
    assert key_path.read_text() != "original private key"
    assert pub_path.read_text() != "original public key"


def test_help_shows_salt_digest_size_range():
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "pbkdf2", "--salt-algo", "blake2s", "--help"])

    assert result.exit_code == 0, result.output
    assert "(1-32)" in result.output


def test_help_shows_soft_max_hint():
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "argon2id", "--help"])

    assert result.exit_code == 0, result.output
    assert "(soft max 100)" in result.output


def test_help_default_line_never_has_a_blank_line_before_it():
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "argon2id", "--help"], env={"COLUMNS": "80", "LINES": "24"})

    assert result.exit_code == 0, result.output
    assert "\n\n[default:" not in result.output


def test_help_default_never_splits_across_the_bracket_on_a_narrow_terminal():
    runner = CliRunner()
    result = runner.invoke(main, ["--kdf", "argon2id", "--help"], env={"COLUMNS": "80", "LINES": "24"})

    assert result.exit_code == 0, result.output
    assert "[default: argon2id]" in result.output
    assert "[default: 1024]" in result.output
    assert "[default:\n" not in result.output


def test_salt_digest_size_out_of_hard_range_rejected_immediately(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "pbkdf2",
            "--salt-algo",
            "blake2s",
            "--seed",
            "x",
            "--salt-digest-size",
            "100",
            "--output",
            str(tmp_path / "key"),
            "--overwrite-files",
        ],
    )

    assert result.exit_code != 0
    assert "must be at most 32" in result.output
    assert "Deriving key" not in result.output


def test_soft_constraint_rejected_without_override_flag(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "pbkdf2",
            "--seed",
            "x",
            "--iterations",
            "60000000",
            "--output",
            str(tmp_path / "key"),
            "--overwrite-files",
        ],
    )

    assert result.exit_code != 0
    assert "force-allow-soft-constraints" in result.output
    assert "Deriving key" not in result.output


def test_soft_constraint_accepted_with_override_flag(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--kdf",
            "pbkdf2",
            "--seed",
            "x",
            "--iterations",
            "60000000",
            "--output",
            str(tmp_path / "key"),
            "--overwrite-files",
            "--force-allow-soft-constraints",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / "key").exists()


def test_force_allow_soft_constraints_alone_forces_flag_mode_not_a_hybrid():
    runner = CliRunner()
    result = runner.invoke(main, ["--force-allow-soft-constraints"])

    assert result.exit_code != 0
    assert "--seed is required" in result.output


def test_help_shows_output_default_with_tilde_not_the_real_home_path(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])

    assert result.exit_code == 0, result.output
    assert "~/.ssh/id_ed25519" in result.output
    assert str(tmp_path) not in result.output


def test_run_dispatches_ssh_argv_to_the_ssh_group(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setattr("sys.argv", ["detssh", "ssh", "list"])

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert exc_info.value.code == 0


def test_run_dispatches_everything_else_to_the_keygen_command(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["detssh", "--kdf", "pbkdf2", "--seed", "x", "--overwrite-files"])

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert exc_info.value.code == 0
    assert (tmp_path / ".ssh" / "id_ed25519").exists()


def _register_prompt_command(label, key_path):
    @click.command()
    def cmd():
        _register_interactively(label, key_path)

    return cmd


def _fake_select(message, choices, default):
    """Answer questionary's backend pickers with pbkdf2 (cheap to derive) and otherwise
    whatever the wizard offered as its default."""
    answer = "pbkdf2" if "pbkdf2" in choices else default
    return type("Q", (), {"ask": lambda self: answer})()


def test_wizard_register_prompt_registers_the_label(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = tmp_path / "id_ed25519"

    result = CliRunner().invoke(
        _register_prompt_command("isik:personal:contaboo", key_path), input="y\nroot@contaboo.com\n\n"
    )

    assert result.exit_code == 0, result.output
    assert "Run: ssh isik:personal:contaboo" in result.output
    entry = load_registry()["isik:personal:contaboo"]
    assert (entry.user, entry.host, entry.port) == ("root", "contaboo.com", None)
    assert entry.key == key_path


def test_wizard_register_prompt_can_be_declined(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    result = CliRunner().invoke(_register_prompt_command("label", tmp_path / "id_ed25519"), input="n\n")

    assert result.exit_code == 0, result.output
    assert load_registry() == {}


def test_wizard_register_prompt_accepts_a_port(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    result = CliRunner().invoke(
        _register_prompt_command("label", tmp_path / "id_ed25519"), input="y\nroot@example.com\n2222\n"
    )

    assert result.exit_code == 0, result.output
    assert load_registry()["label"].port == 2222


def test_wizard_register_prompt_reasks_on_a_destination_without_user_at_host(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    result = CliRunner().invoke(
        _register_prompt_command("label", tmp_path / "id_ed25519"), input="y\nexample.com\nroot@example.com\n\n"
    )

    assert result.exit_code == 0, result.output
    assert "must be user@host" in result.output
    assert load_registry()["label"].host == "example.com"


def test_wizard_register_prompt_asks_for_a_name_when_there_is_no_label(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    result = CliRunner().invoke(
        _register_prompt_command("", tmp_path / "id_ed25519"), input="y\n   \nmyhost\nroot@example.com\n\n"
    )

    assert result.exit_code == 0, result.output
    assert "plain `ssh <name>`" in result.output
    assert load_registry()["myhost"].host == "example.com"


def test_register_flag_needs_a_label_to_name_the_host_block(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            *("--kdf", "pbkdf2", "--iterations", "2", "--seed", "x"),
            *("--output", str(tmp_path / "key")),
            *("--register", "root@example.com"),
        ],
    )

    assert result.exit_code != 0
    assert "--register needs --label" in result.output
    assert not (tmp_path / "key").exists()


def test_register_flag_rejects_a_destination_without_user_at_host(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            *("--kdf", "pbkdf2", "--iterations", "2", "--seed", "x", "--label", "l"),
            *("--output", str(tmp_path / "key")),
            *("--register", "example.com"),
        ],
    )

    assert result.exit_code != 0
    assert "USER@HOST" in result.output
    assert not (tmp_path / "key").exists()


def test_register_port_flag_without_register_flag_fails_before_deriving(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            *("--kdf", "pbkdf2", "--iterations", "2", "--seed", "x"),
            *("--output", str(tmp_path / "key")),
            *("--register-port", "2222"),
        ],
    )

    assert result.exit_code != 0
    assert "--register-port needs --register" in result.output
    assert not (tmp_path / "key").exists()


def test_register_flag_registers_the_generated_key(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = tmp_path / "key"

    result = CliRunner().invoke(
        main,
        [
            *("--kdf", "pbkdf2", "--iterations", "2", "--seed", "x"),
            *("--label", "isik:personal:contaboo"),
            *("--output", str(key_path)),
            *("--register", "root@contaboo.com"),
            *("--register-port", "2222"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Registered isik:personal:contaboo -> root@contaboo.com" in result.output
    entry = load_registry()["isik:personal:contaboo"]
    assert (entry.user, entry.host, entry.port, entry.key) == ("root", "contaboo.com", 2222, key_path)


def test_a_full_interactive_run_generates_and_registers_in_one_go(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setattr(questionary, "select", _fake_select)
    key_path = tmp_path / "id_ed25519"

    answers = [
        "s",  # seed passphrase
        "s",  # ... confirmed
        "isik:personal:contaboo",  # label
        "2",  # pbkdf2 iterations
        "",  # salt digest size: default
        str(key_path),  # output path
        "",  # comment
        "",  # key passphrase: none
        "",  # ... confirmed
        "y",  # register it
        "root@contaboo.com",  # destination
        "",  # default ssh port
    ]

    result = CliRunner().invoke(main, [], input="\n".join(answers) + "\n")

    assert result.exit_code == 0, result.output
    assert key_path.exists()
    assert "Run: ssh isik:personal:contaboo" in result.output
    entry = load_registry()["isik:personal:contaboo"]
    assert (entry.user, entry.host, entry.key) == ("root", "contaboo.com", key_path)
