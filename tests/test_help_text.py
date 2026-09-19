"""Exact-text snapshots of `detssh --help` for two --kdf/--salt-algo combinations.

Everything that composes --help output (option help strings, _help_note's epilog,
KDFSaltCommand.format_options' wrapping) is presentational: no other test asserts
its literal content, so a wrong-but-harmless-looking change (a re-wrapped line, a
dropped word, a flipped `is_flag`) wouldn't fail anything else. These pin the exact
rendered text so such a change is caught here instead of shipping silently.

Regenerate deliberately (never to silence a failure without reading the diff) with:
    uv run python -c "
    from click.testing import CliRunner
    from detssh.cli import main
    open('tests/golden/help_default.txt', 'w').write(CliRunner().invoke(main, ['--help']).output)
    open('tests/golden/help_pbkdf2_sha256.txt', 'w').write(
        CliRunner().invoke(main, ['--kdf', 'pbkdf2', '--salt-algo', 'sha256', '--help']).output
    )
    "
"""

from pathlib import Path

from click.testing import CliRunner

from detssh.cli import main


GOLDEN_DIR = Path(__file__).parent / "golden"


def test_help_text_for_the_default_kdf_and_salt_algo():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert result.output == (GOLDEN_DIR / "help_default.txt").read_text()


def test_help_text_for_a_non_default_kdf_and_salt_algo():
    result = CliRunner().invoke(main, ["--kdf", "pbkdf2", "--salt-algo", "sha256", "--help"])
    assert result.exit_code == 0
    assert result.output == (GOLDEN_DIR / "help_pbkdf2_sha256.txt").read_text()
