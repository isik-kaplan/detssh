from click.testing import CliRunner

from detssh.registry import load_registry
from detssh.ssh_cli import ssh
from detssh.ssh_config import ssh_config_path


def _key(tmp_path, name="id_ed25519"):
    key_path = tmp_path / name
    key_path.write_text("fake private key")
    return key_path


def test_register_writes_the_registry_and_wires_up_ssh_config(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)

    runner = CliRunner()
    result = runner.invoke(ssh, ["register", "isik:personal:contabo", "root@contabo.com", "--key", str(key_path)])

    assert result.exit_code == 0, result.output
    assert "Registered isik:personal:contabo -> root@contabo.com" in result.output
    entries = load_registry()
    assert entries["isik:personal:contabo"].user == "root"
    assert entries["isik:personal:contabo"].host == "contabo.com"
    assert "Include" in ssh_config_path().read_text()


def test_register_accepts_a_port(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)

    runner = CliRunner()
    result = runner.invoke(ssh, ["register", "label", "root@example.com", "--key", str(key_path), "--port", "2222"])

    assert result.exit_code == 0, result.output
    assert load_registry()["label"].port == 2222


def test_register_rejects_a_destination_without_at_sign(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)

    runner = CliRunner()
    result = runner.invoke(ssh, ["register", "label", "example.com", "--key", str(key_path)])

    assert result.exit_code != 0
    assert "user@host" in result.output


def test_register_rejects_a_destination_missing_the_user(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)

    runner = CliRunner()
    result = runner.invoke(ssh, ["register", "label", "@example.com", "--key", str(key_path)])

    assert result.exit_code != 0
    assert "user@host" in result.output


def test_register_requires_the_key_file_to_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    runner = CliRunner()
    result = runner.invoke(ssh, ["register", "label", "root@example.com", "--key", str(tmp_path / "missing")])

    assert result.exit_code != 0


def test_register_on_an_existing_label_asks_to_overwrite_and_declines(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)
    runner = CliRunner()
    runner.invoke(ssh, ["register", "label", "root@example.com", "--key", str(key_path)])

    result = runner.invoke(ssh, ["register", "label", "root@other.com", "--key", str(key_path)], input="n\n")

    assert result.exit_code != 0
    assert load_registry()["label"].host == "example.com"


def test_register_on_an_existing_label_overwrites_when_confirmed(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)
    runner = CliRunner()
    runner.invoke(ssh, ["register", "label", "root@example.com", "--key", str(key_path)])

    result = runner.invoke(ssh, ["register", "label", "root@other.com", "--key", str(key_path)], input="y\n")

    assert result.exit_code == 0, result.output
    assert load_registry()["label"].host == "other.com"


def test_list_reports_no_labels_when_the_registry_is_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    result = CliRunner().invoke(ssh, ["list"])

    assert result.exit_code == 0, result.output
    assert "No labels registered" in result.output


def test_list_shows_registered_labels(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)
    runner = CliRunner()
    runner.invoke(ssh, ["register", "label", "root@example.com", "--key", str(key_path)])

    result = runner.invoke(ssh, ["list"])

    assert result.exit_code == 0, result.output
    assert "label" in result.output
    assert "root@example.com" in result.output


def test_forget_removes_a_registered_label(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    key_path = _key(tmp_path)
    runner = CliRunner()
    runner.invoke(ssh, ["register", "label", "root@example.com", "--key", str(key_path)])

    result = runner.invoke(ssh, ["forget", "label"])

    assert result.exit_code == 0, result.output
    assert "label" not in load_registry()


def test_forget_an_unregistered_label_fails_cleanly(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    result = CliRunner().invoke(ssh, ["forget", "nope"])

    assert result.exit_code != 0
    assert "not registered" in result.output


def test_a_malformed_registry_fails_cleanly_instead_of_raising(monkeypatch, tmp_path):
    from detssh.registry import registry_path

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    registry_path().parent.mkdir(parents=True)
    registry_path().write_text("not an ini file [[[")

    result = CliRunner().invoke(ssh, ["list"])

    assert result.exit_code != 0
    assert "couldn't parse" in result.output
