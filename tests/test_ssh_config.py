import stat
from pathlib import Path

from detssh.registry import Entry
from detssh.ssh_config import (
    ensure_include,
    hosts_file_path,
    include_line,
    render_hosts_file,
    ssh_config_path,
    write_hosts_file,
)


def test_render_hosts_file_includes_a_block_per_label():
    entries = {
        "work": Entry(key=Path("/home/x/.ssh/work/id_ed25519"), user="root", host="example.com", port=2222),
        "home": Entry(key=Path("/home/x/.ssh/home/id_ed25519"), user="me", host="home.lan", port=None),
    }
    rendered = render_hosts_file(entries)

    assert "Host work" in rendered
    assert "HostName example.com" in rendered
    assert "User root" in rendered
    assert "Port 2222" in rendered
    assert "IdentityFile /home/x/.ssh/work/id_ed25519" in rendered
    assert "IdentitiesOnly yes" in rendered

    assert "Host home" in rendered
    home_block = rendered.split("Host home")[1].split("Host ")[0]
    assert "Port" not in home_block


def test_render_hosts_file_with_no_entries_is_just_the_header():
    rendered = render_hosts_file({})
    assert "managed by detssh" in rendered
    assert "Host " not in rendered


def test_write_hosts_file_writes_with_private_permissions(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    entries = {"work": Entry(key=Path("/key"), user="root", host="example.com")}

    path = write_hosts_file(entries)

    assert path == hosts_file_path()
    assert path.read_text() == render_hosts_file(entries)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_ensure_include_adds_the_line_when_config_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    added = ensure_include()

    assert added is True
    assert ssh_config_path().read_text().splitlines()[0] == include_line()


def test_ensure_include_prepends_above_existing_content(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    (tmp_path / ".ssh").mkdir()
    ssh_config_path().write_text("Host *\n    ForwardAgent yes\n")

    ensure_include()

    content = ssh_config_path().read_text()
    assert content.splitlines()[0] == include_line()
    assert "ForwardAgent yes" in content


def test_ensure_include_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    assert ensure_include() is True
    before = ssh_config_path().read_text()

    assert ensure_include() is False
    assert ssh_config_path().read_text() == before
