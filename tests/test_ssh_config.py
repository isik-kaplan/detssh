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


def test_hosts_file_path_is_ssh_hosts_inside_the_registry_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert hosts_file_path() == tmp_path / "detssh" / "ssh_hosts"


def test_ssh_config_path_is_dot_ssh_config_in_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert ssh_config_path() == tmp_path / ".ssh" / "config"


def test_render_hosts_file_exact_text_for_one_entry():
    entries = {"work": Entry(key=Path("/k"), user="root", host="h.example.com", port=2222)}
    assert render_hosts_file(entries) == (
        "# managed by detssh - do not edit; use `detssh ssh` to change entries\n"
        "\n"
        "\n"
        "Host work\n"
        "    HostName h.example.com\n"
        "    User root\n"
        "    Port 2222\n"
        "    IdentityFile /k\n"
        "    IdentitiesOnly yes\n"
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


def test_write_hosts_file_creates_a_missing_registry_dir_with_private_permissions(monkeypatch, tmp_path):
    # A not-yet-existing, deeply nested XDG_CONFIG_HOME so write_hosts_file's mkdir is the
    # one that actually creates registry_dir() - checking a dir that already existed
    # wouldn't tell us anything about this call's mode= argument.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "nested" / "xdg"))
    write_hosts_file({})
    assert stat.S_IMODE(hosts_file_path().parent.stat().st_mode) == 0o700


def test_ensure_include_creates_a_missing_ssh_dir_with_correct_permissions(monkeypatch, tmp_path):
    # Same reasoning: HOME not yet containing .ssh, so ensure_include's mkdir is the one
    # that creates it, and its os.open call is the one that creates the config file -
    # unlike write_hosts_file, there's no later fchmod to paper over a wrong mode here.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    ensure_include()

    assert stat.S_IMODE(ssh_config_path().parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(ssh_config_path().stat().st_mode) == 0o644


def test_ensure_include_adds_the_line_when_config_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    added = ensure_include()

    assert added is True
    assert ssh_config_path().read_text() == include_line() + "\n"


def test_ensure_include_creates_a_deeply_missing_ssh_dir(monkeypatch, tmp_path):
    # HOME itself doesn't exist yet either, so creating ~/.ssh needs parents=True -
    # with only .ssh missing (HOME already there), parents=True and False look the same.
    monkeypatch.setenv("HOME", str(tmp_path / "nested" / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))

    added = ensure_include()

    assert added is True
    assert ssh_config_path().exists()


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
