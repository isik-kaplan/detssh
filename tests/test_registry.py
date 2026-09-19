import stat
from pathlib import Path

import pytest

from detssh.registry import Entry, RegistryError, load_registry, registry_dir, registry_path, save_registry


def test_registry_dir_defaults_to_dot_config(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert registry_dir() == tmp_path / ".config" / "detssh"


def test_registry_dir_honors_xdg_config_home(monkeypatch, tmp_path):
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    assert registry_dir() == xdg / "detssh"


def test_registry_path_is_config_inside_the_registry_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert registry_path() == tmp_path / "detssh" / "config"


def test_load_registry_returns_empty_when_the_file_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert load_registry() == {}


def test_save_and_load_round_trip(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    entries = {
        "work": Entry(key=Path("/home/x/.ssh/work/id_ed25519"), user="root", host="example.com", port=2222),
        "home": Entry(key=Path("/home/x/.ssh/home/id_ed25519"), user="me", host="home.lan", port=None),
    }
    save_registry(entries)
    assert load_registry() == entries


def test_save_registry_creates_the_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    save_registry({"work": Entry(key=Path("/key"), user="root", host="example.com")})
    assert registry_path().exists()


def test_save_registry_creates_the_directory_with_private_permissions(monkeypatch, tmp_path):
    # A deeply nested, not-yet-existing XDG_CONFIG_HOME, so save_registry's mkdir is the one
    # that actually creates registry_dir() - if it already existed, the mode we're checking
    # wouldn't have come from this call.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "nested" / "xdg"))
    save_registry({"work": Entry(key=Path("/key"), user="root", host="example.com")})
    assert stat.S_IMODE(registry_dir().stat().st_mode) == 0o700


def test_load_registry_rejects_malformed_ini(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    registry_path().parent.mkdir(parents=True)
    registry_path().write_text("not an ini file [[[")

    with pytest.raises(RegistryError, match="couldn't parse"):
        load_registry()


def test_load_registry_rejects_a_section_missing_a_required_key(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    registry_path().parent.mkdir(parents=True)
    registry_path().write_text("[work]\nuser = root\nhost = example.com\n")

    with pytest.raises(RegistryError, match="key"):
        load_registry()


def test_load_registry_rejects_a_non_integer_port(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    registry_path().parent.mkdir(parents=True)
    registry_path().write_text("[work]\nkey = /key\nuser = root\nhost = example.com\nport = notanumber\n")

    with pytest.raises(RegistryError, match="port"):
        load_registry()
