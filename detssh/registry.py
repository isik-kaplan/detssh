import configparser
import os
from dataclasses import dataclass
from pathlib import Path


class RegistryError(Exception):
    pass


@dataclass
class Entry:
    key: Path
    user: str
    host: str
    port: int | None = None


def registry_dir():
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "detssh"


def registry_path():
    return registry_dir() / "config"


def load_registry():
    path = registry_path()
    if not path.exists():
        return {}

    parser = configparser.ConfigParser()
    try:
        parser.read(path)
    except configparser.Error as e:
        raise RegistryError(f"couldn't parse {path}: {e}") from e

    entries = {}
    for label in parser.sections():
        section = parser[label]
        try:
            key, user, host = section["key"], section["user"], section["host"]
        except KeyError as e:
            raise RegistryError(f"{path}: [{label}] is missing {e}") from e
        port = section.get("port")
        try:
            port = int(port) if port else None
        except ValueError as e:
            raise RegistryError(f"{path}: [{label}] port must be an integer") from e
        entries[label] = Entry(key=Path(key).expanduser(), user=user, host=host, port=port)
    return entries


def save_registry(entries):
    parser = configparser.ConfigParser()
    for label, entry in entries.items():
        section = {"key": str(entry.key), "user": entry.user, "host": entry.host}
        if entry.port:
            section["port"] = str(entry.port)
        parser[label] = section

    path = registry_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("w") as f:
        parser.write(f)
