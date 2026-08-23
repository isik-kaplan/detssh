import os
import stat
from pathlib import Path

from detssh.registry import registry_dir


HOSTS_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR
HOSTS_DIR_MODE = stat.S_IRWXU
SSH_CONFIG_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
HEADER = "# managed by detssh - do not edit; use `detssh ssh` to change entries\n"


def hosts_file_path():
    return registry_dir() / "ssh_hosts"


def ssh_config_path():
    return Path.home() / ".ssh" / "config"


def render_hosts_file(entries):
    lines = [HEADER]
    for label, entry in sorted(entries.items()):
        lines.append(f"\nHost {label}")
        lines.append(f"    HostName {entry.host}")
        lines.append(f"    User {entry.user}")
        if entry.port:
            lines.append(f"    Port {entry.port}")
        lines.append(f"    IdentityFile {entry.key}")
        lines.append("    IdentitiesOnly yes")
    lines.append("")
    return "\n".join(lines)


def write_hosts_file(entries):
    path = hosts_file_path()
    path.parent.mkdir(mode=HOSTS_DIR_MODE, parents=True, exist_ok=True)

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, HOSTS_FILE_MODE)
    os.fchmod(fd, HOSTS_FILE_MODE)
    with os.fdopen(fd, "w") as f:
        f.write(render_hosts_file(entries))

    return path


def include_line():
    return f"Include {hosts_file_path()}"


def ensure_include():
    """Make sure ~/.ssh/config pulls in detssh's generated hosts file, adding the
    Include line at the top (so it takes priority over any later `Host *` block) if
    it isn't already present anywhere in the file. Returns True if it added the line."""
    line = include_line()
    config_path = ssh_config_path()
    existing = config_path.read_text() if config_path.exists() else ""

    if line in existing.splitlines():
        return False

    config_path.parent.mkdir(mode=HOSTS_DIR_MODE, parents=True, exist_ok=True)
    fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SSH_CONFIG_FILE_MODE)
    with os.fdopen(fd, "w") as f:
        f.write(line + "\n" + existing)

    return True
