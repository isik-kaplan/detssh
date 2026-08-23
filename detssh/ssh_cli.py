from pathlib import Path

import click

from detssh.registry import Entry, RegistryError, load_registry, save_registry
from detssh.ssh_config import ensure_include, hosts_file_path, ssh_config_path, write_hosts_file


@click.group()
def ssh():
    """Register detssh-generated keys so plain `ssh <label>` connects with them."""


def _load_or_die():
    try:
        return load_registry()
    except RegistryError as e:
        raise click.ClickException(str(e)) from e


def _split_destination(destination):
    user, sep, host = destination.partition("@")
    if not sep or not user or not host:
        raise click.UsageError("DESTINATION must be user@host")
    return user, host


@ssh.command()
@click.argument("label")
@click.argument("destination")
@click.option(
    "--key",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to the private key for this label.",
)
@click.option("--port", type=int, default=None, help="Non-default ssh port.")
def register(label, destination, key, port):
    """Register LABEL to connect to DESTINATION (user@host) with --key.

    After this, `ssh LABEL` connects as-is - no -i, no hand-written config.
    """
    user, host = _split_destination(destination)

    entries = _load_or_die()
    existing = entries.get(label)
    if existing and not click.confirm(f"{label} is already registered ({existing.user}@{existing.host}). Overwrite?"):
        raise click.Abort()

    entries[label] = Entry(key=key, user=user, host=host, port=port)
    save_registry(entries)
    write_hosts_file(entries)
    added_include = ensure_include()

    click.echo(f"Registered {label} -> {user}@{host}")
    if added_include:
        click.echo(f"Added 'Include {hosts_file_path()}' to {ssh_config_path()}")
    click.echo(f"Run: ssh {label}")


@ssh.command(name="list")
def list_labels():
    """List registered labels."""
    entries = _load_or_die()
    if not entries:
        click.echo("No labels registered. See `detssh ssh register --help`.")
        return
    for label, entry in sorted(entries.items()):
        destination = f"{entry.user}@{entry.host}" + (f":{entry.port}" if entry.port else "")
        click.echo(f"{label:<24} {destination:<32} {entry.key}")


@ssh.command()
@click.argument("label")
def forget(label):
    """Remove LABEL from the registry. Does not delete the key file itself."""
    entries = _load_or_die()
    if label not in entries:
        raise click.ClickException(f"{label} is not registered")
    del entries[label]
    save_registry(entries)
    write_hosts_file(entries)
    click.echo(f"Forgot {label}")
