from pathlib import Path

import click
from isik.common.settings import Settings

from detssh.keygen import (
    authorize_public_key,
    keypair_from_seed,
    public_key_line,
    public_key_path,
    ssh_dir,
    write_keypair,
)


def _display_path(path):
    try:
        return f"~/{Path(path).relative_to(Path.home())}"
    except (TypeError, ValueError):
        return str(path)


class NoSettings(Settings):
    """The settings of a backend that has none to give."""


def note_if_exists(default):
    """Before asking for an output path: say so when the offered default would overwrite a key."""
    if default is not None and (Path(default).exists() or public_key_path(default).exists()):
        click.echo(f"Note: {_display_path(default)} already exists - enter a different path to avoid this.")


def confirm_overwrite(output, overwrite_files):
    if overwrite_files:
        return
    output = Path(output)
    if (output.exists() or public_key_path(output).exists()) and not click.confirm(
        f"{output} already exists. Overwrite?"
    ):
        raise click.Abort()


def confirm_create_parent_dirs(output, create_parent_dirs, interactive):
    """Decide whether to create the output path's missing parent directories.

    Returns the (possibly updated) flag for write_keypair_and_recap to act on. Flag
    mode requires --create-parent-dirs up front and fails fast otherwise, so a typo
    surfaces before key derivation rather than as a raw OSError after it. Interactive
    mode prompts for the same decision instead, defaulting to yes under ~/.ssh and to
    no (with a warning) elsewhere - matching what --create-parent-dirs would have done.
    """
    parent = Path(output).parent
    if parent.exists() or parent == ssh_dir():
        return create_parent_dirs

    outside = not parent.is_relative_to(ssh_dir())

    if not interactive:
        if not create_parent_dirs:
            raise click.UsageError(f"{_display_path(parent)} doesn't exist. Pass --create-parent-dirs to create it.")
        return True

    if not create_parent_dirs and not outside:
        question, default = f"{_display_path(parent)} doesn't exist. Create it?", True
    elif outside:
        click.echo(f"Warning: {_display_path(parent)} is outside ~/.ssh.")
        question, default = "Create it anyway?", False
    else:
        return True

    if not click.confirm(question, default=default):
        raise click.Abort()
    return True


def write_keypair_and_recap(seed_bytes, output, comment, recap, key_passphrase="", create_parent_dirs=False):
    private_key, public_key = keypair_from_seed(seed_bytes)
    try:
        priv_path, pub_path = write_keypair(
            private_key,
            public_key,
            output,
            comment=comment,
            key_passphrase=key_passphrase,
            create_parent_dirs=create_parent_dirs,
        )
    except OSError as e:
        raise click.ClickException(f"couldn't write {output}: {e.strerror or e}") from e
    except ValueError as e:
        raise click.UsageError(str(e)) from e

    click.echo(f"Wrote private key: {priv_path}{' (encrypted)' if key_passphrase else ''}")
    click.echo(f"Wrote public key:  {pub_path}")

    echo_recap(recap)

    return priv_path, pub_path


def authorize_and_recap(seed_bytes, authorized_keys, comment, recap, create_parent_dirs=False):
    _, public_key = keypair_from_seed(seed_bytes)
    try:
        added = authorize_public_key(
            public_key, authorized_keys, comment=comment, create_parent_dirs=create_parent_dirs
        )
    except OSError as e:
        raise click.ClickException(f"couldn't write {authorized_keys}: {e.strerror or e}") from e

    if added:
        click.echo(f"Added public key to {authorized_keys}:")
    else:
        click.echo(f"Public key already in {authorized_keys}, left it unchanged:")
    click.echo(f"  {public_key_line(public_key, comment).decode('utf-8').rstrip()}")

    echo_recap(recap)


def echo_recap(recap):
    click.echo()
    click.echo("To recreate this exact key, remember your passphrase (keep it secret) plus:")
    for name, value in (*recap, ("algorithm", "ed25519")):
        click.echo(f"  {name:<18} {value}")
