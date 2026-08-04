from pathlib import Path

import click
import questionary

from detssh.keygen import keypair_from_seed, public_key_path, write_keypair


def _display_path(path):
    try:
        return f"~/{Path(path).relative_to(Path.home())}"
    except (TypeError, ValueError):
        return str(path)


DEFAULT_TEXT_MARKER = "\x00"


class Field:
    def __init__(self, message, kind="text", required=False, choices=(), min_value=None, max_value=None, soft_max=None):
        self.message = message
        self.kind = kind
        self.required = required
        self.choices = choices
        self.min_value = min_value
        self.max_value = max_value
        self.soft_max = soft_max

    def hint(self):
        parts = []
        if self.min_value is not None and self.max_value is not None:
            parts.append(f"{self.min_value}-{self.max_value}")
        elif self.min_value is not None:
            parts.append(f">= {self.min_value}")
        elif self.max_value is not None:
            parts.append(f"<= {self.max_value}")
        if self.soft_max is not None:
            parts.append(f"soft max {self.soft_max}")
        return f" ({', '.join(parts)})" if parts else ""

    def hard_error_for(self, value):
        if value is None:
            return None
        if self.min_value is not None and value < self.min_value:
            return f"must be at least {self.min_value}"
        if self.max_value is not None and value > self.max_value:
            return f"must be at most {self.max_value}"
        return None

    def soft_error_for(self, value):
        if value is None or self.soft_max is None or value <= self.soft_max:
            return None
        return f"is {value}, above the recommended safe limit of {self.soft_max} - this may take a long time"

    def ask(self, default):
        message = self.message + self.hint()
        if self.kind == "secret":
            if self.required:
                return click.prompt(message, hide_input=True, confirmation_prompt=True)
            return click.prompt(message, hide_input=True, confirmation_prompt=True, default="", show_default=False)
        if self.kind == "int":
            return click.prompt(message, default=default, type=int)
        if self.kind == "path":
            if default is not None:
                message = f"{message} [{_display_path(default)}]"
            return click.prompt(
                message, default=default, type=click.Path(dir_okay=False, path_type=Path), show_default=False
            )
        if self.kind == "select":
            answer = questionary.select(message, choices=list(self.choices), default=default).ask()
            if answer is None:
                raise click.Abort()
            return answer
        return click.prompt(message, default=default, show_default=bool(default))


def build_options(fields, defaults=None):
    defaults = defaults or {}
    options = []
    for name, field in fields.items():
        kwargs = {"default": None, "help": field.message + field.hint()}

        default_value = defaults.get(name)
        if callable(default_value):
            default_value = default_value()
        if default_value not in (None, ""):
            display_value = _display_path(default_value) if field.kind == "path" else default_value
            kwargs["help"] = f"{field.message}{field.hint()}{DEFAULT_TEXT_MARKER}[default: {display_value}]"

        if field.kind == "int":
            kwargs["type"] = int
        elif field.kind == "select":
            kwargs["type"] = click.Choice(field.choices)
        elif field.kind == "path":
            kwargs["type"] = click.Path(dir_okay=False, path_type=Path)
        options.append(click.Option([f"--{name.replace('_', '-')}"], **kwargs))
    return options


def is_interactive(values):
    return all(value is None for value in values.values())


def resolve_fields(fields, values, defaults, interactive, allow_soft_constraints=False):
    resolved = {}
    soft_violations = []
    for name, field in fields.items():
        flag = f"--{name.replace('_', '-')}"
        value = values.get(name)

        if value is None and interactive:
            default = defaults.get(name)
            if callable(default):
                default = default()
            while True:
                value = field.ask(default)
                hard_error = field.hard_error_for(value)
                if hard_error:
                    click.echo(f"Error: {flag} {hard_error}")
                    continue
                break
            soft_error = field.soft_error_for(value)
            if soft_error:
                soft_violations.append(f"{flag} {soft_error}")
        elif value is None and field.required:
            raise click.UsageError(f"{flag} is required")
        elif value is None:
            default = defaults.get(name)
            value = default() if callable(default) else default
        else:
            hard_error = field.hard_error_for(value)
            if hard_error:
                raise click.UsageError(f"{flag} {hard_error}")
            soft_error = field.soft_error_for(value)
            if soft_error and not allow_soft_constraints:
                raise click.UsageError(f"{flag} {soft_error} - pass --force-allow-soft-constraints to override")

        if field.kind == "path" and value is not None:
            value = Path(value).expanduser()
        if field.required and not value:
            raise click.UsageError(f"{flag} must not be empty")
        resolved[name] = value

    if soft_violations:
        click.echo("These may take a long time:")
        for violation in soft_violations:
            click.echo(f"  {violation}")
        if not click.confirm("Continue anyway?"):
            raise click.Abort()

    return resolved


def confirm_overwrite(output, overwrite_files):
    if overwrite_files:
        return
    output = Path(output)
    if (output.exists() or public_key_path(output).exists()) and not click.confirm(
        f"{output} already exists. Overwrite?"
    ):
        raise click.Abort()


def write_keypair_and_recap(seed_bytes, output, comment, recap, key_passphrase=""):
    private_key, public_key = keypair_from_seed(seed_bytes)
    try:
        priv_path, pub_path = write_keypair(
            private_key, public_key, output, comment=comment, key_passphrase=key_passphrase
        )
    except OSError as e:
        raise click.ClickException(f"couldn't write {output}: {e.strerror or e}") from e
    except ValueError as e:
        raise click.UsageError(str(e)) from e

    click.echo(f"Wrote private key: {priv_path}{' (encrypted)' if key_passphrase else ''}")
    click.echo(f"Wrote public key:  {pub_path}")

    click.echo()
    click.echo("To recreate this exact key, remember your passphrase (keep it secret) plus:")
    for name, value in (*recap, ("algorithm", "ed25519")):
        click.echo(f"  {name:<18} {value}")
