import sys
import textwrap
from pathlib import Path

import click
from click.formatting import measure_table

from detssh.backends import kdf, salt
from detssh.backends.base import (
    DEFAULT_TEXT_MARKER,
    Field,
    _display_path,
    authorize_and_recap,
    build_options,
    confirm_create_parent_dirs,
    confirm_overwrite,
    is_interactive,
    resolve_fields,
    write_keypair_and_recap,
)
from detssh.backends.kdf.base import KDFError
from detssh.backends.salt.base import SaltError
from detssh.keygen import (
    COMMENT_FORBIDDEN_CHARS,
    ED25519_SEED_LENGTH,
    default_authorized_keys_path,
    default_output_path,
)
from detssh.ssh_cli import OptionalPort, register_entry, split_destination


DEFAULT_KDF = "argon2id"
DEFAULT_SALT_ALGO = "blake2b"
HASH_LEN = ED25519_SEED_LENGTH

GENERATE_MODE = "Generate a keypair (private + public key)"
AUTHORIZE_MODE = "Only add the public key to an authorized_keys file"
MODE = Field("What do you want to do?", kind="select", choices=(GENERATE_MODE, AUTHORIZE_MODE))
# Flags that only make sense when a private key gets written.
KEYPAIR_ONLY_FLAGS = ("output", "key_passphrase", "register", "register_port")

SELECTORS = {
    "kdf": Field("KDF backend", kind="select", choices=tuple(kdf.BACKENDS)),
    "salt_algo": Field("Salt hash algorithm", kind="select", choices=tuple(salt.ALGOS)),
}
COMMON = {
    "seed": Field("Seed passphrase", kind="secret", required=True),
    "label": Field("Label"),
    "output": Field("Output path for the private key (ssh-keygen style, e.g. ~/.ssh/id_ed25519)", kind="path"),
    "comment": Field("Comment for the public key"),
    "key_passphrase": Field("Passphrase to encrypt the private key file with (leave empty for none)", kind="secret"),
}
DEFAULTS = {
    "kdf": DEFAULT_KDF,
    "salt_algo": DEFAULT_SALT_ALGO,
    "label": "",
    "output": default_output_path,
    "comment": "",
    "key_passphrase": "",
}


def _peek(args, flag, default):
    """Guess a flag's value before click does the real parsing, so we know which
    backend's options to register. Skips past a consumed value instead of scanning
    it as a token in its own right, so a value that happens to equal the flag itself
    (e.g. `--kdf --kdf`) isn't misread as a second occurrence of the flag."""
    value = default
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == flag and i + 1 < len(args):
            value = args[i + 1]
            i += 2
            continue
        if arg.startswith(flag + "="):
            value = arg.split("=", 1)[1]
        i += 1
    return value


def _fields_for(kdf_cls, salt_cls, authorize=False):
    fields = {
        "seed": COMMON["seed"],
        "label": COMMON["label"],
        **kdf_cls.fields,
        **salt_cls.fields,
        "output": COMMON["output"],
        "comment": COMMON["comment"],
        "key_passphrase": COMMON["key_passphrase"],
    }
    if authorize:
        del fields["output"], fields["key_passphrase"]
    return fields


def _help_note(kdf_cls, salt_cls):
    return (
        "\b\n"
        f"Options below are for --kdf={kdf_cls.name} --salt-algo={salt_cls.name} "
        "(defaults, unless you passed both already).\n"
        f"--kdf choices:       {', '.join(kdf.BACKENDS)}\n"
        f"--salt-algo choices: {', '.join(salt.ALGOS)}\n"
        "\b\n"
        "Each combination has its own options. To see another one's:\n"
        "  detssh --kdf pbkdf2 --salt-algo sha256 --help\n"
        "\b\n"
        "To use a generated key with plain `ssh <label>`, see:\n"
        "  detssh ssh --help"
    )


def _registration_from_flags(label, values):
    """Validate --register/--register-port up front, so a typo surfaces now rather than
    after a minute of key derivation. Returns None when --register wasn't passed."""
    destination, port = values.get("register"), values.get("register_port")
    if destination is None:
        if port is not None:
            raise click.UsageError("--register-port needs --register")
        return None
    if not label:
        raise click.UsageError("--register needs --label: the label names the `Host` block in ~/.ssh/config")
    parsed = split_destination(destination)
    if parsed is None:
        raise click.UsageError("--register must be USER@HOST")
    user, host = parsed
    return label, user, host, port


def _check_authorize_flags(authorize, authorized_keys, overwrite_files, values):
    """Reject flag combinations --authorize can't honor, before any key derivation."""
    if not authorize:
        if authorized_keys is not None:
            raise click.UsageError("--authorized-keys needs --authorize")
        return
    if overwrite_files:
        raise click.UsageError("--overwrite-files can't be used with --authorize: it only appends")
    for name in KEYPAIR_ONLY_FLAGS:
        if values.get(name) is not None:
            flag = f"--{name.replace('_', '-')}"
            raise click.UsageError(f"{flag} can't be used with --authorize: no private key is written")


def _ask_authorized_keys():
    default = default_authorized_keys_path()
    return click.prompt(
        f"authorized_keys file to add the public key to [{_display_path(default)}]",
        default=default,
        type=click.Path(dir_okay=False, path_type=Path),
        show_default=False,
    )


def _register_interactively(label, key_path):
    """Offer to wire the key we just wrote into ~/.ssh/config. Declining leaves the key
    exactly as written - `detssh ssh register` does the same thing later on."""
    if label:
        question = f"Register this key so `ssh {label}` connects with it?"
    else:
        question = "Register this key in ~/.ssh/config so plain `ssh <name>` connects with it?"
    if not click.confirm(question, default=bool(label)):
        return

    name = label
    while not name:
        name = click.prompt("Name to connect with, as in `ssh <name>`").strip()

    while (parsed := split_destination(click.prompt("Destination (user@host)"))) is None:
        click.echo("Error: destination must be user@host")
    user, host = parsed

    port = click.prompt("Non-default ssh port", default="", show_default=False, type=OptionalPort())
    register_entry(name, user, host, key=key_path, port=port)


class KDFSaltCommand(click.Command):
    def parse_args(self, ctx, args):
        kdf_name = _peek(args, "--kdf", DEFAULT_KDF)
        salt_name = _peek(args, "--salt-algo", DEFAULT_SALT_ALGO)

        kdf_cls = kdf.BACKENDS.get(kdf_name, kdf.BACKENDS[DEFAULT_KDF])
        salt_cls = salt.ALGOS.get(salt_name, salt.ALGOS[DEFAULT_SALT_ALGO])

        fields = {**SELECTORS, **_fields_for(kdf_cls, salt_cls)}
        defaults = {**DEFAULTS, **kdf_cls.defaults, **salt_cls.defaults}
        self.params = build_options(fields, defaults) + [
            click.Option(
                ["--authorize"],
                is_flag=True,
                help="Only add the public key to an authorized_keys file (see --authorized-keys), so the "
                "machine accepts logins from wherever you derived the private key. Writes no private key. "
                "Doesn't switch to flag mode on its own: `detssh --authorize` still prompts for the rest.",
            ),
            click.Option(
                ["--authorized-keys"],
                type=click.Path(dir_okay=False, path_type=Path),
                default=None,
                help="authorized_keys file for --authorize to append to. Skipped if the key is already "
                f"in it.{DEFAULT_TEXT_MARKER}[default: ~/.ssh/authorized_keys]",
            ),
            click.Option(["--overwrite-files"], is_flag=True, help="Overwrite existing output files without asking."),
            click.Option(
                ["--create-parent-dirs"],
                is_flag=True,
                help="Create the output path's (or --authorized-keys file's) parent directories if missing, "
                "even outside ~/.ssh. Interactive mode prompts for this itself if you don't pass the flag; "
                "non-interactive mode requires it explicitly.",
            ),
            click.Option(
                ["--register"],
                metavar="USER@HOST",
                default=None,
                help="Register the generated key so plain `ssh <label>` connects to USER@HOST, as "
                "`detssh ssh register` would. Needs --label, which names the `Host` block. Interactive "
                "mode asks about this at the end instead.",
            ),
            click.Option(
                ["--register-port"],
                type=OptionalPort(),
                default=None,
                help="Non-default ssh port to register with --register.",
            ),
            click.Option(
                ["--force-allow-soft-constraints"],
                is_flag=True,
                default=None,
                help="Flag mode only: skip the 'this may take a long time' confirmation for oversized cost "
                "knobs. Interactive mode always asks.",
            ),
        ]
        self.epilog = _help_note(kdf_cls, salt_cls)

        return super().parse_args(ctx, args)

    def format_options(self, ctx, formatter):
        opts = [record for param in self.get_params(ctx) if (record := param.get_help_record(ctx)) is not None]
        if not opts:
            return

        first_col = min(measure_table(opts)[0], 30)
        text_width = max(formatter.width - first_col - 4, 10)

        rewrapped = []
        for name, help_text in opts:
            if DEFAULT_TEXT_MARKER in help_text:
                description, default_line = help_text.split(DEFAULT_TEXT_MARKER, 1)
                lines = textwrap.wrap(description, text_width) or [""]
                lines.append(default_line)
                help_text = "\b\n" + "\n".join(lines)
            rewrapped.append((name, help_text))

        with formatter.section("Options"):
            formatter.write_dl(rewrapped)


@click.command(cls=KDFSaltCommand, context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 120})
def main(overwrite_files, create_parent_dirs, authorize, authorized_keys, **values):
    interactive = is_interactive(values)
    force_allow_soft_constraints = bool(values.get("force_allow_soft_constraints"))

    _check_authorize_flags(authorize, authorized_keys, overwrite_files, values)
    if interactive and not authorize:
        authorize = MODE.ask(GENERATE_MODE) == AUTHORIZE_MODE

    kdf_name = values["kdf"]
    if kdf_name is None:
        kdf_name = SELECTORS["kdf"].ask(DEFAULTS["kdf"]) if interactive else DEFAULTS["kdf"]
    kdf_cls = kdf.BACKENDS[kdf_name]

    salt_name = values["salt_algo"]
    if salt_name is None:
        salt_name = SELECTORS["salt_algo"].ask(DEFAULTS["salt_algo"]) if interactive else DEFAULTS["salt_algo"]
    salt_cls = salt.ALGOS[salt_name]

    fields = _fields_for(kdf_cls, salt_cls, authorize)
    defaults = {**DEFAULTS, **kdf_cls.defaults, **salt_cls.defaults}

    resolved = {
        "kdf": kdf_name,
        "salt_algo": salt_name,
        "hash_len": HASH_LEN,
        **resolve_fields(fields, values, defaults, interactive, force_allow_soft_constraints),
    }

    if any(char in resolved["comment"] for char in COMMENT_FORBIDDEN_CHARS):
        raise click.UsageError("--comment must not contain newlines")

    if authorize:
        if authorized_keys is None:
            authorized_keys = _ask_authorized_keys() if interactive else default_authorized_keys_path()
        target = authorized_keys.expanduser()
    else:
        target = resolved["output"]

    registration = None if interactive else _registration_from_flags(resolved["label"], values)

    try:
        salt_bytes = salt_cls.digest(resolved["label"], resolved)
    except SaltError as e:
        raise click.UsageError(f"{salt_name}: {e}") from e
    salt_error = kdf_cls.salt_constraints.error_for(len(salt_bytes))
    if salt_error:
        raise click.UsageError(f"{kdf_name} {salt_error}")

    if not authorize:
        confirm_overwrite(target, overwrite_files)
    create_parent_dirs = confirm_create_parent_dirs(target, create_parent_dirs, interactive)

    click.echo("Deriving key...")
    try:
        seed_bytes = kdf_cls.run(resolved, salt_bytes)
    except KDFError as e:
        raise click.UsageError(f"{kdf_name}: {e}") from e

    recap = (
        ("kdf", kdf_name),
        ("salt-algo", salt_name),
        ("label", repr(resolved["label"])),
        ("encoding", "utf-8"),
        *salt_cls.recap(resolved),
        *kdf_cls.recap(resolved),
        ("hash-len", resolved["hash_len"]),
    )

    if authorize:
        authorize_and_recap(seed_bytes, target, resolved["comment"], recap, create_parent_dirs=create_parent_dirs)
        return

    priv_path, _ = write_keypair_and_recap(
        seed_bytes,
        resolved["output"],
        resolved["comment"],
        recap=recap,
        key_passphrase=resolved["key_passphrase"],
        create_parent_dirs=create_parent_dirs,
    )

    click.echo()
    if interactive:
        _register_interactively(resolved["label"], priv_path)
    elif registration:
        label, user, host, port = registration
        register_entry(label, user, host, key=priv_path, port=port)


def run():
    """Console-script entry point: `detssh ssh ...` dispatches to the ssh_config
    registry commands, everything else runs the keygen wizard as before."""
    argv = sys.argv[1:]
    if argv[:1] == ["ssh"]:
        from detssh.ssh_cli import ssh

        ssh(args=argv[1:], prog_name="detssh ssh")
    else:
        main(args=argv, prog_name="detssh")


if __name__ == "__main__":
    run()
