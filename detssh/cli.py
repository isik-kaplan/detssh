import sys
from pathlib import Path

import click
from isik.cli import HelpFormat, is_interactive, no_option_given, options
from isik.common.settings import (
    AskedAtUse,
    Constant,
    NoEnv,
    NoQuestion,
    OnlyWhen,
    ReplacedByFlow,
    Requires,
    Selector,
    Setting,
    Settings,
)

from detssh.backends import kdf, salt
from detssh.backends.base import (
    authorize_and_recap,
    confirm_create_parent_dirs,
    confirm_overwrite,
    note_if_exists,
    write_keypair_and_recap,
)
from detssh.backends.kdf.base import KDFError
from detssh.backends.salt.base import SaltError
from detssh.hardening import harden
from detssh.keygen import (
    COMMENT_FORBIDDEN_CHARS,
    ED25519_SEED_LENGTH,
    default_authorized_keys_path,
    default_output_path,
)
from detssh.seed_prompt import ask_seed
from detssh.ssh_cli import OptionalPort, register_entry, split_destination
from detssh.strength import confirm_seed_strength


DEFAULT_KDF = "argon2id"
DEFAULT_SALT_ALGO = "blake2b"
HASH_LEN = ED25519_SEED_LENGTH

GENERATE_MODE = "Generate a keypair (private + public key)"
AUTHORIZE_MODE = "Only add the public key to an authorized_keys file"

# A file path, never a directory: an existing directory is refused when given or answered.
FILE = click.Path(dir_okay=False, path_type=Path)
NOT_WITH_AUTHORIZE = "%(name)s can't be used with --authorize: no private key is written"


def _writes_a_keypair(values):
    return not values.authorize


def _authorizes(values):
    return values.authorize


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


class Generate(
    Settings,
    prefix="DETSSH_",
    env=NoEnv(reason="a stray environment variable would silently derive a different key"),
    ask_order=["authorize"],
    soft_override="force_allow_soft_constraints",
):
    kdf = Selector(
        "KDF backend",
        {name: backend.settings for name, backend in kdf.BACKENDS.items()},
        default=DEFAULT_KDF,
    )
    salt_algo = Selector(
        "Salt hash algorithm",
        {name: algo.settings for name, algo in salt.ALGOS.items()},
        default=DEFAULT_SALT_ALGO,
    )
    seed = Setting(str, "Seed passphrase", secret=True, confirm=True, required=True, prompt=ask_seed)
    label = Setting(str, "Label", default="")
    kdf_settings = kdf.settings
    salt_settings = salt_algo.settings
    output = Setting(
        FILE,
        "Output path for the private key (ssh-keygen style, e.g. ~/.ssh/id_ed25519)",
        default=default_output_path,
        before_ask=note_if_exists,
        only_when=OnlyWhen(_writes_a_keypair, message=NOT_WITH_AUTHORIZE),
    )
    comment = Setting(str, "Comment for the public key", default="")
    key_passphrase = Setting(
        str,
        "Passphrase to encrypt the private key file with (leave empty for none)",
        secret=True,
        confirm=True,
        default="",
        only_when=OnlyWhen(_writes_a_keypair, message=NOT_WITH_AUTHORIZE),
    )
    authorize = Setting(
        bool,
        "Only add the public key to an authorized_keys file (see --authorized-keys), so the "
        "machine accepts logins from wherever you derived the private key. Writes no private key. "
        "Doesn't switch to flag mode on its own: `detssh --authorize` still prompts for the rest.",
        default=False,
        negatable=False,
        question="What do you want to do?",
        choices={GENERATE_MODE: False, AUTHORIZE_MODE: True},
    )
    authorized_keys = Setting(
        FILE,
        "authorized_keys file for --authorize to append to. Skipped if the key is already in it.",
        default=default_authorized_keys_path,
        question="authorized_keys file to add the public key to",
        only_when=OnlyWhen(_authorizes, message="%(name)s needs --authorize"),
    )
    overwrite_files = Setting(
        bool,
        "Overwrite existing output files without asking.",
        default=False,
        negatable=False,
        question=AskedAtUse(reason="confirmed when the key is written, and only if the output file already exists"),
        only_when=OnlyWhen(_writes_a_keypair, message="%(name)s can't be used with --authorize: it only appends"),
    )
    create_parent_dirs = Setting(
        bool,
        "Create the output path's (or --authorized-keys file's) parent directories if missing, "
        "even outside ~/.ssh. Interactive mode prompts for this itself if you don't pass the flag; "
        "non-interactive mode requires it explicitly.",
        default=False,
        negatable=False,
        question=AskedAtUse(reason="confirmed when the key is written, and only if the parent directory is missing"),
    )
    register = Setting(
        str,
        "Register the generated key so plain `ssh <label>` connects to USER@HOST, as "
        "`detssh ssh register` would. Needs --label, which names the `Host` block. Interactive "
        "mode asks about this at the end instead.",
        default=None,
        metavar="USER@HOST",
        question=ReplacedByFlow(
            flow=_register_interactively, reason="asked once the key is written, with its own confirm and re-asks"
        ),
        requires=Requires(
            "label", message="%(name)s needs %(other)s: the label names the `Host` block in ~/.ssh/config"
        ),
        only_when=OnlyWhen(_writes_a_keypair, message=NOT_WITH_AUTHORIZE),
    )
    register_port = Setting(
        OptionalPort(),
        "Non-default ssh port to register with --register.",
        default=None,
        question=ReplacedByFlow(
            flow=_register_interactively, reason="asked once the key is written, as part of registering it"
        ),
        requires="register",
        only_when=OnlyWhen(_writes_a_keypair, message=NOT_WITH_AUTHORIZE),
    )
    force_allow_soft_constraints = Setting(
        bool,
        "Flag mode only: skip the 'this may take a long time' confirmation for oversized cost "
        "knobs. Interactive mode always asks.",
        default=False,
        negatable=False,
        question=NoQuestion(reason="interactive mode always confirms oversized cost knobs itself, once"),
    )
    accept_weak_seed = Setting(
        bool,
        "Flag mode only: use the seed even if it looks weak. Interactive mode warns and asks instead.",
        default=False,
        negatable=False,
        question=NoQuestion(reason="interactive mode asks itself, and only when the seed looks weak"),
    )
    hash_len = Constant(HASH_LEN, reason="an Ed25519 private key is its 32-byte seed, so the KDF always makes 32")

    def check(self):
        if any(char in self.comment for char in COMMENT_FORBIDDEN_CHARS):
            raise self.error("comment", "must not contain newlines")
        if self.register is not None and split_destination(self.register) is None:
            raise self.error("register", "must be USER@HOST")


@options(
    Generate,
    interactive=no_option_given(ignoring=["authorize", "authorized_keys", "overwrite_files", "create_parent_dirs"]),
    help=HelpFormat(default_on_own_line=True, first_column_max=30),
    epilog=lambda selection: _help_note(kdf.BACKENDS[selection["kdf"]], salt.ALGOS[selection["salt_algo"]]),
)
@click.command(context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 120})
def main(settings):
    interactive = is_interactive()
    kdf_cls = kdf.BACKENDS[settings.kdf]
    salt_cls = salt.ALGOS[settings.salt_algo]
    resolved = settings.as_dict()
    target = settings.authorized_keys if settings.authorize else settings.output

    try:
        salt_bytes = salt_cls.digest(settings.label, resolved)
    except SaltError as e:
        raise click.UsageError(f"{settings.salt_algo}: {e}") from e
    salt_error = kdf_cls.salt_constraints.error_for(len(salt_bytes))
    if salt_error:
        raise click.UsageError(f"{settings.kdf} {salt_error}")

    confirm_seed_strength(settings.seed, settings.label, settings.comment, settings.accept_weak_seed, interactive)
    if not settings.authorize:
        confirm_overwrite(target, settings.overwrite_files)
    create_parent_dirs = confirm_create_parent_dirs(target, settings.create_parent_dirs, interactive)

    click.echo("Deriving key...")
    try:
        seed_bytes = kdf_cls.run(resolved, salt_bytes)
    except KDFError as e:
        raise click.UsageError(f"{settings.kdf}: {e}") from e

    recap = (
        ("kdf", settings.kdf),
        ("salt-algo", settings.salt_algo),
        ("label", repr(settings.label)),
        ("encoding", "utf-8"),
        *salt_cls.recap(resolved),
        *kdf_cls.recap(resolved),
        ("hash-len", settings.hash_len),
    )

    if settings.authorize:
        authorize_and_recap(seed_bytes, target, settings.comment, recap, create_parent_dirs=create_parent_dirs)
        return

    priv_path, _ = write_keypair_and_recap(
        seed_bytes,
        settings.output,
        settings.comment,
        recap=recap,
        key_passphrase=settings.key_passphrase,
        create_parent_dirs=create_parent_dirs,
    )

    click.echo()
    if interactive:
        _register_interactively(settings.label, priv_path)
    elif settings.register is not None:
        user, host = split_destination(settings.register)
        register_entry(settings.label, user, host, key=priv_path, port=settings.register_port)


def run():
    """Console-script entry point: `detssh ssh ...` dispatches to the ssh_config
    registry commands, `detssh seed` generates a seed, everything else runs the keygen
    wizard as before."""
    argv = sys.argv[1:]
    if argv[:1] == ["ssh"]:
        from detssh.ssh_cli import ssh

        ssh(args=argv[1:], prog_name="detssh ssh")
    elif argv[:1] == ["seed"]:
        from detssh.diceware import seed

        harden()
        seed(args=argv[1:], prog_name="detssh seed")
    else:
        harden()
        main(args=argv, prog_name="detssh")


if __name__ == "__main__":
    run()
