import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ED25519_SEED_LENGTH = 32
COMMENT_FORBIDDEN_CHARS = ("\n", "\r")
PRIVATE_KEY_MODE = stat.S_IRUSR | stat.S_IWUSR
SSH_DIR_MODE = stat.S_IRWXU


def ssh_dir():
    return Path.home() / ".ssh"


def default_output_path():
    return ssh_dir() / "id_ed25519"


# ed25519 is the only algorithm whose private key is literally its own seed, so it's the only one usable here.
def keypair_from_seed(seed):
    if len(seed) != ED25519_SEED_LENGTH:
        raise ValueError(f"Ed25519 seed must be {ED25519_SEED_LENGTH} bytes, got {len(seed)}")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key, private_key.public_key()


def public_key_path(private_key_path):
    private_key_path = Path(private_key_path)
    return private_key_path.with_name(private_key_path.name + ".pub")


def write_keypair(private_key, public_key, output_path, comment="", key_passphrase="", create_parent_dirs=False):
    if any(char in comment for char in COMMENT_FORBIDDEN_CHARS):
        raise ValueError("comment must not contain newlines")

    output_path = Path(output_path)
    pub_path = public_key_path(output_path)

    if create_parent_dirs or output_path.parent == ssh_dir():
        output_path.parent.mkdir(mode=SSH_DIR_MODE, parents=True, exist_ok=True)

    encryption_algorithm = (
        serialization.BestAvailableEncryption(key_passphrase.encode("utf-8"))
        if key_passphrase
        else serialization.NoEncryption()
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption_algorithm,
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_KEY_MODE)
    os.fchmod(fd, PRIVATE_KEY_MODE)
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)

    comment_suffix = f" {comment}" if comment else ""
    pub_path.write_bytes(public_bytes + comment_suffix.encode("utf-8") + b"\n")

    return output_path, pub_path
