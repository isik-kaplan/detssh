import hashlib

from detssh.backends.base import Field
from detssh.backends.kdf.base import NO_SALT_CONSTRAINTS, KDFBackend, KDFError


class Pbkdf2(KDFBackend):
    name = "pbkdf2"
    salt_constraints = NO_SALT_CONSTRAINTS

    fields = {
        "iterations": Field("PBKDF2 iterations", kind="int", soft_max=50_000_000),
    }
    defaults = {
        "iterations": 600_000,
    }

    @classmethod
    def run(cls, resolved, salt):
        try:
            return hashlib.pbkdf2_hmac(
                "sha256",
                resolved["seed"].encode("utf-8"),
                salt,
                resolved["iterations"],
                dklen=resolved["hash_len"],
            )
        except (ValueError, OverflowError) as e:
            raise KDFError(str(e)) from e

    @classmethod
    def recap(cls, resolved):
        return (
            ("iterations", resolved["iterations"]),
            ("prf", "sha256"),
        )
