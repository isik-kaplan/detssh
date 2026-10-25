import hashlib

from isik.common.settings import Setting, Settings

from detssh.backends.kdf.base import NO_SALT_CONSTRAINTS, KDFBackend, KDFError


class Pbkdf2Settings(Settings):
    iterations = Setting(int, "PBKDF2 iterations", default=600_000, soft_max=50_000_000)


class Pbkdf2(KDFBackend):
    name = "pbkdf2"
    salt_constraints = NO_SALT_CONSTRAINTS
    settings = Pbkdf2Settings

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
