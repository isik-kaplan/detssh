import hashlib

from isik.common.settings import Setting, Settings

from detssh.backends.kdf.base import NO_SALT_CONSTRAINTS, KDFBackend, KDFError


class ScryptSettings(Settings):
    cost = Setting(int, "scrypt cost (N, power of two)", default=2**14, soft_max=2**18)
    block_size = Setting(int, "scrypt block size (r)", default=8, soft_max=16)
    parallelism = Setting(int, "scrypt parallelism (p)", default=1, soft_max=8)


class Scrypt(KDFBackend):
    name = "scrypt"
    salt_constraints = NO_SALT_CONSTRAINTS
    settings = ScryptSettings

    @classmethod
    def run(cls, resolved, salt):
        cost, block_size, parallelism = resolved["cost"], resolved["block_size"], resolved["parallelism"]
        maxmem = 128 * block_size * (cost + parallelism + 2) * 2
        try:
            return hashlib.scrypt(
                resolved["seed"].encode("utf-8"),
                salt=salt,
                n=cost,
                r=block_size,
                p=parallelism,
                maxmem=maxmem,
                dklen=resolved["hash_len"],
            )
        except (ValueError, TypeError, OverflowError) as e:
            raise KDFError(str(e)) from e

    @classmethod
    def recap(cls, resolved):
        return (
            ("cost (N)", resolved["cost"]),
            ("block-size (r)", resolved["block_size"]),
            ("parallelism (p)", resolved["parallelism"]),
        )
