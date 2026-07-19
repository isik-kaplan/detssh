import hashlib

from detssh.backends.base import Field
from detssh.backends.kdf.base import NO_SALT_CONSTRAINTS, KDFBackend, KDFError


class Scrypt(KDFBackend):
    name = "scrypt"
    salt_constraints = NO_SALT_CONSTRAINTS

    fields = {
        "cost": Field("scrypt cost (N, power of two)", kind="int", soft_max=2**18),
        "block_size": Field("scrypt block size (r)", kind="int", soft_max=16),
        "parallelism": Field("scrypt parallelism (p)", kind="int", soft_max=8),
    }
    defaults = {
        "cost": 2**14,
        "block_size": 8,
        "parallelism": 1,
    }

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
