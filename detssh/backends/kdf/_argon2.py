from argon2.exceptions import Argon2Error
from argon2.low_level import hash_secret_raw

from detssh.backends.base import Field
from detssh.backends.kdf.base import KDFBackend, KDFError, SaltConstraints


class Argon2Base(KDFBackend):
    salt_constraints = SaltConstraints(min_size=8)
    type = None

    fields = {
        "iterations": Field("Argon2 iterations", kind="int", soft_max=100),
        "memory": Field("Argon2 memory, in MiB", kind="int", soft_max=2048),
        "parallelism": Field("Argon2 parallelism", kind="int", soft_max=16),
    }
    defaults = {
        "iterations": 10,
        "memory": 1024,
        "parallelism": 4,
    }

    @classmethod
    def run(cls, resolved, salt):
        try:
            return hash_secret_raw(
                secret=resolved["seed"].encode("utf-8"),
                salt=salt,
                time_cost=resolved["iterations"],
                memory_cost=resolved["memory"] * 1024,
                parallelism=resolved["parallelism"],
                hash_len=resolved["hash_len"],
                type=cls.type,
            )
        except (Argon2Error, OverflowError, ValueError) as e:
            raise KDFError(str(e)) from e

    @classmethod
    def recap(cls, resolved):
        return (
            ("iterations", resolved["iterations"]),
            ("memory", f"{resolved['memory']} MiB"),
            ("parallelism", resolved["parallelism"]),
        )
