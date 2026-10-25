from argon2.exceptions import Argon2Error
from argon2.low_level import hash_secret_raw
from isik.common.settings import Setting, Settings

from detssh.backends.kdf.base import KDFBackend, KDFError, SaltConstraints


class Argon2Settings(Settings):
    iterations = Setting(int, "Argon2 iterations", default=10, soft_max=100)
    memory = Setting(int, "Argon2 memory, in MiB", default=1024, soft_max=2048)
    parallelism = Setting(int, "Argon2 parallelism", default=4, soft_max=16)


class Argon2Base(KDFBackend):
    salt_constraints = SaltConstraints(min_size=8)
    type = None
    settings = Argon2Settings

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
