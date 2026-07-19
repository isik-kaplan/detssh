import bcrypt

from detssh.backends.base import Field
from detssh.backends.kdf.base import KDFBackend, KDFError, SaltConstraints


class BcryptPbkdf(KDFBackend):
    name = "bcrypt_pbkdf"
    salt_constraints = SaltConstraints(min_size=1)

    fields = {
        "rounds": Field("bcrypt_pbkdf rounds", kind="int", soft_max=2000),
    }
    defaults = {
        "rounds": 16,
    }

    @classmethod
    def run(cls, resolved, salt):
        try:
            return bcrypt.kdf(
                password=resolved["seed"].encode("utf-8"),
                salt=salt,
                desired_key_bytes=resolved["hash_len"],
                rounds=resolved["rounds"],
            )
        except (ValueError, OverflowError) as e:
            raise KDFError(str(e)) from e

    @classmethod
    def recap(cls, resolved):
        return (("rounds", resolved["rounds"]),)
