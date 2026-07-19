import hashlib

from detssh.backends.base import Field
from detssh.backends.salt.base import SaltAlgo, SaltError


class Blake2b(SaltAlgo):
    name = "blake2b"
    min_digest_size = 1
    max_digest_size = 64

    fields = {
        "salt_digest_size": Field(
            "Salt digest size, in bytes", kind="int", min_value=min_digest_size, max_value=max_digest_size
        ),
    }
    defaults = {
        "salt_digest_size": 16,
    }

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.blake2b(label.encode("utf-8"), digest_size=resolved["salt_digest_size"]).digest()
        except (ValueError, OverflowError) as e:
            raise SaltError(str(e)) from e
