import hashlib

from isik.common.settings import Setting, Settings

from detssh.backends.salt.base import SaltAlgo, SaltError


MIN_DIGEST_SIZE = 1
MAX_DIGEST_SIZE = 64


class Blake2bSettings(Settings):
    salt_digest_size = Setting(int, "Salt digest size, in bytes", default=16, min=MIN_DIGEST_SIZE, max=MAX_DIGEST_SIZE)


class Blake2b(SaltAlgo):
    name = "blake2b"
    min_digest_size = MIN_DIGEST_SIZE
    max_digest_size = MAX_DIGEST_SIZE
    settings = Blake2bSettings

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.blake2b(label.encode("utf-8"), digest_size=resolved["salt_digest_size"]).digest()
        except (ValueError, OverflowError) as e:
            raise SaltError(str(e)) from e
