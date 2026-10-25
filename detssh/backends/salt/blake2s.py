import hashlib

from isik.common.settings import Setting, Settings

from detssh.backends.salt.base import SaltAlgo, SaltError


MIN_DIGEST_SIZE = 1
MAX_DIGEST_SIZE = 32


class Blake2sSettings(Settings):
    salt_digest_size = Setting(int, "Salt digest size, in bytes", default=16, min=MIN_DIGEST_SIZE, max=MAX_DIGEST_SIZE)


class Blake2s(SaltAlgo):
    name = "blake2s"
    min_digest_size = MIN_DIGEST_SIZE
    max_digest_size = MAX_DIGEST_SIZE
    settings = Blake2sSettings

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.blake2s(label.encode("utf-8"), digest_size=resolved["salt_digest_size"]).digest()
        except (ValueError, OverflowError) as e:
            raise SaltError(str(e)) from e
