import hashlib

from detssh.backends.salt.base import SaltAlgo, SaltError


class Sha256(SaltAlgo):
    name = "sha256"
    digest_size = 32

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.sha256(label.encode("utf-8")).digest()
        except ValueError as e:
            raise SaltError(str(e)) from e
