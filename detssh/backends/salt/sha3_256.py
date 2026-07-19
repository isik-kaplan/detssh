import hashlib

from detssh.backends.salt.base import SaltAlgo, SaltError


class Sha3256(SaltAlgo):
    name = "sha3_256"
    digest_size = 32

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.sha3_256(label.encode("utf-8")).digest()
        except ValueError as e:
            raise SaltError(str(e)) from e
