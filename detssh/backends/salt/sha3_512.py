import hashlib

from detssh.backends.salt.base import SaltAlgo, SaltError


class Sha3512(SaltAlgo):
    name = "sha3_512"
    digest_size = 64

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.sha3_512(label.encode("utf-8")).digest()
        except ValueError as e:
            raise SaltError(str(e)) from e
