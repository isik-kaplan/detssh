import hashlib

from detssh.backends.salt.base import SaltAlgo, SaltError


class Sha512(SaltAlgo):
    name = "sha512"
    digest_size = 64

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.sha512(label.encode("utf-8")).digest()
        except ValueError as e:
            raise SaltError(str(e)) from e
