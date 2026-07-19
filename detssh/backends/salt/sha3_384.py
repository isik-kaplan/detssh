import hashlib

from detssh.backends.salt.base import SaltAlgo, SaltError


class Sha3384(SaltAlgo):
    name = "sha3_384"
    digest_size = 48

    @classmethod
    def digest(cls, label, resolved):
        try:
            return hashlib.sha3_384(label.encode("utf-8")).digest()
        except ValueError as e:
            raise SaltError(str(e)) from e
