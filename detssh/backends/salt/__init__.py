from detssh.backends.salt.blake2b import Blake2b
from detssh.backends.salt.blake2s import Blake2s
from detssh.backends.salt.sha3_256 import Sha3256
from detssh.backends.salt.sha3_384 import Sha3384
from detssh.backends.salt.sha3_512 import Sha3512
from detssh.backends.salt.sha256 import Sha256
from detssh.backends.salt.sha384 import Sha384
from detssh.backends.salt.sha512 import Sha512


ALGOS = {
    "blake2b": Blake2b,
    "blake2s": Blake2s,
    "sha256": Sha256,
    "sha384": Sha384,
    "sha512": Sha512,
    "sha3_256": Sha3256,
    "sha3_384": Sha3384,
    "sha3_512": Sha3512,
}


def validate_algos(algos):
    for name, algo in algos.items():
        if algo.name != name:
            raise TypeError(f"{algo.__name__}.name must equal its registry key {name!r}")
        if algo.digest_size is None and (algo.min_digest_size is None or algo.max_digest_size is None):
            raise TypeError(f"{algo.__name__} must set digest_size, or min/max_digest_size if variable")


validate_algos(ALGOS)
