from detssh.backends.kdf.argon2d import Argon2D
from detssh.backends.kdf.argon2i import Argon2I
from detssh.backends.kdf.argon2id import Argon2Id
from detssh.backends.kdf.bcrypt_pbkdf import BcryptPbkdf
from detssh.backends.kdf.pbkdf2 import Pbkdf2
from detssh.backends.kdf.scrypt import Scrypt


BACKENDS = {
    "argon2id": Argon2Id,
    "argon2i": Argon2I,
    "argon2d": Argon2D,
    "scrypt": Scrypt,
    "pbkdf2": Pbkdf2,
    "bcrypt_pbkdf": BcryptPbkdf,
}

for _name, _backend in BACKENDS.items():
    if _backend.name != _name:
        raise TypeError(f"{_backend.__name__}.name must equal its registry key {_name!r}")
    if _backend.salt_constraints is None:
        raise TypeError(f"{_backend.__name__} must set salt_constraints (use NO_SALT_CONSTRAINTS if none apply)")
