from argon2.low_level import Type

from detssh.backends.kdf._argon2 import Argon2Base


class Argon2I(Argon2Base):
    name = "argon2i"
    type = Type.I
