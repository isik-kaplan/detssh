from argon2.low_level import Type

from detssh.backends.kdf._argon2 import Argon2Base


class Argon2Id(Argon2Base):
    name = "argon2id"
    type = Type.ID
