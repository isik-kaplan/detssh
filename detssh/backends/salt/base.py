class SaltError(Exception):
    pass


class SaltAlgo:
    name = None
    digest_size = None
    min_digest_size = None
    max_digest_size = None
    fields = {}
    defaults = {}

    @classmethod
    def is_variable(cls):
        return cls.digest_size is None

    @classmethod
    def digest(cls, label, resolved):
        raise NotImplementedError

    @classmethod
    def recap(cls, resolved):
        if cls.is_variable():
            return (("salt-digest-size", resolved["salt_digest_size"]),)
        return ()
