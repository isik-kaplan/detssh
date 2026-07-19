class SaltConstraints:
    def __init__(self, min_size=None, max_size=None, exact_size=None):
        self.min_size = min_size
        self.max_size = max_size
        self.exact_size = exact_size

    def error_for(self, size):
        if self.exact_size is not None and size != self.exact_size:
            return f"needs a salt of exactly {self.exact_size} bytes, got {size}"
        if self.min_size is not None and size < self.min_size:
            return f"needs a salt of at least {self.min_size} bytes, got {size}"
        if self.max_size is not None and size > self.max_size:
            return f"needs a salt of at most {self.max_size} bytes, got {size}"
        return None


NO_SALT_CONSTRAINTS = SaltConstraints()


class KDFError(Exception):
    pass


class KDFBackend:
    name = None
    salt_constraints = None
    fields = {}
    defaults = {}

    @classmethod
    def run(cls, resolved, salt):
        raise NotImplementedError

    @classmethod
    def recap(cls, resolved):
        return ()
