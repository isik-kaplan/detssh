"""Best-effort process hardening, applied before the seed passphrase is read.

None of this protects against root or an already compromised machine. It only
keeps the seed and the derived key from leaking by accident: into a core dump,
to another process running as the same user, or into swap. A step the platform
doesn't support is skipped, and one that fails is ignored.
"""

import ctypes
import resource
import sys


PR_SET_DUMPABLE = 4  # linux/prctl.h
MCL_CURRENT = 1  # sys/mman.h on Linux
MCL_FUTURE = 2
PT_DENY_ATTACH = 31  # sys/ptrace.h on macOS


def harden():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None)
    if sys.platform.startswith("linux"):
        # Also stops processes running as the same user from attaching or reading /proc/<pid>/mem.
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        # With MCL_FUTURE, any allocation past RLIMIT_MEMLOCK fails outright, so a large Argon2
        # memory cost would die mid-derivation. Only lock when there's no limit to hit.
        if resource.getrlimit(resource.RLIMIT_MEMLOCK)[0] == resource.RLIM_INFINITY:
            libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    elif sys.platform == "darwin":
        libc.ptrace(PT_DENY_ATTACH, 0, None, 0)
