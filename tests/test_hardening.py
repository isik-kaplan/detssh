import os
import resource
import subprocess
import sys

import pytest

from detssh import hardening


class FakeLibc:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        return lambda *args: self.calls.append((name, *args))


@pytest.fixture
def libc(monkeypatch):
    # Never touch the real process here: a denied attach or a locked heap would outlive the test.
    fake = FakeLibc()
    fake.opened = []
    monkeypatch.setattr(hardening.ctypes, "CDLL", lambda *args: fake.opened.append(args) or fake)
    monkeypatch.setattr(hardening.resource, "setrlimit", lambda *args: fake.calls.append(("setrlimit", *args)))
    monkeypatch.setattr(hardening.resource, "getrlimit", lambda which: (8 << 20, resource.RLIM_INFINITY))
    return fake


def test_harden_only_disables_core_dumps_on_other_platforms(monkeypatch, libc):
    monkeypatch.setattr(hardening.sys, "platform", "plan9")

    hardening.harden()

    assert libc.opened == [(None,)]
    assert libc.calls == [("setrlimit", resource.RLIMIT_CORE, (0, 0))]


def test_harden_on_linux_blocks_attaching_but_skips_locking_under_a_memlock_limit(monkeypatch, libc):
    monkeypatch.setattr(hardening.sys, "platform", "linux")

    hardening.harden()

    assert libc.calls == [
        ("setrlimit", resource.RLIMIT_CORE, (0, 0)),
        ("prctl", 4, 0, 0, 0, 0),
    ]


def test_harden_on_linux_locks_memory_when_memlock_is_unlimited(monkeypatch, libc):
    monkeypatch.setattr(hardening.sys, "platform", "linux")
    asked = []
    monkeypatch.setattr(
        hardening.resource,
        "getrlimit",
        lambda which: asked.append(which) or (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
    )

    hardening.harden()

    assert asked == [resource.RLIMIT_MEMLOCK]
    assert libc.calls == [
        ("setrlimit", resource.RLIMIT_CORE, (0, 0)),
        ("prctl", 4, 0, 0, 0, 0),
        ("mlockall", 3),
    ]


def test_harden_on_macos_denies_debuggers(monkeypatch, libc):
    monkeypatch.setattr(hardening.sys, "platform", "darwin")

    hardening.harden()

    assert libc.calls == [
        ("setrlimit", resource.RLIMIT_CORE, (0, 0)),
        ("ptrace", 31, 0, None, 0),
    ]


def _in_subprocess(code, **kwargs):
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, **kwargs)


def test_harden_really_disables_core_dumps():
    out = _in_subprocess(
        "import resource; from detssh.hardening import harden; harden(); "
        "print(resource.getrlimit(resource.RLIMIT_CORE))"
    )

    assert out.stdout.strip() == "(0, 0)"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_GET_DUMPABLE is Linux-only")
def test_harden_really_makes_the_process_undumpable_on_linux():
    out = _in_subprocess(
        "import ctypes; from detssh.hardening import harden; harden(); print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))"
    )

    assert out.stdout.strip() == "0"


def test_a_hardened_run_still_derives_and_writes_the_key(tmp_path):
    # The real entry point, real hardening: a locked or undumpable process must still rate the seed and
    # derive the key. A subprocess skips conftest, so the seed has to pass the real weak-seed check.
    seed = "letter begin beyond watch grief tumble"
    code = f"import sys; from detssh.cli import run; sys.argv = ['detssh', '--seed', {seed!r}]; run()"
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env={**os.environ, "HOME": str(tmp_path)}
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / ".ssh" / "id_ed25519").exists()
