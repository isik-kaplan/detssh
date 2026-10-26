import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "seed_strength: run with the real weak-seed check instead of skipping it")


@pytest.fixture(autouse=True)
def _skip_weak_seed_check(request, monkeypatch):
    # Most tests derive from throwaway seeds like "x", which the weak-seed check would stop. Only tests
    # marked seed_strength are about the check, so everything else runs as if every seed were strong.
    if request.node.get_closest_marker("seed_strength") is None:
        monkeypatch.setattr("detssh.strength.WEAK_SEED_BITS", 0)
