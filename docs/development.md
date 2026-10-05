# Development

```
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

`pytest` runs with coverage on by default (`[tool.pytest.ini_options]` in
`pyproject.toml`) and fails under 100% line+branch coverage - same gate
locally and in CI, nothing extra to remember to pass.

100% coverage means every line runs under test, not that every behavior
change gets caught - a test can execute a line without asserting anything
meaningful about it. [`mutmut`](https://mutmut.readthedocs.io/) checks the
second thing: it rewrites the source one small change at a time (flips a
comparison, drops an argument, tweaks a string) and reruns the tests against
each mutant, one at a time. A mutant that still passes ("survived") is a
change the suite wouldn't notice.

```
uv run mutmut run       # takes a few minutes; ctrl-c-safe, resumes where it left off
uv run mutmut results   # list survivors by name
uv run mutmut show <name>   # see what a specific mutant changed
```

A survivor is either a real test gap (add an assertion that would fail
against the mutant) or a genuinely equivalent mutant - the mutated code is
provably indistinguishable from the original for every input (e.g.
`"utf-8"` vs `"UTF-8"` as a codec name: Python's codec lookup is
case-insensitive, so no test could tell them apart). CI
(`.github/workflows/tests.yml`, job `mutation`) fails on any survivor not
listed in `tests/mutmut_known_equivalents.txt`, which names each one and
says why - add a confirmed-equivalent mutant there (never to silence a
failure without doing that check) rather than chasing an unwinnable test.
