# Contributing

- A new leak class or pattern needs three things: a seed in `selftest.py`, a test that the
  pattern fires, and a test of the realistic look-alike it must not fire on. Build the seed from
  fragments, so the repository holds no literal leak.
- Test fixtures never hold a literal secret, private address, home path or real email. Build
  them from fragments at run time, as the existing tests do. CI runs the gate on this repository.
- Install `pytest hypothesis`. Run `python -m pytest -q`, then `sh examples/demo.sh` with the tool on your PATH. The
  `examples/check_readme.py` script checks the README quick start against the demo output, so
  change the two together.
