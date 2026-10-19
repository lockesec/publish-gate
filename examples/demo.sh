#!/bin/sh
# Plays the README quick start in a throwaway directory. CI runs it, and
# examples/check_readme.py compares its output with the README transcript.
set -eu
command -v publish-gate >/dev/null || { echo "demo: publish-gate is not on PATH (pip install .)" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -r "$work"' EXIT
cd "$work"
mkdir repo
printf '# App\n\nBuilt for Example Industries.\n' > repo/README.md
printf 'DB_PASSWORD=dev\n' > repo/.env
printf 'Example Industries\n' > denylist
echo '$ publish-gate repo --denylist denylist'
publish-gate repo --denylist denylist || echo "(exit $?)"
printf '# App\n\nBuilt for a client.\n' > repo/README.md
rm repo/.env
echo '$ publish-gate repo --denylist denylist'
publish-gate repo --denylist denylist || echo "(exit $?)"
