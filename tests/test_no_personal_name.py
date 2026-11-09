"""The shipped files carry no real account name as sample data."""
import subprocess
from pathlib import Path

NAME = "se" + "th"          # built from parts so this file does not hold it either


def test_no_tracked_file_uses_the_maintainers_account_name_as_sample_data():
    root = Path(__file__).resolve().parents[1]
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True,
                             check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        import pytest
        pytest.skip("not a git checkout")
    hits = []
    for rel in filter(None, out.decode().split("\0")):
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if NAME in text.lower():
            hits.append(rel)
    assert not hits, hits
