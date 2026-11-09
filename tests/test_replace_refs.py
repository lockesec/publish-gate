"""`git replace` must not change what a history scan reads."""
import os
import subprocess

from publish_gate import scan
from publish_gate.classes import Terms

TOKEN = "".join(["ghp", "_", "Rv7" * 13])
ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
       "GIT_CONFIG_GLOBAL": os.devnull}


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          text=True, env=ENV).stdout.strip()


def test_a_replaced_leaking_commit_is_still_read(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.txt").write_text("hello\n")
    git(tmp_path, "add", "a.txt")
    git(tmp_path, "commit", "-q", "-m", "base")
    (tmp_path / "a.txt").write_text(f"token={TOKEN}\n")
    git(tmp_path, "commit", "-q", "-am", "leak")
    leak = git(tmp_path, "rev-parse", "HEAD")
    base = git(tmp_path, "rev-parse", "HEAD~1")
    (tmp_path / "a.txt").write_text("hello\n")
    git(tmp_path, "commit", "-q", "-am", "remove")
    clean = git(tmp_path, "commit-tree", f"{base}^{{tree}}", "-p", base, "-m", "clean")
    git(tmp_path, "replace", leak, clean)
    res = scan.scan_history(tmp_path, Terms([], []))
    assert any(f.cls == "secret" for f in res.findings)
