"""Reading a tree and a history: files git cannot or should not skip, symlink targets, commit
authors, UTF-16 text, and the summary counts. Every literal leak is built from fragments."""
import os
import subprocess

import pytest
from publish_gate import cli, scan
from publish_gate.classes import Terms, scan_line

NONE = Terms([], [])


def j(*parts):
    return "".join(parts)


TOKEN = j("ghp", "_", "Rv7" * 13)


def classes(line, terms=NONE, suffix=""):
    return {c for c, _ in scan_line(line, terms, suffix)}


def git(root, *args, author=("t", "t@example.com")):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1],
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
                        "PATH": "/usr/bin:/bin"})


def repo(root, files, author=("t", "t@example.com")):
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "first", author=author)
    return root


def test_what_an_inline_marker_does_excuse_is_counted_in_the_summary(tmp_path, capsys):
    (tmp_path / "a.md").write_text(j("ops alice", "@corp.io  # publish-gate: allow=email\n"))
    rc = cli.main([str(tmp_path), "--no-denylist"])
    out = capsys.readouterr().out
    assert rc == 0 and "1 excused by an inline allow marker" in out


# a tracked file the user cannot read is NOT EVALUABLE, not a crash
@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_an_unreadable_tracked_file_is_not_evaluable(tmp_path, capsys):
    root = repo(tmp_path, {"sub/leak.yaml": f"t: {TOKEN}\n", "a.md": "x\n"})
    (root / "sub").chmod(0)
    try:
        rc = cli.main([str(root), "--no-denylist"])
    finally:
        (root / "sub").chmod(0o755)
    assert rc == 2 and "NOT EVALUABLE" in capsys.readouterr().err


# a file name that is not UTF-8 is still read
def test_a_tracked_file_with_a_non_utf8_name_is_read(tmp_path):
    root = repo(tmp_path, {"a.md": "x\n"})
    (root / os.fsdecode(b"caf\xe9.yaml")).write_text(f"t: {TOKEN}\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "second")
    res = scan.scan_tree(root, NONE)
    assert res.scanned == 2 and any(f.cls == "secret" and "caf" in f.where for f in res.findings)


# outside git, an unreadable directory is NOT EVALUABLE, never skipped
@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_an_unreadable_directory_outside_git_is_not_evaluable(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub/leak.yaml").write_text(f"t: {TOKEN}\n")
    (tmp_path / "sub").chmod(0)
    try:
        with pytest.raises(scan.NotEvaluable):
            scan.scan_tree(tmp_path, NONE)
    finally:
        (tmp_path / "sub").chmod(0o755)


# git publishes a symlink as its target: judged in the tree and in the history
def test_a_symlink_target_is_judged_in_tree_and_history(tmp_path):
    root = tmp_path
    (root / "a.md").write_text("x\n")
    os.symlink(j("/ho", "me/mara/data"), root / "data")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "first")
    for res in (scan.scan_tree(root, NONE), scan.scan_history(root, NONE)):
        assert any(f.cls == "home-path" and "symlink target" in f.where for f in res.findings)


# the author and committer of every commit are published with the history
def test_history_reads_the_author_address(tmp_path):
    root = repo(tmp_path, {"a.md": "x\n"}, author=("Dev", j("dev", "@corp-internal.io")))
    res = scan.scan_history(root, NONE)
    assert any(f.cls == "email" and "author" in f.where for f in res.findings)


# UTF-16 text (Windows PowerShell, .reg) is text, with or without a byte-order mark
@pytest.mark.parametrize("enc", ["utf-16", "utf-16-le"])
def test_utf16_text_is_read(enc, tmp_path):
    (tmp_path / "deploy.ps1").write_bytes(f"Set-Token {TOKEN}\r\n".encode(enc))
    res = scan.scan_tree(tmp_path, NONE)
    assert res.scanned == 1 and res.unscanned == 0 and "secret" in {f.cls for f in res.findings}


def test_one_value_matched_twice_is_one_finding(tmp_path):
    (tmp_path / "a.yml").write_text(f"token: {TOKEN}\n")
    assert len(scan.scan_tree(tmp_path, NONE).findings) == 1
