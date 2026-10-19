"""Trees and histories: file-level leaks, binaries counted as unscanned, history judged commit
by commit, and the cases the gate refuses to call clean."""
import subprocess

import pytest
from publish_gate import scan
from publish_gate.classes import Terms

NONE = Terms([], [])


def j(*parts):
    return "".join(parts)


def tree(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text)
    return root


def kinds(res):
    return {f.cls for f in res.findings}


def test_a_clean_tree_is_clean_and_counts_what_it_read(tmp_path):
    res = scan.scan_tree(tree(tmp_path, {"README.md": "hello\n", "src/a.py": "x = 1\n"}), NONE)
    assert res.findings == [] and res.scanned == 2 and res.unscanned == 0


def test_line_findings_carry_file_and_line(tmp_path):
    res = scan.scan_tree(tree(tmp_path, {"docs/a.md": j("ok\nsee /ho", "me/mara/x\n")}), NONE)
    f = res.findings[0]
    assert f.cls == "home-path" and f.where == "docs/a.md:2"


@pytest.mark.parametrize("rel", [".env", ".env.local", "MEMORY.md", "CLAUDE.local.md",
                                 ".claude/settings.local.json",
                                 ".claude/projects/x/abc.jsonl", "state/notes.sqlite",
                                 "cache/model.pkl"])
def test_agent_state_and_env_files_block(rel, tmp_path):
    res = scan.scan_tree(tree(tmp_path, {rel: "x\n"}), NONE)
    assert kinds(res) & {"env-file", "agent-state"}, (rel, kinds(res))


@pytest.mark.parametrize("rel", [".env.example", ".env.sample", "src/memory.py",
                                 "docs/MEMORY-design.md"])
def test_their_look_alikes_do_not(rel, tmp_path):
    res = scan.scan_tree(tree(tmp_path, {rel: "x = 1\n"}), NONE)
    assert not kinds(res) & {"env-file", "agent-state"}


def test_a_synthetic_data_folder_is_review_not_block(tmp_path):
    root = tree(tmp_path, {"examples/memory/MEMORY.md": "invented\n",
                           "examples/memory/SYNTHETIC-DATA": "synthetic: true\nwritten for the demo\n"})
    res = scan.scan_tree(root, NONE)
    assert [f.cls for f in res.findings] == ["synthetic-data"]
    assert scan.verdict(res, accept_review=False) == 1 and scan.verdict(res, accept_review=True) == 0


def test_a_marker_that_does_not_declare_is_ignored(tmp_path):
    root = tree(tmp_path, {"examples/MEMORY.md": "x\n", "examples/SYNTHETIC-DATA": "maybe\n"})
    assert "agent-state" in kinds(scan.scan_tree(root, NONE))


def test_binaries_are_counted_unscanned(tmp_path):
    res = scan.scan_tree(tree(tmp_path, {"logo.png": b"\x89PNG\x00\x01\x02", "a.md": "x\n"}), NONE)
    assert res.unscanned == 1 and res.scanned == 1


def test_a_file_name_is_judged_too(tmp_path):
    for name in ("acme-industrial-contract.md", "acme_industrial.md", "Acme Industrial.md"):
        res = scan.scan_tree(tree(tmp_path / name, {f"notes/{name}": "x\n"}),
                             Terms(["acme industrial"], []))
        assert "denylist" in kinds(res), name


def test_an_oversized_text_file_is_not_evaluable(tmp_path):
    root = tree(tmp_path, {"big.txt": "a" * 2000})
    with pytest.raises(scan.NotEvaluable):
        scan.scan_tree(root, NONE, max_bytes=1000)


def test_dot_git_is_not_scanned_as_a_tree(tmp_path):
    root = tree(tmp_path, {".git/config": j("url = /ho", "me/mara/x\n"), "a.md": "x\n"})
    assert scan.scan_tree(root, NONE).findings == []


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
                        "PATH": "/usr/bin:/bin"})


def test_history_finds_a_leak_that_was_deleted_later(tmp_path):
    root = tree(tmp_path, {"a.md": j("host 192.", "168.1.20\n")})
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "first")
    (root / "a.md").write_text("cleaned\n")
    git(root, "commit", "-q", "-am", "clean it")
    assert scan.scan_tree(root, NONE).findings == []
    res = scan.scan_history(root, NONE)
    assert "private-ip" in kinds(res) and any("a.md" in f.where for f in res.findings)


def test_history_reads_commit_messages(tmp_path):
    root = tree(tmp_path, {"a.md": "x\n"})
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", j("fix\n\nCo-Authored-By: Bot <bot", "@corp.io>"))
    res = scan.scan_history(root, NONE)
    assert any(f.cls == "email" and "commit" in f.where for f in res.findings)


def test_history_refuses_a_dirty_tree_and_no_commits(tmp_path):
    root = tree(tmp_path, {"a.md": "x\n"})
    git(root, "init", "-q")
    with pytest.raises(scan.NotEvaluable):
        scan.scan_history(root, NONE)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "first")
    (root / "a.md").write_text("changed\n")
    with pytest.raises(scan.NotEvaluable):
        scan.scan_history(root, NONE)


def test_in_a_git_repo_the_tree_is_what_git_would_publish(tmp_path):
    root = tree(tmp_path, {".gitignore": ".venv/\nbuild/\n", "a.md": "x\n",
                           ".venv/lib/x.py": j("p = '/ho", "me/mara/x'\n"),
                           "new.md": j("host 192.", "168.1.9\n")})
    git(root, "init", "-q")
    git(root, "add", ".gitignore", "a.md")
    git(root, "commit", "-q", "-m", "first")
    res = scan.scan_tree(root, NONE)
    where = {f.where.split(":")[0] for f in res.findings}
    assert "new.md" in where                      # untracked, not ignored: would be added
    assert not any(".venv" in w for w in where)   # ignored: not published
    assert res.scope == "git"


def test_outside_git_every_file_is_read(tmp_path):
    root = tree(tmp_path, {".venv/x.py": j("p = '/ho", "me/mara/x'\n")})
    res = scan.scan_tree(root, NONE)
    assert res.findings and res.scope == "walk"
