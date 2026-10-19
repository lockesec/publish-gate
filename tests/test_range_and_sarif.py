"""`--range` judges only what one push sends (the pre-push hook), and `--format sarif|json`
carry every finding with a structured location, and a NOT EVALUABLE run as a failure, never
as an empty result. Leaks are assembled from fragments."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from publish_gate import cli

TOKEN = "".join(("ghp", "_", "Rv7" * 13))
ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "PATH": "/usr/bin:/bin"}


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          env=ENV, text=True).stdout.strip()


def commit(root, rel, text, msg):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", msg)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def two_commits(tmp_path):
    git(tmp_path, "init", "-q")
    old = commit(tmp_path, "old.yml", f"t: {TOKEN}\n", "old leak, already published")
    new = commit(tmp_path, "new.md", "fine\n", "new work")
    return tmp_path, old, new


def run(capsys, *argv):
    rc = cli.main([*argv, "--no-denylist"])
    return rc, capsys.readouterr()


def test_a_range_judges_only_its_commits_and_ignores_a_dirty_tree(two_commits, capsys):
    root, old, new = two_commits
    (root / "scratch.txt").write_text("uncommitted\n")      # not pushed, not judged
    rc, cap = run(capsys, str(root), "--history", "--range", f"{old}..{new}")
    assert rc == 0 and f"1 commit(s) in {old}..{new}" in cap.out
    rc, cap = run(capsys, str(root), "--history", "--range", new)    # both commits
    assert rc == 1 and "old.yml" in cap.out


def test_a_range_judges_what_its_commits_change(two_commits, capsys):
    root, old, new = two_commits
    edited = commit(root, "old.yml", f"t: {TOKEN}\nmore: 1\n", "touch the old file")
    rc, cap = run(capsys, str(root), "--history", "--range", f"{new}..{edited}")
    assert rc == 1 and f"old.yml @ {edited[:12]}" in cap.out      # a changed file is resent
    gone = commit(root, "new.md", "still fine\n", "edit")
    (root / "old.yml").unlink()
    git(root, "commit", "-q", "-am", "delete the leak")
    rc, cap = run(capsys, str(root), "--history", "--range", f"{gone}..HEAD")
    assert rc == 0                                                  # a deletion sends nothing


def test_a_new_branch_range_and_an_empty_range(two_commits, capsys):
    root, old, new = two_commits
    rc, cap = run(capsys, str(root), "--history", "--range", f"{new} --not --branches")
    assert rc == 0 and "0 commit(s)" in cap.out
    rc, cap = run(capsys, str(root), "--history", "--range=--output=/tmp/x")
    assert rc == 2 and "--range accepts" in cap.err


def test_range_without_history_is_a_usage_error(two_commits, capsys):
    rc, cap = run(capsys, str(two_commits[0]), "--range", "HEAD")
    assert rc == 64


def test_sarif_carries_paths_lines_commits_and_levels(two_commits, capsys):
    root, old, new = two_commits
    commit(root, "notes.md", "see [[Private Note]]\n", "".join(("mail ops", "@corp-x.io")))
    rc, cap = run(capsys, str(root), "--history", "--format", "sarif")
    assert rc == 1
    doc = json.loads(cap.out)
    run_ = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run_["invocations"][0]["executionSuccessful"] is True
    by_rule = {r["ruleId"]: r for r in run_["results"]}
    sec = by_rule["secret"]
    assert sec["level"] == "error" and TOKEN not in json.dumps(doc)
    loc = sec["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "old.yml" and loc["region"]["startLine"] == 1
    assert sec["properties"]["commit"] == old
    assert by_rule["wikilink"]["level"] == "warning"
    assert by_rule["email"]["locations"][0]["logicalLocations"][0]["kind"] == "commit"


def test_not_evaluable_is_a_failed_run_in_sarif_and_json(tmp_path, capsys):
    rc, cap = run(capsys, str(tmp_path / "missing"), "--format", "sarif")
    doc = json.loads(cap.out)
    inv = doc["runs"][0]["invocations"][0]
    assert rc == 2 and inv["executionSuccessful"] is False and doc["runs"][0]["results"] == []
    assert "NOT EVALUABLE" in inv["toolExecutionNotifications"][0]["message"]["text"]
    rc, cap = run(capsys, str(tmp_path / "missing"), "--json")
    assert rc == 2 and json.loads(cap.out)["verdict"] == "not-evaluable"


HOOK = Path(__file__).resolve().parent.parent / "examples" / "pre-push"


@pytest.mark.skipif(shutil.which("publish-gate") is None, reason="publish-gate is not installed")
def test_the_pre_push_hook_stops_a_push_that_adds_a_leak(tmp_path):
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(["git", "clone", "-q", str(remote), str(work)], check=True, capture_output=True)
    commit(work, "a.md", "fine\n", "first")
    env = {**os.environ, **{k: v for k, v in ENV.items() if k != "PATH"}}
    hook = work / ".git" / "hooks" / "pre-push"
    shutil.copy(HOOK, hook)
    hook.chmod(0o755)
    push = ["git", "-C", str(work), "-c", "core.hooksPath=.git/hooks", "push", "-q", "origin", "HEAD:main"]
    env["PUBLISH_GATE_DENYLIST"] = str(tmp_path / "deny")
    (tmp_path / "deny").write_text("Zebulon Freight\n")
    assert subprocess.run(push, env=env, capture_output=True).returncode == 0
    commit(work, "b.yml", f"t: {TOKEN}\n", "oops")
    r = subprocess.run(push, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "secret" in r.stderr


def test_the_negative_control_runs_through_the_range_path(monkeypatch, two_commits, capsys):
    """A blind range path must make a ranged run NOT EVALUABLE, even when the full-history
    path still sees everything."""
    from publish_gate import scan
    real = scan._changed
    monkeypatch.setattr(scan, "_changed", lambda root, c: [e for e in real(root, c)
                                                         if not e[0].endswith(".env")])
    root, old, new = two_commits
    rc, cap = run(capsys, str(root), "--history", "--range", f"{old}..{new}")
    assert rc == 2 and "env-file" in cap.err
    rc, cap = run(capsys, str(root), "--history")
    assert rc == 1                                   # the full path is unaffected
