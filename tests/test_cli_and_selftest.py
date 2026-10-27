"""The negative control has teeth (a blind class makes the run NOT EVALUABLE), and the CLI's
exit codes, denylist rules and output never show a secret."""
import json
import re

import pytest
from publish_gate import classes, cli, scan, selftest


def j(*parts):
    return "".join(parts)


def run(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


@pytest.fixture
def denylist(tmp_path_factory):
    p = tmp_path_factory.mktemp("config") / "denylist"     # outside the tree being judged
    p.write_text("# private names\nAcme Industrial\nreview: projectx\n")
    return p


def test_a_blind_class_makes_every_run_not_evaluable(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(classes, "HOME_PATH", re.compile(r"(?!x)x"))
    (tmp_path / "a.md").write_text("hello\n")
    rc, _, err = run([str(tmp_path), "--no-denylist"], capsys)
    assert rc == 2 and "home-path" in err and "NOT EVALUABLE" in err


def test_history_self_test_runs_in_history_mode(monkeypatch):
    called = {}
    real = scan.scan_history

    def spy(*a, **k):
        called["yes"] = True
        return real(*a, **k)
    monkeypatch.setattr(scan, "scan_history", spy)
    selftest.run(classes.Terms([], []), history=True)
    assert called


def test_clean_tree_exits_0_and_prints_the_denominators(tmp_path, denylist, capsys):
    (tmp_path / "README.md").write_text("hello\n")
    rc, out, _ = run([str(tmp_path), "--denylist", str(denylist)], capsys)
    assert rc == 0 and "CLEAN" in out and "1 text file(s) scanned" in out and "12 classes" in out


def test_findings_exit_1_and_name_class_and_place(tmp_path, denylist, capsys):
    (tmp_path / "a.md").write_text(j("Built for Acme Industrial.\nsee /ho", "me/mara/x\n"))
    rc, out, _ = run([str(tmp_path), "--denylist", str(denylist)], capsys)
    assert rc == 1 and "denylist" in out and "a.md:1" in out and "home-path" in out and "a.md:2" in out


def test_review_findings_pass_only_when_accepted(tmp_path, denylist, capsys):
    (tmp_path / "a.md").write_text("the projectx scheduler\n")
    assert run([str(tmp_path), "--denylist", str(denylist)], capsys)[0] == 1
    assert run([str(tmp_path), "--denylist", str(denylist), "--accept-review"], capsys)[0] == 0


def test_a_missing_or_empty_denylist_is_not_evaluable(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("PUBLISH_GATE_DENYLIST", str(tmp_path / "nope"))
    (tmp_path / "a.md").write_text("x\n")
    rc, _, err = run([str(tmp_path)], capsys)
    assert rc == 2 and "--no-denylist" in err
    empty = tmp_path / "empty"
    empty.write_text("# nothing\n")
    assert run([str(tmp_path), "--denylist", str(empty)], capsys)[0] == 2


def test_the_hostname_is_always_a_block_term(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli.socket, "gethostname", lambda: "seedbox-42")
    (tmp_path / "a.md").write_text("built on seedbox-42\n")
    rc, out, _ = run([str(tmp_path), "--no-denylist"], capsys)
    assert rc == 1 and "denylist" in out


def test_json_output_never_contains_a_secret(tmp_path, capsys):
    secret = j("ghp", "_", "Ab9" * 12)
    (tmp_path / "a.py").write_text(f"TOKEN = '{secret}'\n")
    rc, out, _ = run([str(tmp_path), "--no-denylist", "--json"], capsys)
    d = json.loads(out)
    assert rc == 1 and secret not in out and secret[:12] not in out
    assert d["findings"][0]["class"] == "secret" and d["self_test_classes"] == 12


def test_usage_errors_exit_64(capsys, tmp_path):
    assert run([], capsys)[0] == 64
    assert run([str(tmp_path), "--no-denylist", "--internal-id", "("], capsys)[0] == 64


def test_a_path_that_is_not_a_directory_is_not_evaluable(tmp_path, capsys):
    assert run([str(tmp_path / "missing"), "--no-denylist"], capsys)[0] == 2


def test_a_denylist_inside_the_tree_is_refused(tmp_path, capsys):
    (tmp_path / "a.md").write_text("x\n")
    inside = tmp_path / "denylist"
    inside.write_text("Acme Industrial\n")
    rc, _, err = run([str(tmp_path), "--denylist", str(inside)], capsys)
    assert rc == 2 and "inside the tree" in err


def test_a_repo_allow_file_excuses_review_terms_only(tmp_path, denylist, capsys):
    (tmp_path / "a.md").write_text("the projectx scheduler, built for Acme Industrial\n")
    (tmp_path / ".publish-gate-allow").write_text("projectx\nAcme Industrial\n")
    rc, out, err = run([str(tmp_path), "--denylist", str(denylist)], capsys)
    assert rc == 1 and "review-term" not in out and "denylist" in out
    assert "cannot excuse" in out + err          # it says the block term was not excused


def test_allow_term_on_the_command_line(tmp_path, denylist, capsys):
    (tmp_path / "a.md").write_text("the projectx scheduler\n")
    assert run([str(tmp_path), "--denylist", str(denylist), "--allow-term", "projectx"], capsys)[0] == 0
