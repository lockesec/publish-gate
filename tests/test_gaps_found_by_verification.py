"""Behaviours no test held until seeded regressions got through the suite. Fake secrets and
addresses are assembled from parts so this file passes its own gate."""
from pathlib import PurePosixPath as P

import pytest
from publish_gate import classes as c
from publish_gate import scan as s

NONE = c.Terms([], [])
TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 4
TOKEN2 = "gh" + "p_" + "Z9y8X7w6V5" * 4
VAL = "Zq9Wx7" + "Vb5Nm3Lk1"


def F(cls):
    return s.Finding(cls, "w", "x")


def result(*classes):
    res = s.Result()
    res.findings = [F(x) for x in classes]
    return res


def test_redact_leaves_no_part_of_the_secret():
    out = c.redact(f"token {TOKEN} here")
    assert out == f"token <secret: {len(TOKEN)} chars> here"


def test_redact_handles_every_secret_of_a_kind_on_a_line():
    out = c.redact(f"{TOKEN} and {TOKEN2}")
    assert TOKEN not in out and TOKEN2 not in out


def test_a_secret_in_a_finding_path_is_redacted_too():
    f = s.Finding("env-file", f"a/{TOKEN}.env", "x", path=f"a/{TOKEN}.env")
    assert TOKEN not in f.where and TOKEN not in f.path


@pytest.mark.parametrize("n,shown", [(80, "a" * 80), (81, "a" * 77 + "..."), (82, "a" * 77 + "...")])
def test_excerpts_stop_at_80_characters(n, shown):
    assert c.mask("email", "a" * n) == shown


def test_accepting_review_never_clears_a_block():
    assert s.verdict(result("secret"), accept_review=True) == 1
    assert s.verdict(result("review-term", "secret"), accept_review=True) == 1


def test_accepting_review_clears_only_review():
    assert s.verdict(result("review-term"), accept_review=True) == 0
    assert s.verdict(result("review-term"), accept_review=False) == 1


def test_a_denylisted_name_cannot_be_excused_inline():
    t = c.Terms(["acme corp"], [])
    assert c.scan_line("at acme corp # publish-gate: allow=denylist", t, ".py")[0][0] == "denylist"


def test_an_impossible_octet_is_not_a_private_address():
    assert c._private_ips("1" + "0.0.0.256") == []


@pytest.mark.parametrize("parts,hit", [((100, 64, 0, 1), True), ((100, 127, 255, 1), True), ((100, 128, 0, 1), False),
                                       ((172, 31, 0, 1), True), ((172, 32, 0, 1), False)])
def test_private_range_edges(parts, hit):
    assert bool(c._private_ips(".".join(map(str, parts)))) is hit


def test_a_short_name_is_not_looked_for_glued():
    assert c.scan_line("acmecorp", c.Terms(["acm"], []), ".py") == []
    assert [k for k, _ in c.scan_line("acmecorp", c.Terms(["acme"], []), ".py")] == ["review-term"]


def test_agent_state_extensions_match_in_any_case():
    assert s._file_class(P("a/x.PKL"), set()) == "agent-state"


def test_a_synthetic_folder_covers_only_itself():
    assert s._file_class(P("fx/x.db"), {"fx"}) == "synthetic-data"
    assert s._file_class(P("fxtra/x.db"), {"fx"}) == "agent-state"


def test_only_the_first_line_declares_synthetic_data():
    assert s._declares_synthetic("\n  Synthetic: TRUE\nx")
    assert not s._declares_synthetic("x\nsynthetic: true")


# ---- found by the 2026-10-31 verification pass ----
from publish_gate import cli  # noqa: E402

NAME = "Zorblax" + " Holdings"


def kinds(line, terms=NONE, suffix=".txt"):
    return {k for k, _ in c.scan_line(line, terms, suffix)}


def run_cli(args, capsys):
    rc = cli.main(args)
    cap = capsys.readouterr()
    return rc, cap.out + cap.err


def test_a_byte_order_mark_does_not_disable_the_first_denylist_term(tmp_path, capsys):
    dl = tmp_path / "dl"
    dl.write_bytes(b"\xef\xbb\xbf" + NAME.encode() + b"\nsecond name\n")
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "a.txt").write_text("built for " + NAME)
    rc, out = run_cli([str(tree), "--denylist", str(dl)], capsys)
    assert rc == 1 and "denylist" in out


@pytest.mark.parametrize("line", ["x = ZorblaxHoldings(", "zorblaxholdings" + ".com", "ZorblaxHoldings"])
def test_a_many_word_name_written_glued_is_found(line):
    assert "review-term" in kinds(line, c.Terms([NAME], []))


def test_a_glued_name_is_reported_once(tmp_path):
    assert c.scan_line("Zorblax Holdings", c.Terms([NAME], []), ".txt") == [("denylist", "Zorblax Holdings")]


def test_a_pgp_private_key_block_is_a_secret():
    assert kinds("-----BEGIN PGP PRIVATE KEY" + " BLOCK-----") == {"secret"}


@pytest.mark.parametrize("word", ["testing_R3al!Pass", "nullPointerAuth9", "trueBlue_Pw_88",
                                  "Exampleton_9Xq2", "dummyRealPw_7731"])
def test_a_real_value_that_starts_like_a_placeholder_word_is_a_secret(word):
    assert kinds("password=" + word) == {"secret"}


@pytest.mark.parametrize("word", ["test", "test_pw_1", "changeme1", "example", "dummy-value", "null", "TRUE"])
def test_a_placeholder_word_is_still_a_placeholder(word):
    assert kinds("password=" + word.ljust(8, "_")) == set()


def test_an_interface_address_with_a_prefix_is_a_host_and_a_network_is_not():
    host = "192." + "168.1.50"
    assert kinds(f"addresses: [{host}/24]") == {"private-ip"}
    assert kinds("allow 192." + "168.1.0/24 and 10." + "0.0.0/8") == set()
    assert kinds("192." + "168.1.0/32") == {"private-ip"}


def test_a_utf32_file_is_read_as_text():
    body = "token: " + TOKEN + "\n"
    for bom, enc in ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be")):
        assert TOKEN in s._text(bom + body.encode(enc))


def test_an_empty_tree_is_not_evaluable_not_clean(tmp_path, capsys):
    rc, out = run_cli([str(tmp_path), "--no-denylist"], capsys)
    assert rc == 2 and "NOT EVALUABLE" in out and "no files" in out


def test_a_git_tree_where_every_file_is_ignored_is_not_evaluable(tmp_path):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("*\n")
    (tmp_path / "secret.txt").write_text(TOKEN)
    # .gitignore itself is ignored by '*', so git lists nothing
    with pytest.raises(s.NotEvaluable, match="no files"):
        s.scan_tree(tmp_path, NONE)


def test_an_assigned_secret_in_a_file_name_is_not_printed(tmp_path, capsys):
    value = "Hunter2" + "Hunter2"
    (tmp_path / f"password={value}.txt").write_text("x")
    for fmt in ("text", "json"):
        rc, out = run_cli([str(tmp_path), "--no-denylist", "--format", fmt], capsys)
        assert rc == 1 and value not in out and "secret" in out


def test_a_dot_env_file_is_an_env_file_in_any_case():
    assert s._file_class(P(".ENV"), set()) == "env-file"
    assert s._file_class(P("a/.Env.local"), set()) == "env-file"
    assert s._file_class(P(".ENV.EXAMPLE"), set()) is None


@pytest.mark.parametrize("line,suffix", [
    ("STRIPE_SEC" + "RET=" + VAL, ".env"),
    ("sec" + "ret: " + VAL, ".yaml"),
    ("aws_secret_access" + "_key = " + VAL, ".ini"),
    ("AWS_SECRET_ACCESS" + "_KEY=" + VAL, ".env"),
    ("pass" + 'word = "correct horse ' + 'battery staple"', ".py"),
    ("pass" + "word: 'it has spaces " + "inside'", ".yaml"),
])
def test_more_credential_forms_are_secrets(line, suffix):
    assert "secret" in [cls for cls, _ in c.scan_line(line, NONE, suffix)]


@pytest.mark.parametrize("line,suffix", [
    ("the secret: it is short", ".md"),
    ('secret = "$' + '{VALUE}"', ".py"),
    ("client_secret = get_secret()", ".py"),
    ("secrets: inherit", ".yaml"),
    ('password = "changeme"', ".py"),
    ('"secret": "A private key or access token"', ".py"),
    ('SECRET = "select * from integration_tokens;"', ".py"),
    ('assert kinds("pass' + 'word=" + word) == {"secret"}', ".py"),
])
def test_the_wider_forms_stay_quiet_on_what_is_not_a_literal(line, suffix):
    assert "secret" not in [cls for cls, _ in c.scan_line(line, NONE, suffix)]


def test_a_quoted_value_with_spaces_never_prints():
    shown = c.redact("pass" + 'word = "correct horse ' + 'battery staple"')
    assert "horse" not in shown and "<secret: 28 chars>" in shown


@pytest.mark.parametrize("name", [
    "fx/MEMORY.md", "fx/CLAUDE.local.md", "fx/session-state.md", "fx/settings.local.json",
    "fx/.claude.json", "fx/.claude-mem/notes.db", "fx/.claude/projects/x/t.jsonl",
])
def test_a_marker_cannot_wave_through_agent_memory_or_a_transcript(name):
    assert s._file_class(P(name), {"fx"}) == "agent-state"


@pytest.mark.parametrize("name", ["fx/x.db", "fx/x.sqlite", "fx/x.pkl", "fx/x.parquet"])
def test_a_marker_still_downgrades_a_data_fixture(name):
    assert s._file_class(P(name), {"fx"}) == "synthetic-data"
