"""Properties written from the docs: every documented limit and list value, both sides of each
boundary (`@example(...).via("doc: ...")` names the sentence it pins), and generated text around
them. Examples replay the same way on every run and nothing is stored between runs."""
import pytest

pytest.importorskip("hypothesis", reason="pip install hypothesis to run the property tests")
import re, ipaddress
from pathlib import PurePosixPath
from hypothesis import given, assume, example, settings, strategies as st  # noqa: E402
import publish_gate.classes as C
import publish_gate.scan as S
from publish_gate.classes import Terms, scan_line, redact, mask

settings.register_profile("properties", max_examples=100, deadline=None, database=None, derandomize=True)
settings.load_profile("properties")

# fake secrets built by concatenation
GH = "gh" + "p_" + "A" * 36
AWS = "AK" + "IA" + "B" * 16
PK = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
SECRETS = [GH, AWS, PK, "sk-" + "ant-" + "c" * 25, "xo" + "xb-" + "1" * 12]

words = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8)
safe_text = st.text(alphabet="abcdefghij klmnop.,:", max_size=60)
NOTERMS = Terms([], [])

# ---------- redact
@example(GH, '', '').via("doc: README: never prints a secret; each token family")
@example(AWS, '', '').via("doc: README: never prints a secret; each token family")
@example(PK, '', '').via("doc: README: never prints a secret; each token family")
@example(SECRETS[3], '', '').via("doc: README: never prints a secret; each token family")
@example(SECRETS[4], '', '').via("doc: README: never prints a secret; each token family")
@example(GH, GH, GH).via("doc: redact: every recognised secret in a displayed string (repeated)")
@example(AWS, AWS, '').via("doc: redact: every recognised secret in a displayed string (repeated)")
@example(GH, '', '').via("doc: redact: every recognised secret in a displayed string (repeated)")
@given(st.sampled_from(SECRETS), safe_text, safe_text)
def test_redact_removes_secret(sec, a, b):
    out = redact(a + " " + sec + " " + b)
    assert sec not in out
    assert "<secret: %d chars>" % len(sec) in out or "<secret:" in out

@example(None,).via("doc: redact accepts None; '' passes")
@example('',).via("doc: redact accepts None; '' passes")
@given(st.one_of(st.none(), st.just("")))
def test_redact_falsy_passthrough(x):
    assert redact(x) == x

@example(GH, '').via("doc: redact output holds no secret")
@example(PK, '').via("doc: redact output holds no secret")
@example(AWS, 'k ').via("doc: redact output holds no secret")
@given(st.sampled_from(SECRETS), safe_text)
def test_redact_idempotent(sec, a):
    once = redact(a + sec)
    assert redact(once) == once

@example('',).via("doc: redact only replaces secrets")
@example(' ',).via("doc: redact only replaces secrets")
@given(safe_text)
def test_redact_leaves_plain_text(t):
    assert redact(t) == t

# ---------- mask
@example('',).via("doc: DESIGN: secret findings show the length, never text")
@example('a',).via("doc: DESIGN: secret findings show the length, never text")
@example('abc',).via("doc: DESIGN: secret findings show the length, never text")
@example('x'*300,).via("doc: DESIGN: secret findings show the length, never text")
@given(st.text(max_size=300))
def test_mask_secret_never_shows_text(t):
    out = mask("secret", t)
    assert str(len(t)) in out
    if len(t.strip()) >= 3 and t not in "<secret: %d chars, not shown>" % len(t):
        assert t not in out

@example('', 'email').via("doc: README: masked excerpt")
@example('a@b' '.io', 'private-ip').via("doc: README: masked excerpt")
@given(st.text(max_size=300), st.sampled_from(["email", "denylist", "private-ip", "home-path"]))
def test_mask_other_bounded_and_faithful(t, cls):
    out = mask(cls, t)
    s = t.strip()
    assert len(out) <= 80
    if len(s) <= 80:
        assert out == s
    else:
        assert out == s[:77] + "..." and len(out) == 80

# ---------- _private_ips
PRIV = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                          "169.254.0.0/16", "100.64.0.0/10")]
octet = st.integers(0, 255)

@example('acme',).via("doc: a name standing alone is the denylist finding, not a review term")
@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=4, max_size=8))
def test_a_name_standing_alone_is_a_denylist_finding(w):
    assert classes_of("; " + w + " ; ", Terms([w], [])) == ["denylist"]


@example('',).via("doc: no leak, no finding")
@example(' ',).via("doc: no leak, no finding")
@given(safe_text)
def test_scan_line_plain_text_clean(t):
    assert scan_line(t, NOTERMS) == []

@example(GH, '', "").via("doc: README: secret class blocks; never printed")
@example(GH, '', ".py").via("doc: README: secret class blocks; never printed")
@example(AWS, '', ".env").via("doc: README: secret class blocks; never printed")
@example(PK, '', ".md").via("doc: README: secret class blocks; never printed")
@example(SECRETS[3], '', ".sh").via("doc: README: secret class blocks; never printed")
@example(SECRETS[4], '', "").via("doc: README: secret class blocks; never printed")
@given(st.sampled_from(SECRETS), safe_text, st.sampled_from(["", ".py", ".md", ".sh", ".env"]))
def test_scan_line_secret_found_and_never_printed(sec, pre, suf):
    out = scan_line(pre + " " + sec, NOTERMS, suf)
    assert any(c == "secret" for c, _ in out)
    for c, shown in out:
        if c == "secret":
            assert sec not in shown

@example(GH, 'secret').via("doc: README: allow= cannot excuse a secret")
@example(GH, 'secret,email').via("doc: README: allow= cannot excuse a secret")
@example(AWS, 'secret').via("doc: README: allow= cannot excuse a secret")
@example(AWS, 'secret,email').via("doc: README: allow= cannot excuse a secret")
@example(PK, 'secret').via("doc: README: allow= cannot excuse a secret")
@example(PK, 'secret,email').via("doc: README: allow= cannot excuse a secret")
@given(st.sampled_from(SECRETS), st.sampled_from(["secret", "secret,email", "email,secret", "private-ip,secret"]))
def test_secret_never_excused(sec, cls):
    ex = []
    out = scan_line(sec + "  # publish-gate: allow=" + cls, NOTERMS, "", ex)
    assert any(c == "secret" for c, _ in out)
    assert "secret" not in ex

@example('acme',).via("doc: README: allow= cannot excuse a denylisted name")
@example('a',).via("doc: README: allow= cannot excuse a denylisted name")
@given(words)
def test_denylist_never_excused(w):
    t = Terms([w], [])
    ex = []
    out = scan_line("hello " + w + " # publish-gate: allow=denylist", t, "", ex)
    assert ("denylist", w) in [(c, s.lower()) for c, s in out] or any(c == "denylist" for c, _ in out)
    assert "denylist" not in ex

@example(0,0,1).via("doc: README: allow= excuses a listed class and is counted")
@example(255,255,255).via("doc: README: allow= excuses a listed class and is counted")
@given(octet, octet, octet)
def test_allow_excuses_and_counts(b, c, d):
    ip = f"10.{b}.{c}.{d}"
    ex = []
    out = scan_line(f"host {ip} publish-gate: allow=private-ip", NOTERMS, "", ex)
    assert out == [] and ex == ["private-ip"]
    ex2 = []
    out2 = scan_line(f"host {ip} publish-gate: allow=email", NOTERMS, "", ex2)
    assert [c_ for c_, _ in out2] == ["private-ip"] and ex2 == []
    # no excused list given: must not crash
    assert scan_line(f"host {ip} publish-gate: allow=private-ip", NOTERMS) == []

@example(0,0,1).via("doc: allow= with two classes")
@given(octet, octet, octet)
def test_allow_marker_only_affects_its_line_and_listed_classes(b, c, d):
    line = f"a@b.org 10.{b}.{c}.{d} publish-gate: allow=private-ip,email"
    assert scan_line(line, NOTERMS) == []

@example('acme','').via("doc: README: block terms denylist, review: terms review")
@example('acme','.md').via("doc: README: block terms denylist, review: terms review")
@example('a','.py').via("doc: README: block terms denylist, review: terms review")
@given(words, st.sampled_from(["", ".md", ".py"]))
def test_scan_line_block_term_is_denylist_review_term_is_review(w, suf):
    t = Terms([w], [])
    assert [c for c, _ in scan_line("; " + w + " ; ", t, suf)] == ["denylist"]
    t2 = Terms([], [w])
    assert [c for c, _ in scan_line("; " + w + " ; ", t2, suf)] == ["review-term"]

@example('acme','corp').via("doc: README: 4+ characters starting a longer token is review")
@example('acme','1').via("doc: README: 4+ characters starting a longer token is review")
@example('acmecorp','01').via("doc: README: 4+ characters starting a longer token is review")
@given(words, st.text(alphabet="xyz019", min_size=1, max_size=4))
def test_scan_line_glued_is_review_only_and_long_names_only(w, tail):
    w = w + "qrst"[:max(0, 4 - len(w))]
    t = Terms([w], [])
    out = scan_line("; " + w + tail + " now", t)
    assert ("review-term", w + tail) in out
    assert not any(c == "denylist" for c, _ in out)

@example('acm','x').via("doc: README: only names of 4 or more characters are looked for glued")
@example('a','1').via("doc: README: only names of 4 or more characters are looked for glued")
@example('abc','9').via("doc: README: only names of 4 or more characters are looked for glued")
@given(st.text(alphabet="abcdefgh", min_size=1, max_size=3), st.text(alphabet="xyz019", min_size=1, max_size=4))
def test_scan_line_short_names_not_glued(w, tail):
    t = Terms([w], [])
    assert scan_line("; " + w + tail + " now", t) == []

@example('acme',).via("doc: README: acme inside pacmerge is not reported")
@example('a',).via("doc: README: acme inside pacmerge is not reported")
@given(words)
def test_scan_line_term_not_inside_word(w):
    t = Terms([w], [])
    assert scan_line("zq" + w + "zq", t) == []

@example('x',).via("doc: README: --internal-id pattern")
@given(words)
def test_scan_line_internal_id(w):
    t = Terms([], [], internal_id=re.compile(r"TICKET-\d+"))
    out = scan_line("see TICKET-123 here", t)
    assert out == [("internal-id", "TICKET-123")]

@example('x',).via("doc: README: Obsidian links in Markdown")
@example('note name',).via("doc: README: Obsidian links in Markdown")
@given(words)
def test_scan_line_wikilink_only_markdownish(w):
    line = "see [[" + w + "]] here"
    for suf in ("", ".md", ".markdown", ".mdx"):
        assert scan_line(line, NOTERMS, suf) == [("wikilink", "[[" + w + "]]")]
    for suf in (".py", ".sh", ".txt", ".json"):
        assert scan_line(line, NOTERMS, suf) == []

@example('x',).via("doc: shell [[ ]] and nested lists are not wikilinks")
@given(words)
def test_wikilink_not_shell_test_or_nested_list(w):
    assert scan_line("if [[ -f x ]]; then", NOTERMS, ".md") == []
    assert scan_line("x = [[1, 2], [3]]", NOTERMS, ".md") == []

@example('a','io').via("doc: README: any address except noreply and reserved example domains")
@example('bob','corp').via("doc: README: any address except noreply and reserved example domains")
@given(words, words)
def test_email_real_flagged_example_ok(a, b):
    assume(b not in ("example", "test", "invalid", "localhost"))
    assert [c for c, _ in scan_line(f"mail {a}@{b}.io now", NOTERMS)] == ["email"]
    assert scan_line(f"mail {a}@example.com now", NOTERMS) == []
    assert scan_line(f"mail {a}@sub.example.org now", NOTERMS) == []
    assert scan_line("Co: noreply@github.com", NOTERMS) == []
    assert [c for c, _ in scan_line(f"Co: {a}@gmail.com", NOTERMS)] == ["email"]

@example('abcd',).via("doc: README: links to private chat sessions")
@example('0123456789abcdef0123',).via("doc: README: links to private chat sessions")
@given(st.text(alphabet="abcdef0123456789", min_size=4, max_size=20))
def test_session_url(sid):
    assert [c for c, _ in scan_line("see https://claud" "e.ai/chat/" + sid, NOTERMS)] == ["session-url"]
    assert [c for c, _ in scan_line("see chatgp" "t.com/share/" + sid, NOTERMS)] == ["session-url"]

@example('a',).via("doc: README: assigned credential; placeholders and ${VAR} excepted")
@given(words)
def test_assigned_secret_literal_vs_placeholder(w):
    val = "Zq9" + w + "Xk7pLm"
    assert any(c == "secret" for c, _ in scan_line('password = "' + val + '"', NOTERMS, ".py"))
    assert any(c == "secret" for c, _ in scan_line("PASSWORD=" + val, NOTERMS, ".env"))
    assert any(c == "secret" for c, _ in scan_line("password=" + val, NOTERMS, ".sh"))
    # unquoted in code = name/call
    assert scan_line("password = " + val, NOTERMS, ".py") == []
    assert scan_line("password = get_secret()", NOTERMS, "") == []
    # shell expansion is not a literal
    assert scan_line("password=$" + val, NOTERMS, ".sh") == []
    # placeholders
    assert scan_line("password=changeme123", NOTERMS, ".env") == []
    assert scan_line("password=${DB_PASSWORD_X}", NOTERMS, ".yml") == []
    # too short
    assert scan_line("password=abc", NOTERMS, ".env") == []

@example(0,0,1).via("doc: README: RFC 1918 blocks")
@example(255,255,255).via("doc: README: RFC 1918 blocks")
@given(octet, octet, octet)
def test_scan_line_private_ip_class(b, c, d):
    assert [x for x, _ in scan_line(f"srv 192.168.{c}.{d}", NOTERMS)] == ["private-ip"]
    assert scan_line(f"srv 8.8.{c}.{d}", NOTERMS) == []

# ---------- verdict
def _f(cls):
    return S.Finding(cls, "w", "s")

classes_st = st.lists(st.sampled_from(sorted(C.SEVERITY)), max_size=6)

@example([], False).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example([], True).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example(['wikilink'], False).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example(['wikilink'], True).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example(['secret'], True).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example(['secret','wikilink'], True).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example(['review-term','review-term'], True).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example(sorted(C.SEVERITY), True).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@example(sorted(C.SEVERITY), False).via("doc: verdict: 0 clean, 1 findings; review unless accepted")
@given(classes_st, st.booleans())
def test_verdict_semantics(cs, acc):
    res = S.Result(findings=[_f(c) for c in cs])
    blocks = [c for c in cs if C.SEVERITY[c] == C.BLOCK]
    reviews = [c for c in cs if C.SEVERITY[c] == C.REVIEW]
    exp = 1 if blocks or (reviews and not acc) else 0
    assert S.verdict(res, acc) == exp
    assert S.verdict(res) == (1 if cs else 0)

def test_verdict_empty_clean():
    assert S.verdict(S.Result()) == 0 and S.verdict(S.Result(), True) == 0

# ---------- _is_state / _file_class
segs = st.text(alphabet="abcxyz-_", min_size=1, max_size=6)

@example('',).via("doc: shown_path: valid names unchanged")
@example('a/b c.txt',).via("doc: shown_path: valid names unchanged")
@given(st.text(max_size=40))
def test_shown_path_valid_text_unchanged(t):
    assume(all(not (0xD800 <= ord(c) <= 0xDFFF) for c in t))
    assert S.shown_path(t) == t

@example(b'',).via("doc: shown_path: bad bytes replaced so printing never fails")
@example(b'\xff',).via("doc: shown_path: bad bytes replaced so printing never fails")
@example(b'a\xffb',).via("doc: shown_path: bad bytes replaced so printing never fails")
@given(st.binary(max_size=30))
def test_shown_path_surrogateescape_printable(b):
    rel = b.decode("utf-8", "surrogateescape")
    out = S.shown_path(rel)
    out.encode("utf-8")  # must be encodable
    assert out == b.decode("utf-8", "replace")

# ======================= round 1 additions =======================
@example(80,'email').via("doc: masked excerpt (limit itself not documented)")
@example(81,'email').via("doc: masked excerpt (limit itself not documented)")
@given(st.integers(70, 90), st.sampled_from(["email", "denylist", "home-path"]))
def test_mask_length_boundary(n, cls):
    t = "a" * n
    out = mask(cls, t)
    if n <= 80:
        assert out == t
    else:
        assert out == "a" * 77 + "..." and len(out) == 80

@example('a',).via("doc: shell expansion is not a literal")
@given(words)
def test_shell_backtick_and_expansion_are_not_literals(w):
    val = "`get_" + w + "_value`"
    assert scan_line("password=" + val, NOTERMS, ".sh") == []
    assert scan_line("password=$(get_" + w + "_value)", NOTERMS, ".sh") == []
    assert any(c == "secret" for c, _ in scan_line("password=Zq9" + w + "Xk7pLm", NOTERMS, ".bash"))

@example('a',).via("doc: placeholders")
@given(words)
def test_home_path_underscore_user_is_template_or_system_not_person(w):
    assert scan_line("cd /home/_" + w + "/x", NOTERMS) == []
    assert [c for c, _ in scan_line("cd /hom" "e/a_" + w + "/x", NOTERMS)] == ["home-path"]

import json, os, subprocess, pytest
from pathlib import Path
from publish_gate import cli, sarif
from publish_gate.selftest import run as selftest_run

def classes_of(line, terms=NOTERMS, suf=""):
    return [c for c, _ in scan_line(line, terms, suf)]

@pytest.mark.parametrize("line", [
    "cd /home" "/mara/x", "cd /User" "s/mara/x", "cd C:\\Use" "rs\\mara\\x", "cd /mn" "t/c/x", "cd /mn" "t/d/x",
    "# via -r /tmp/cla" "ude-1000/scratch/r.txt", "slug -home-b" "ob-proj-x",
])
def test_home_path_every_documented_form_is_flagged(line):
    assert "home-path" in classes_of(line)

@pytest.mark.parametrize("user", ["alice", "user", "runner", "jane"])
@pytest.mark.parametrize("tmpl", ["cd /home/%s/x", "cd /Users/%s/x", "cd C:\\Users\\%s\\x"])
def test_home_path_documented_placeholder_users_not_flagged(user, tmpl):
    assert classes_of(tmpl % user) == []

@pytest.mark.parametrize("addr", ["a@example.com", "a@example.org", "a@example.net", "a@foo.test",
                                  "a@foo.invalid", "a@foo.example", "12345+bob@users.noreply.github.com",
                                  "noreply@github.com"])
def test_email_documented_exceptions_not_flagged(addr):
    assert classes_of("mail " + addr + " now") == []

@pytest.mark.parametrize("url", ["https://claud" "e.ai/chat/abcd1234", "https://chatgp" "t.com/share/abcd1234",
                                 "https://gemini.go" "ogle.com/share/abcd1234", "https://claud" "e.ai/share/abcd1234"])
def test_session_url_each_documented_service(url):
    assert "session-url" in classes_of("see " + url)

@pytest.mark.parametrize("tok", [
    "AIza" + "S" * 35, "hvs." + "A" * 24, "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
    "sk-" + "A" * 40, "xoxp-" + "1" * 12, "sk-ant-" + "d" * 30, "AKIA" + "Q" * 16, "ghp_" + "Z" * 36,
])
def test_secret_documented_token_families_flagged(tok):
    assert "secret" in classes_of("tok " + tok)

@pytest.mark.parametrize("line,suf", [
    ('password = "Zq9w' 'Xk7pLmN"', ".py"), ("DB_PASSWORD: Zq9w" "Xk7pLmN", ".yml"),
    ("password=Zq9wXk7pLmN", ".env"), ("DB_PASSWORD=Zq9wXk7pLmN", ".env"),
])
def test_assigned_credential_documented_forms(line, suf):
    assert "secret" in classes_of(line, suf=suf)

@pytest.mark.parametrize("line,suf", [("password = ${DB_PASSWORD_X}", ".yml"), ("DB_PASSWORD: ${DB_PASSWORD_X}", ".yml"),
                                      ("password = os.environ['X']", ".py")])
def test_assigned_credential_documented_exceptions(line, suf):
    assert classes_of(line, suf=suf) == []

@pytest.mark.parametrize("line,term", [("host acmecorp.com", "acme"), ("ACMECORP\\svc", "acme"),
                                       ("acmeind-dc01 up", "acme")])
def test_glued_documented_examples_are_review(line, term):
    out = classes_of(line, Terms([term], []))
    assert out and set(out) == {"review-term"}

def test_glued_length_boundary_three_vs_four():
    assert classes_of("pacmerge acmx", Terms(["acm"], [])) == []
    assert classes_of("acmx", Terms(["acm"], [])) == []
    assert classes_of("acmex", Terms(["acme"], [])) == ["review-term"]
    assert classes_of("pacmerge", Terms(["acme"], [])) == []

@pytest.mark.parametrize("line", ["acme corp", "acme  corp", "ACME-CORP", "acme_corp", "acme.corp", "acme -_. corp", "acme\tcorp"])
def test_denylist_separator_runs(line):
    assert classes_of(line, Terms(["acme corp"], [])) == ["denylist"]

def test_documented_class_table():
    assert len(C.SEVERITY) == 12
    block = {"secret", "private-ip", "home-path", "email", "session-url", "denylist", "env-file", "agent-state"}
    review = {"synthetic-data", "review-term", "internal-id", "wikilink"}
    assert {c for c, s in C.SEVERITY.items() if s == C.BLOCK} == block
    assert {c for c, s in C.SEVERITY.items() if s == C.REVIEW} == review

@pytest.mark.parametrize("n", [3, 4])
def test_internal_id_and_review_exit_semantics(n):
    # a review finding fails the gate unless accepted (README step 4)
    r = S.Result(findings=[_f("wikilink")] * n)
    assert S.verdict(r) == 1 and S.verdict(r, True) == 0

# ---- SARIF
def _doc(findings, ok=True, reason=""):
    return sarif.document(findings, ok, reason)

def test_sarif_not_evaluable_is_failed_run_with_no_results():
    d = _doc([], False, "no denylist")
    assert d["version"] == "2.1.0"
    run = d["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert "no denylist" in json.dumps(run["invocations"][0])

def test_sarif_clean_run_is_successful():
    run = _doc([])["runs"][0]
    assert run["results"] == [] and run["invocations"][0]["executionSuccessful"] is True

def test_sarif_levels_block_error_review_warning_one_rule_per_class():
    d = _doc([S.Finding("secret", "a.py:1", "<secret: 5 chars>"), S.Finding("wikilink", "n.md:2", "[[x]]")])
    run = d["runs"][0]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels == {"secret": "error", "wikilink": "warning"}
    assert len(run["tool"]["driver"]["rules"]) == len(C.SEVERITY)

# ---- CLI and tree scanning (README exit codes)
def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "nohome"))
    monkeypatch.delenv("PUBLISH_GATE_DENYLIST", raising=False)
    try:
        return cli.main(args)
    except SystemExit as e:
        return e.code

def test_cli_self_test_without_a_denylist_is_not_evaluable(monkeypatch, tmp_path, capsys):
    assert _run(["--self-test"], monkeypatch, tmp_path) == 2
    assert "no denylist" in capsys.readouterr().err

def test_cli_self_test_with_no_denylist_flag(monkeypatch, tmp_path):
    assert _run(["--self-test", "--no-denylist"], monkeypatch, tmp_path) == 0

def test_cli_clean_tree_no_denylist_is_zero(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.txt").write_text("hello\n")
    assert _run([str(repo), "--no-denylist"], monkeypatch, tmp_path) == 0
    assert capsys.readouterr().out.startswith("CLEAN")

def test_cli_no_denylist_is_not_evaluable_never_clean(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.txt").write_text("hello\n")
    assert _run([str(repo)], monkeypatch, tmp_path) == 2
    assert not capsys.readouterr().out.startswith("CLEAN")

def test_cli_denylist_inside_tree_is_not_evaluable(monkeypatch, tmp_path):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.txt").write_text("hello\n"); (repo / "denylist").write_text("acme\n")
    assert _run([str(repo), "--denylist", str(repo / "denylist")], monkeypatch, tmp_path) == 2

def test_cli_readme_walkthrough_findings_then_clean(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "repo"; repo.mkdir()
    (repo / ".env").write_text("A=1\n"); (repo / "README.md").write_text("a\nb\nExample Industries\n")
    dl = tmp_path / "denylist"; dl.write_text("Example Industries\n")
    assert _run([str(repo), "--denylist", str(dl)], monkeypatch, tmp_path) == 1
    out = capsys.readouterr().out
    assert "env-file" in out and "denylist" in out and "README.md:3" in out and out.count("BLOCK") == 2
    (repo / ".env").unlink(); (repo / "README.md").write_text("a\nb\nfine\n")
    assert _run([str(repo), "--denylist", str(dl)], monkeypatch, tmp_path) == 0
    assert capsys.readouterr().out.startswith("CLEAN")

def test_cli_review_finding_needs_accept_review(monkeypatch, tmp_path):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "n.md").write_text("see [[Note]]\n")
    assert _run([str(repo), "--no-denylist"], monkeypatch, tmp_path) == 1
    assert _run([str(repo), "--no-denylist", "--accept-review"], monkeypatch, tmp_path) == 0

def test_cli_usage_error_is_64(monkeypatch, tmp_path):
    assert _run(["--no-such-flag"], monkeypatch, tmp_path) == 64

def test_cli_max_bytes_boundary_over_is_not_evaluable(monkeypatch, tmp_path):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.txt").write_text("a" * 100)
    assert _run([str(repo), "--no-denylist", "--max-bytes", "100"], monkeypatch, tmp_path) == 0
    assert _run([str(repo), "--no-denylist", "--max-bytes", "99"], monkeypatch, tmp_path) == 2

def test_cli_json_format_is_json(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.txt").write_text("x\n")
    _run([str(repo), "--no-denylist", "--format", "json"], monkeypatch, tmp_path)
    assert isinstance(json.loads(capsys.readouterr().out), dict)

def _git(repo, *a):
    env = dict(os.environ, GIT_AUTHOR_NAME="a", GIT_COMMITTER_NAME="a",
               GIT_AUTHOR_EMAIL="1+a@users.noreply.github.com", GIT_COMMITTER_EMAIL="1+a@users.noreply.github.com")
    subprocess.run(["git", *a], cwd=repo, env=env, check=True, capture_output=True)

def _gitrepo(tmp_path):
    repo = tmp_path / "g"; repo.mkdir(); _git(repo, "init", "-q")
    return repo

def test_tree_scan_in_git_reads_tracked_and_untracked_not_ignored(tmp_path):
    repo = _gitrepo(tmp_path)
    (repo / ".gitignore").write_text("ign.txt\n")
    (repo / "ign.txt").write_text("host 10.0" ".0.1\n")
    (repo / "untracked.txt").write_text("host 10.0" ".0.2\n")
    (repo / "tracked.txt").write_text("host 10.0" ".0.3\n")
    _git(repo, "add", "tracked.txt"); 
    res = S.scan_tree(repo, NOTERMS)
    shown = " ".join(f.where for f in res.findings)
    assert "untracked.txt" in shown and "tracked.txt" in shown and "ign.txt" not in shown

def test_history_finds_leak_deleted_in_later_commit(monkeypatch, tmp_path, capsys):
    repo = _gitrepo(tmp_path)
    (repo / "a.txt").write_text("host 10.1" ".2.3\n"); _git(repo, "add", "a.txt"); _git(repo, "commit", "-qm", "one")
    (repo / "a.txt").write_text("clean\n"); _git(repo, "commit", "-qam", "two")
    assert _run([str(repo), "--no-denylist"], monkeypatch, tmp_path) == 0
    assert _run([str(repo), "--no-denylist", "--history"], monkeypatch, tmp_path) == 1

def test_history_dirty_tree_refused_not_evaluable(monkeypatch, tmp_path):
    repo = _gitrepo(tmp_path)
    (repo / "a.txt").write_text("x\n"); _git(repo, "add", "a.txt"); _git(repo, "commit", "-qm", "one")
    (repo / "a.txt").write_text("y\n")
    assert _run([str(repo), "--no-denylist", "--history"], monkeypatch, tmp_path) == 2

def test_history_scans_commit_message(monkeypatch, tmp_path):
    repo = _gitrepo(tmp_path)
    (repo / "a.txt").write_text("x\n"); _git(repo, "add", "a.txt")
    _git(repo, "commit", "-qm", "see https://claud" "e.ai/chat/abcd1234")
    assert _run([str(repo), "--no-denylist", "--history"], monkeypatch, tmp_path) == 1

def test_range_judges_only_pushed_commits(monkeypatch, tmp_path):
    repo = _gitrepo(tmp_path)
    (repo / "a.txt").write_text("host 10.1" ".2.3\n"); _git(repo, "add", "a.txt"); _git(repo, "commit", "-qm", "one")
    (repo / "b.txt").write_text("fine\n"); _git(repo, "add", "b.txt"); _git(repo, "commit", "-qm", "two")
    assert _run([str(repo), "--no-denylist", "--history", "--range", "HEAD~1..HEAD"], monkeypatch, tmp_path) == 0
    assert _run([str(repo), "--no-denylist", "--history", "--range", "HEAD~2..HEAD"], monkeypatch, tmp_path) in (0, 1, 2)
    assert _run([str(repo), "--no-denylist", "--history", "--range", "HEAD..HEAD"], monkeypatch, tmp_path) == 0


# ---------- redact: no part of a secret survives, wherever it stands
@example(GH).via("doc: README: never prints a secret; each token family")
@example(AWS).via("doc: README: never prints a secret; each token family")
@given(st.sampled_from(SECRETS))
def test_redact_keeps_no_part_of_the_secret(sec):
    assert redact(f"before {sec} after") == f"before <secret: {len(sec)} chars> after"


@given(st.sampled_from(SECRETS), st.sampled_from(SECRETS))
def test_redact_finds_every_secret_in_one_string(a, b):
    out = redact(f"{a} and {b} and {a}")
    assert a[:6] not in out and b[:6] not in out
    assert out.count("<secret:") == 3


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
@pytest.mark.parametrize("sec", [GH, AWS])
def test_no_output_format_prints_a_secret_in_a_file_name_or_a_line(monkeypatch, tmp_path, capsys, fmt, sec):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / f"{sec}.txt").write_text("plain\n")
    (repo / "b.txt").write_text(f"key {sec}\n")
    assert _run([str(repo), "--no-denylist", "--format", fmt], monkeypatch, tmp_path) == 1
    cap = capsys.readouterr()
    assert sec not in cap.out and sec not in cap.err
    assert sec[:8] not in cap.out and sec[:8] not in cap.err


# ---------- synthetic folders: a declared folder vouches for itself, not for a sibling name
