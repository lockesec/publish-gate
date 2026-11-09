"""The same discipline as test_properties.py, for boundaries the docs state but only an internal
helper exposes on its own: file classes, decoding, private addresses and glued names. They call
private helpers, so they are not spec-first the way test_properties.py is."""
import pytest

pytest.importorskip("hypothesis", reason="pip install hypothesis to run the property tests")
import re, ipaddress
from pathlib import PurePosixPath
from hypothesis import given, assume, example, settings, strategies as st  # noqa: E402
import publish_gate.classes as C
import publish_gate.scan as S
from publish_gate.classes import Terms, scan_line, redact, mask, _private_ips, _glued_token, _terms_re

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
PRIV = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                          "169.254.0.0/16", "100.64.0.0/10")]
octet = st.integers(0, 255)

@example(10,0,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(10,255,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(9,255,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(11,0,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(172,15,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(172,16,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(172,31,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(172,32,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(192,167,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(192,168,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(192,168,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(192,169,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(169,253,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(169,254,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(169,254,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(169,255,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(100,63,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(100,64,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(100,127,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(100,128,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(127,0,0,1).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(192,0,2,1).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(198,51,100,1).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(203,0,113,1).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(0,0,0,0).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@example(255,255,255,255).via("doc: README: RFC 1918, link-local, CGNAT in; documentation ranges and loopback out; range edges")
@given(octet, octet, octet, octet)
def test_private_ips_exact_membership(a, b, c, d):
    ip = f"{a}.{b}.{c}.{d}"
    got = _private_ips("host " + ip + " end")
    priv = any(ipaddress.ip_address(ip) in n for n in PRIV)
    assert got == ([ip] if priv else [])

@example(0,0,0,256).via("doc: octet range 0-255")
@example(255,255,255,999).via("doc: octet range 0-255")
@given(octet, octet, octet, st.integers(256, 999))
def test_private_ips_out_of_range_octet(a, b, c, d):
    assert _private_ips(f"x 10.{b}.{c}.{d} y") == []
    assert _private_ips(f"x 192.168.{c}.{d} y") == []

@pytest.mark.parametrize("net", ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.0/31"])
def test_private_network_range_is_not_a_host(net):
    assert _private_ips(f"net {net} end") == []


@pytest.mark.parametrize("cidr,ip", [("10.1" ".2.3/24", "10.1" ".2.3"), ("10.0" ".0.1/8", "10.0" ".0.1"), ("10.1" ".2.1/31", "10.1" ".2.1")])
def test_a_prefix_with_host_bits_set_is_a_host(cidr, ip):
    assert _private_ips(f"net {cidr} end") == [ip]


@example(0,0,0).via("doc: README: private host as /32 or in a URL or with a port")
@example(255,255,255).via("doc: README: private host as /32 or in a URL or with a port")
@given(octet, octet, octet)
def test_private_ips_slash32_is_host(b, c, d):
    ip = f"10.{b}.{c}.{d}"
    assert _private_ips(f"host {ip}/32 end") == [ip]
    assert _private_ips(f"http://{ip}/path") == [ip]
    assert _private_ips(f"{ip}:8080") == [ip]

@example(0,0,0,0).via("doc: version-like dotted numbers are not addresses")
@example(1,1,1,1).via("doc: version-like dotted numbers are not addresses")
@given(octet, octet, octet, octet)
def test_private_ips_not_inside_longer_dotted_number(a, b, c, d):
    assert _private_ips(f"v1.10.{b}.{c}.{d}") == []
    assert _private_ips(f"10.{b}.{c}.{d}.5") == []

@example('',).via("doc: no digits, no address")
@given(safe_text)
def test_private_ips_no_digits_none(t):
    assert _private_ips(t) == []

# ---------- _terms_re
@example(['acme','corp'], ' ', '', '').via("doc: name matched across spaces, hyphens, underscores, dots")
@example(['acme','corp'], '-', '', '').via("doc: name matched across spaces, hyphens, underscores, dots")
@example(['acme','corp'], '_', '', '').via("doc: name matched across spaces, hyphens, underscores, dots")
@example(['acme','corp'], '.', '', '').via("doc: name matched across spaces, hyphens, underscores, dots")
@example(['acme','corp'], ' - ', '', '').via("doc: name matched across spaces, hyphens, underscores, dots")
@example(['acme','corp'], '  ', '', '').via("doc: name matched across spaces, hyphens, underscores, dots")
@example(['acme'], ' ', '', '').via("doc: name matched across spaces, hyphens, underscores, dots")
@example(['a','b','c'], '.', '(', ')').via("doc: name matched across spaces, hyphens, underscores, dots")
@given(st.lists(words, min_size=1, max_size=3), st.sampled_from([" ", "-", "_", ".", " - ", "  "]),
       st.sampled_from(["", " ", "(", "\"", "/"]), st.sampled_from(["", " ", ")", ",", "/"]))
def test_terms_re_bounded_finds_term_across_separators(ws, sep, pre, post):
    term = " ".join(ws)
    rx = _terms_re([term])
    line = pre + sep.join(ws).upper() + post
    assert rx.search(line)

@example('acme','a').via("doc: a bounded name is not found inside a word")
@example('acme','0').via("doc: a bounded name is not found inside a word")
@example('a','z').via("doc: a bounded name is not found inside a word")
@given(words, st.sampled_from("abcxyz0123456789"))
def test_terms_re_bounded_not_inside_word(w, ch):
    rx = _terms_re([w])
    assert not rx.search(ch + w)
    assert not rx.search(w + ch)

@example([],).via("doc: no terms, no regex")
@example([""],).via("doc: no terms, no regex")
@example([' ', '\t'],).via("doc: no terms, no regex")
@given(st.lists(st.sampled_from(["", " ", "  ", "\t"]), max_size=3))
def test_terms_re_empty_is_none(ts):
    assert _terms_re(ts) is None
    assert _terms_re(ts, bounded=False) is None

@example('acme','corp').via("doc: names: longest first")
@given(words, words)
def test_terms_re_longest_alternative_wins(a, b):
    assume(a != b)
    rx = _terms_re([a, a + " " + b])
    m = rx.search(a + " " + b)
    assert m and m.group(0) == a + " " + b

@example('acme','c').via("doc: unbounded finds inside")
@given(words, st.text(alphabet="abc012", min_size=1, max_size=5))
def test_terms_re_unbounded_matches_inside(w, tail):
    rx = _terms_re([w], bounded=False)
    assert rx.search("zz" + w + tail)

@example('.',).via("doc: terms are literal names")
@example('*',).via("doc: terms are literal names")
@example('a|b',).via("doc: terms are literal names")
@example('\\',).via("doc: terms are literal names")
@example('(',).via("doc: terms are literal names")
@example('[a]',).via("doc: terms are literal names")
@example('^$',).via("doc: terms are literal names")
@given(st.text(alphabet=".*+?[](){}|^$\\a", min_size=1, max_size=8))
def test_terms_re_escapes_metacharacters(t):
    assume(t.strip())
    rx = _terms_re([t], bounded=False)
    assert rx.search("<<" + t + ">>")

# ---------- _glued_token
def _first(term, line):
    rx = _terms_re([term], bounded=False)
    return line, rx.search(line)

@example('acme','corp').via("doc: README: name starting a longer token")
@example('acme','1').via("doc: README: name starting a longer token")
@given(words, st.text(alphabet="abcxyz019", min_size=1, max_size=6))
def test_glued_name_starting_token_returns_whole_token(w, tail):
    line, m = _first(w, "; " + w + tail + " now")
    tok = _glued_token(line, m)
    assert tok == w + tail

@example('acme','x').via("doc: README: acme-dc01 style tokens")
@given(words, st.text(alphabet="abcxyz019", min_size=1, max_size=4))
def test_glued_token_extends_over_token_chars(w, tail):
    line, m = _first(w, w + tail + "-a.b_c;rest")
    assert _glued_token(line, m) == w + tail + "-a.b_c"

@example('acme','p','merge').via("doc: README: acme inside pacmerge not reported")
@example('acme','p','').via("doc: README: acme inside pacmerge not reported")
@given(words, st.sampled_from("abcxyz019"), st.text(alphabet="abc", max_size=3))
def test_glued_mid_word_is_none(w, pre, tail):
    rx = _terms_re([w], bounded=False)
    line = pre + w + tail
    m = rx.match(line, 1)       # the occurrence that starts right after the prefix character
    assert m
    assert _glued_token(line, m) is None

# ---------- scan_line
@example('mara',).via("doc: README: /home/<user>, /Users/<user>; placeholders fine")
@example('bob',).via("doc: README: /home/<user>, /Users/<user>; placeholders fine")
@given(words)
def test_home_path_real_user_and_placeholder(w):
    assume(w not in C._PLACEHOLDER_USERS)
    out = scan_line("cd /home/" + w + "/proj", NOTERMS)
    assert [c for c, _ in out] == ["home-path"]
    for u in sorted(C._PLACEHOLDER_USERS):
        assert scan_line("cd /home/" + u + "/proj", NOTERMS) == []
        assert scan_line("cd /Users/" + u.upper() + "/proj", NOTERMS) == []

def _f(cls):
    return S.Finding(cls, "w", "s")

classes_st = st.lists(st.sampled_from(sorted(C.SEVERITY)), max_size=6)

segs = st.text(alphabet="abcxyz-_", min_size=1, max_size=6)

@example([], 'MEMORY.md').via("doc: README agent-state: MEMORY.md, CLAUDE.local.md, .claude/settings.local.json")
@example([], 'CLAUDE.local.md').via("doc: README agent-state: MEMORY.md, CLAUDE.local.md, .claude/settings.local.json")
@example(['.claude'], 'settings.local.json').via("doc: README agent-state: MEMORY.md, CLAUDE.local.md, .claude/settings.local.json")
@example(['a','b'], 'session-state.md').via("doc: README agent-state: MEMORY.md, CLAUDE.local.md, .claude/settings.local.json")
@given(st.lists(segs, max_size=3), st.sampled_from(["MEMORY.md", "memory.md", "CLAUDE.local.md",
       "settings.local.json", "session-state.md", "session-state-1.json", ".claude.json"]))
def test_is_state_names(d, n):
    assert S._is_state(PurePosixPath(*d, n))

@example([], 'x', '.db').via("doc: README agent-state: databases and pickles")
@example([], 'x', '.sqlite').via("doc: README agent-state: databases and pickles")
@example([], 'x', '.pkl').via("doc: README agent-state: databases and pickles")
@example(['d'], 'x', '.pickle').via("doc: README agent-state: databases and pickles")
@given(st.lists(segs, max_size=3), segs, st.sampled_from([".db", ".sqlite", ".sqlite3", ".duckdb", ".parquet", ".pkl", ".pickle", ".DB", ".Pkl"]))
def test_is_state_ext(d, n, e):
    assert S._is_state(PurePosixPath(*d, n + e))

@example([], '.claud' 'e-mem', [], 'a').via("doc: claud" "e-mem directory is state")
@given(st.lists(segs, max_size=2), st.sampled_from([".claud" "e-mem", "claud" "e-mem"]), st.lists(segs, max_size=2), segs)
def test_is_state_dirs(a, sd, b, n):
    assert S._is_state(PurePosixPath(*a, sd, *b, n + ".txt"))

@example([], 'a').via("doc: README: session transcripts")
@example(['a'], 'a').via("doc: README: session transcripts")
@given(st.lists(segs, max_size=2), segs)
def test_is_state_transcripts(a, n):
    assert S._is_state(PurePosixPath(*a, ".claude", "projects", "x", n + ".jsonl"))
    assert not S._is_state(PurePosixPath(*a, ".claude", "x", n + ".jsonl"))
    assert not S._is_state(PurePosixPath(*a, "projects", "x", n + ".jsonl"))
    assert not S._is_state(PurePosixPath(*a, ".claude", "projects", "x", n + ".txt"))

@example([], 'a').via("doc: ordinary files are not state")
@example(['src'], 'main').via("doc: ordinary files are not state")
@given(st.lists(segs, max_size=3), segs)
def test_is_state_ordinary_files_not_state(d, n):
    assume(n.lower() not in ("memory",) and not n.startswith("session-state"))
    assert not S._is_state(PurePosixPath(*d, n + ".py"))
    assert not S._is_state(PurePosixPath(*d, n + ".md"))

@example([], '.env').via("doc: README: committed .env blocks")
@example(['a'], '.env.local').via("doc: README: committed .env blocks")
@given(st.lists(segs, max_size=3), st.sampled_from([".env", ".env.local", ".env.prod", ".env.production.x"]))
def test_file_class_env(d, n):
    assert S._file_class(PurePosixPath(*d, n), set()) == "env-file"

@example([], '.env.example').via("doc: README: .env.example and friends fine")
@example([], '.env.sample').via("doc: README: .env.example and friends fine")
@given(st.lists(segs, max_size=3), st.sampled_from([".env.example", ".env.sample", ".env.template", ".env.dist"]))
def test_file_class_env_templates_ok(d, n):
    assert S._file_class(PurePosixPath(*d, n), set()) is None

@example('a',).via("doc: env lookalikes are fine")
@given(segs)
def test_file_class_not_env_lookalikes(n):
    assert S._file_class(PurePosixPath(n + ".env"), set()) is None
    assert S._file_class(PurePosixPath("x.envrc"), set()) is None
    assert S._file_class(PurePosixPath(".environment"), set()) is None
    assert S._file_class(PurePosixPath(".envx"), set()) is None

@example('d','n').via("doc: README: synthetic-data review class")
@example('a','a').via("doc: README: synthetic-data review class")
@given(segs, segs)
def test_file_class_state_and_synthetic(d, n):
    p = PurePosixPath(d, n + ".db")
    assert S._file_class(p, set()) == "agent-state"
    assert S._file_class(p, {d}) == "synthetic-data"
    assert S._file_class(p, {d + "x"}) == "agent-state"       # prefix must be a whole directory
    assert S._file_class(p, {"other"}) == "agent-state"
    assert S._file_class(PurePosixPath(d, n + ".py"), {d}) is None

@example('a',).via("doc: env-file outranks state")
@given(segs)
def test_file_class_env_beats_state(n):
    assert S._file_class(PurePosixPath(n, ".env"), {n}) == "env-file"

# ---------- _declares_synthetic
@example('', 'synthetic: true', '').via("doc: SYNTHETIC-DATA declares synthetic: true")
@example('\n\n  ', 'Synthetic: TRUE', '\r\nmore: 1').via("doc: SYNTHETIC-DATA declares synthetic: true")
@given(st.sampled_from(["", " ", "\n", "\n\n  "]), st.sampled_from(["synthetic: true", "Synthetic: TRUE", "  synthetic: true  "]),
       st.sampled_from(["", "\nmore", "\r\nmore: 1"]))
def test_declares_synthetic_first_nonblank_line(pre, decl, post):
    assert S._declares_synthetic(pre + decl + post)

@example('',).via("doc: blank declares nothing")
@example(' ',).via("doc: blank declares nothing")
@example('\n',).via("doc: blank declares nothing")
@given(st.text(alphabet=" \t\r\n", max_size=30))
def test_declares_synthetic_blank_false(t):
    assert S._declares_synthetic(t) is False

@example('',).via("doc: declaration must be first line")
@given(st.text(alphabet="abc: ", max_size=20))
def test_declares_synthetic_must_be_first_line(t):
    assert not S._declares_synthetic("name: x\nsynthetic: true\n" + t)
    assert not S._declares_synthetic("synthetic: truex")
    assert not S._declares_synthetic("synthetic: false")
    assert not S._declares_synthetic("# synthetic: true")

@example('',).via("doc: total function")
@given(st.text(max_size=60))
def test_declares_synthetic_never_raises(t):
    assert S._declares_synthetic(t) in (True, False)

# ---------- _text
@example('',).via("doc: UTF-8 text is text")
@example('é',).via("doc: UTF-8 text is text")
@given(st.text(max_size=100))
def test_text_utf8_roundtrip(t):
    assume("\x00" not in t)
    assert S._text(t.encode("utf-8")) == t

@example(b'',).via("doc: README: binary is not read")
@example(b'a',).via("doc: README: binary is not read")
@given(st.binary(max_size=200))
def test_text_nul_in_head_not_utf8_text(b):
    data = b"\x00" + b
    assume(not data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")))
    assume(len(data) < 8)   # too short to be NUL-interleaved utf-16
    assert S._text(data) is None

@example('a',).via("doc: README: UTF-16 read as text")
@given(st.text(alphabet="abcdefg hij", min_size=1, max_size=60))
def test_text_utf16_bom(t):
    assert S._text(("\ufeff" + t).encode("utf-16-le").join([b"\xff\xfe", b""])[:0] + b"\xff\xfe" + t.encode("utf-16-le")) == t
    assert S._text(b"\xfe\xff" + t.encode("utf-16-be")) == t

@example('abcdefgh',).via("doc: README: UTF-16 (PowerShell, .reg) read as text")
@given(st.text(alphabet="abcdefg hij", min_size=8, max_size=60))
def test_text_utf16_no_bom_ascii(t):
    assert S._text(t.encode("utf-16-le")) == t
    assert S._text(t.encode("utf-16-be")) == t

@example('',).via("doc: BOM stripped")
@example('a',).via("doc: BOM stripped")
@given(st.text(alphabet="abcdefg hij", max_size=40))
def test_text_utf8_bom_stripped(t):
    assert S._text(b"\xef\xbb\xbf" + t.encode()) == t

@example(b'',).via("doc: total function")
@example(b'\xff\xfe',).via("doc: total function")
@example(b'\x00',).via("doc: total function")
@given(st.binary(max_size=60))
def test_text_never_raises_and_returns_str_or_none(b):
    r = S._text(b)
    assert r is None or isinstance(r, str)

@example(b'\xff',).via("doc: invalid bytes replaced, not binary")
@given(st.binary(min_size=1, max_size=60))
def test_text_invalid_utf8_without_nul_is_replaced_not_binary(b):
    assume(b"\x00" not in b and not b.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")))
    r = S._text(b)
    assert r == b.decode("utf-8", errors="replace")

# ---------- shown_path
@example('acme','a','-','x').via("doc: token start")
@given(words, st.sampled_from("abcxyz019"), st.sampled_from(["-", ".", "_", " ", "/"]),
       st.text(alphabet="xyz019", min_size=1, max_size=4))
def test_glued_name_after_separator_after_alnum_still_starts_token(w, pre, sep, tail):
    # only the character directly before the name decides whether it starts a token
    line = pre + sep + w + tail
    rx = _terms_re([w], bounded=False)
    m = rx.match(line, 2)
    assert m
    assert _glued_token(line, m) == w + tail

@given(st.integers(0, 1), st.text(alphabet="abcdefg hij", min_size=1, max_size=1))
def test_text_nul_after_sniff_window_is_still_text(_, ch):
    data = b"a" * 8192 + b"\x00" + b"b"
    assert S._text(data) == data.decode()

@given(st.text(alphabet="abcdefg hij", min_size=4, max_size=4))
def test_text_utf16_four_chars_is_text(t):
    assert S._text(t.encode("utf-16-le")) == t
    assert S._text(t.encode("utf-16-be")) == t

@given(st.text(alphabet="abcdefg", min_size=9, max_size=9))
def test_text_utf16_tolerates_one_in_ten_non_ascii(t):
    s = t + "Ł"       # 10 chars, 1 non-ASCII (high byte not NUL)
    assert S._text(s.encode("utf-16-le")) == s
    assert S._text(s.encode("utf-16-be")) == s

@given(st.text(alphabet="abcdefg", min_size=8, max_size=20), st.integers(0, 7))
def test_text_utf16_with_embedded_nul_char_is_binary(t, i):
    s = t[:i] + "\x00" + t[i:]
    assert S._text(s.encode("utf-16-le")) is None

@given(st.text(alphabet="abcdefg hij", min_size=8, max_size=30))
def test_text_utf16_trailing_odd_byte_ignored(t):
    assert S._text(t.encode("utf-16-le") + b"x") == t
    assert S._text(t.encode("utf-16-be") + b"x") == t


# ======================= @example arm: documented boundaries with no property to attach to =======================
import json, os, subprocess, pytest
from pathlib import Path
from publish_gate import cli, sarif
from publish_gate.selftest import run as selftest_run

def classes_of(line, terms=NOTERMS, suf=""):
    return [c for c, _ in scan_line(line, terms, suf)]

def _doc(findings, ok=True, reason=""):
    return sarif.document(findings, ok, reason)

def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "nohome"))
    monkeypatch.delenv("PUBLISH_GATE_DENYLIST", raising=False)
    try:
        return cli.main(args)
    except SystemExit as e:
        return e.code

def _git(repo, *a):
    env = dict(os.environ, GIT_AUTHOR_NAME="a", GIT_COMMITTER_NAME="a",
               GIT_AUTHOR_EMAIL="1+a@users.noreply.github.com", GIT_COMMITTER_EMAIL="1+a@users.noreply.github.com")
    subprocess.run(["git", *a], cwd=repo, env=env, check=True, capture_output=True)

def _gitrepo(tmp_path):
    repo = tmp_path / "g"; repo.mkdir(); _git(repo, "init", "-q")
    return repo

@given(st.sampled_from(["2", "-old", "_x", ".bak"]))
def test_a_sibling_of_a_synthetic_folder_is_not_vouched_for(suffix):
    name = PurePosixPath("synth" + suffix) / "x.db"
    inside = PurePosixPath("synth") / "x.db"
    assert S._file_class(name, {"synth"}) == "agent-state"
    assert S._file_class(inside, {"synth"}) == "synthetic-data"
