"""The leak classes, judged one line at a time.

BLOCK classes fail the gate; REVIEW classes fail it unless a person accepts them
(`--accept-review`). Every pattern is a single pass over the line with bounded repetition.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass

BLOCK = "block"
REVIEW = "review"
SEVERITY = {
    "secret": BLOCK, "private-ip": BLOCK, "home-path": BLOCK, "email": BLOCK,
    "session-url": BLOCK, "denylist": BLOCK, "env-file": BLOCK, "agent-state": BLOCK,
    "review-term": REVIEW, "wikilink": REVIEW, "internal-id": REVIEW, "synthetic-data": REVIEW,
}
#: Classes whose excerpt is never shown, not even a prefix.
MASKED = frozenset({"secret"})

SECRET_PATTERNS = [
    re.compile(r"-{4,5} ?BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)? ?-{4,5}"),   # PEM, PGP, SSH2
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),              # AWS access key id
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),            # Slack
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),                 # Anthropic
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),           # OpenAI-style
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),                   # Google API key
    re.compile(r"\bhvs\.[A-Za-z0-9_-]{20,}\b"),                 # Vault service token
    re.compile(r"\bsk_live_(?![xX]{8})[A-Za-z0-9]{16,}\b"),     # Stripe
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),                  # GitLab
    re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),                     # Hugging Face
    re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}"),
    re.compile(r"hooks\.slack\.com/services/(?!T0+/B0+/)[A-Za-z0-9/]{20,}"),  # not Slack's own doc example
    re.compile(r"\bS[ACNOUPX][A-Z2-7]{56}\b"),                  # NATS NKEY seed
    re.compile(r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b"),      # Grafana service account
    re.compile(r"\bglc_[A-Za-z0-9+/_-]{32,}"),                   # Grafana Cloud
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
ASSIGNED_SECRET = re.compile(
    r"(?i)(?:\b|(?<=_))(?:api[_-]?key|secret[_-]?key[_-]?base|secret[_-]?key|secret[_-]?access[_-]?key|access[_-]?token|auth[_-]?token|token|"
    r"private[_-]?key|passphrase|passwd|password|pwd|pass|secret)\b[\"']?\s*[:=]\s*(?:([\"'])((?:(?!\1).){6,})\1|([^\s\"'#,;]{6,}))")
#: Any value of 8 or more counts; under a password's own names, 6 or more. A name such as `pwd` is
#: also the shell's working directory, so a path there is not a value.
_SHORT_OK = re.compile(r"(?i)^(?:passwd|password|pwd|pass)\b")
#: `pass` and `pwd` are ordinary words on their own (a test status, a working directory). Bare, the
#: value has to look like a credential: letters mixed with a digit or a symbol. `db_pass`,
#: `MYSQL_PWD` and `export PASS=` name a credential already.
_BARE_WORD = re.compile(r"(?i)^(?:pwd|pass)\b")
_CREDENTIAL_SHAPED = re.compile(r"(?=.*[A-Za-z])(?=.*[^A-Za-z_-])")
_EXPORT = re.compile(r"(?:^|[\s;])export\s+$")
#: A C macro names its value with a space, not `=`: `#define DB_PASSWORD "..."`. Only a quoted literal
#: with no space or slash counts; under a non-password name it must mix letters with a digit or symbol,
#: so `#define TOKEN_HEADER "Authorization"` stays quiet.
_DEFINE = re.compile(r"(?i)^\s*#\s*define\s+(\w*?(?:passw(?:or)?d|passphrase|secret|api_?key|token)\w*)\s+\"([^\"\s/\\]{6,})\"")


def _prefixed(line: str, at: int) -> bool:
    return (at > 0 and line[at - 1] in "_-") or _EXPORT.search(line[max(0, at - 40):at]) is not None
#: Secrets known by what surrounds them; a placeholder is not a secret. The scheme is capped, so a
#: long dotted line stays linear. A URL password stops at ? and #, and runs to the last @ before the
#: host, so it may hold an @ itself.
_BASIC = re.compile(r"(?i)\bauthorization[\"'`]?\s*[:=,]\s*[\"'`]?\s*basic\s+([A-Za-z0-9+/]{12,}={0,2})")
_BEARER = re.compile(r"(?i)\bauthorization[\"'`]?\s*[:=,]\s*[\"'`]?\s*bearer\s+([A-Za-z0-9._~+/${}()%#-]{20,})")
_URL_PASSWORD = re.compile(r"(?i)[a-z0-9+.-]{0,30}://([^\s/:@?#]*):((?:#\{|[^\s/?#]){6,})@([^\s/@:?#]+)")
_LOCAL_HOST = frozenset({"localhost", "127.0.0.1"})
#: A template is set aside and what is left is judged, so a literal beside one still counts. Each
#: span stops at the next opener, which keeps a line of bare openers linear. A bracket holding only
#: words stands for a secret. Case matters for $name: `$ecretPa55` is a password.
_TEMPLATE = re.compile(r"\{\{[^{}]*\}\}|\$\{[^{}]*\}|\$\([^()]*\)|%\{[^{}]*\}|#\{[^{}]*\}")
_TEMPLATE_LITERAL_FLOOR = 6
_DOC_SHAPE = re.compile(r"\$[A-Z_][A-Z0-9_]*|\$[a-z_][a-z0-9_]*|__[A-Z0-9_]+__|%[A-Za-z_]\w*%|%\(\w+\)s|"
                        r"<[A-Za-z_ -]*>|\{[A-Za-z_ -]*\}|\[[A-Za-z_ -]*\]|[xX]{6,}|\*{4,}|\.{4,}")
#: One of these alone, or several joined by - or _, reads as a placeholder (PASSWORD_HERE,
#: your-token-goes-here). A word outside the list makes it a value: my-horse-battery is one.
_DOC_ROOTS = frozenset({"changeme", "example", "placeholder", "password", "passwd", "redacted", "dummy",
                        "test", "secret", "yourpassword"})
_DOC_WORDS = _DOC_ROOTS | frozenset({"your", "my", "the", "a", "an", "access", "api", "auth", "key", "token",
                                     "db", "pass", "here", "goes", "now", "please", "value", "sample", "fake"})


def _doc_value(value: str) -> bool:
    rest = _TEMPLATE.sub("", value)
    if rest != value:
        return len(rest) < _TEMPLATE_LITERAL_FLOOR or _doc_value(rest)
    if _DOC_SHAPE.fullmatch(value):
        return True
    low = value.lower()
    if re.fullmatch(r"[a-z]+\d{0,3}", low):
        return low.rstrip("0123456789") in _DOC_ROOTS
    words = re.split(r"[-_]", low)
    return len(words) > 1 and all(w in _DOC_WORDS for w in words)


def _url_passwords(text: str):
    """Spans of the passwords in URLs on a line. user:same@localhost is a local default."""
    for m in _URL_PASSWORD.finditer(text):
        user, value, host = m.group(1), m.group(2), m.group(3)
        if _doc_value(value) or (user == value and host.lower() in _LOCAL_HOST):
            continue
        yield m.start(2), m.end(2)


#: The user:password pairs documentation uses in a Basic header.
_SAMPLE_WORDS = frozenset({"user", "username", "pass", "passwd", "password", "admin", "test", "foo", "bar",
                           "example", "secret", "aladdin", "opensesame"})


def _sample_pair(value: str) -> bool:
    try:
        pair = base64.b64decode(value, validate=True).decode("utf-8").lower()
    except ValueError:
        return False
    name, sep, word = pair.partition(":")
    return bool(sep) and name in _SAMPLE_WORDS and word in _SAMPLE_WORDS


def _context_spans(text: str) -> list:
    spans = list(_url_passwords(text))
    spans += [m.span(1) for m in _BEARER.finditer(text) if not _doc_value(m.group(1)) and not _CALL.match(m.group(1))]
    spans += [m.span(1) for m in _BASIC.finditer(text) if not _doc_value(m.group(1)) and not _sample_pair(m.group(1))]
    return spans


def redact(text: "str | None") -> "str | None":
    """Replace every recognised secret in a DISPLAYED string (a location, a file name, an error
    message) with its length, so no output format can print one, not even through a file name
    (outside review 2026-10-19: a token-named file printed in full in text, JSON and SARIF)."""
    if not text:
        return text
    for p in SECRET_PATTERNS:
        text = p.sub(lambda m: f"<secret: {len(m.group(0))} chars>", text)

    def hide_value(m):                    # an assigned credential: keep its name, hide the value
        g = m.lastindex
        return (m.group(0)[:m.start(g) - m.start()] + f"<secret: {len(m.group(g))} chars>"
                + m.group(0)[m.end(g) - m.start():])
    for a, b in sorted(_context_spans(text), reverse=True):
        text = text[:a] + f"<secret: {b - a} chars>" + text[b:]
    return ASSIGNED_SECRET.sub(hide_value, text)


#: A placeholder WORD is a whole word: `test`, `test_pw`, `test123` are placeholders, but
#: `testing_R3al!Pass` or `nullPointerAuth9` are real values that merely start with one.
_PLACEHOLDER = re.compile(r"(?i)^(?:\$\{?|<|\{|%|x{6,}|\*{4,}|your[_-]|os\.environ|getenv|"
                          r"(?:changeme|example|placeholder|redacted|dummy|test|none|null|true|false)"
                          r"(?![a-z]))")
#: In source code a secret is a quoted literal; an unquoted value there is a name or a call
#: (`password = get_secret()`). In config and env files an unquoted value is the value.
_CALL = re.compile(r"^[A-Za-z_][\w.]*\(")
#: `private_key` and `passphrase` usually name a file or a variable, and prose uses both words.
_KEY_NAME = re.compile(r"(?i)private|passphrase")
#: A real path: a named key file, or at least two slashes. Base64 may start with a slash too.
_KEY_PATH = re.compile(r"(?i)[\w./~-]*\w\.(?:pem|key|p12|pfx|der|ppk|asc)|(?:~|\.{0,2})/[\w.-]+(?:/[\w.-]+)+")


def _not_key_material(name: str, value: str, quoted: bool) -> bool:
    if name.lower().startswith("private") and _KEY_PATH.fullmatch(value):
        return True
    return not quoted and not re.search(r"\d|[a-z].*[A-Z]|[A-Z].*[a-z]|^[A-Z]+$", value)
_CODE_SUFFIXES = frozenset({".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go",
                            ".rs", ".rb", ".java", ".kt", ".cs", ".php"})
#: In these an unquoted word is a name when it reads as one (`options.password`, `fake_token`). One with
#: a digit in it is treated as a value, since a header's macro or a comment can hold a literal.
_NAMES_ARE_BARE = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".ex", ".exs", ".swift", ".scala"})
_BARE_NAME = re.compile(r"[A-Za-z_]+(?:\[[^\]]{0,40}\]|\([^)]{0,40}\))*"
                        r"(?:(?:\.|->|::)[A-Za-z_]+(?:\[[^\]]{0,40}\]|\([^)]{0,40}\))*)*[;)]*")
#: In a shell script an unquoted word IS a literal (`password=R3dTeam_42`); only an expansion
#: ($VAR, ${VAR}, $(cmd), `cmd`) is not. Outside review 2026-10-19: such a line read CLEAN.
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ksh"})

#: Names that stand for "some user" in docs, tests and CI (GitHub runners use /home/runner).
#: Your own user name is never on this list unless it is one of these words.
_PLACEHOLDER_USERS = frozenset({
    "user", "username", "name", "you", "yourname", "your-name", "me", "someone", "example",
    "demo", "test", "tester", "foo", "bar", "alice", "bob", "carol", "dave", "eve", "jane",
    "john", "joe", "runner", "ubuntu", "vagrant", "ec2-user", "admin", "shared"})
_HOME_USER = re.compile(r"(?:/home/|/Users/|Users\\+)([^/\\\s]+)", re.I)

HOME_PATH = re.compile(
    r"(?<![\w.~-])(?:/home/|/Users/)(?!<)[A-Za-z0-9._-]+(?![A-Za-z0-9._-])|[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+|"
    r"/mnt/[a-z]/|/tmp/claude-\d+/|-home-[a-z][a-z0-9._-]*-")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"
                   r"|\b[A-Za-z0-9._%+-]{1,64}@localhost\b")
# GitHub's own public addresses: noreply@ (web commits) and support@ (Dependabot's sign-off)
_OK_EMAIL = re.compile(r"(?i)^(?:noreply|support)@github\.com$|@(?:users\.noreply\.github\.com|(?:[\w-]+\.)*example\.(?:com|org|net)|"
                       r"(?:[\w-]+\.)*(?:example|test|invalid|localhost))$|@localhost$")
SESSION_URL = re.compile(
    r"claude\.ai/(?:code/session_|chat/|share/)[A-Za-z0-9_-]+|"
    r"chatgpt\.com/(?:c|share|g)/[A-Za-z0-9-]+|chat\.openai\.com/(?:c|share)/[A-Za-z0-9-]+|"
    r"gemini\.google\.com/(?:app|share)/[A-Za-z0-9]+")
# an Obsidian double-bracket link; not a nested list or a shell double-bracket test
WIKILINK = re.compile(r"\[\[(?![\s\"'\[\d:-])[^\]\n]{1,200}\]\]")
ALLOW = re.compile(r"publish-gate:\s*allow=([a-z,-]+)")
#: An inline marker is content in the judged file: it may not clear these.
NEVER_EXCUSED = frozenset({"secret", "denylist"})
# a full stop after the address ends a sentence; a digit after the dot makes it a longer version string
# an address written with a range prefix (/0 to /31) and no host bits set is a network (firewall
# docs, this table); with host bits set (`192.x.y.50/24`, an interface address), with /32, or
# with a URL path or a port after it, it is a host
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
                   r"(?!\d|\.\d)(?:/([12]?\d|3[01])(?!\d))?")
# built from parts so this module holds no literal private address
_PRIVATE_NETS = tuple(ipaddress.IPv4Network(".".join(p) + "/" + b) for p, b in
                      ((("10", "0", "0", "0"), "8"), (("172", "16", "0", "0"), "12"),
                       (("192", "168", "0", "0"), "16"), (("169", "254", "0", "0"), "16"),
                       (("100", "64", "0", "0"), "10")))
_MARKDOWN = frozenset({".md", ".markdown", ".mdx", ""})


@dataclass
class Terms:
    """Private names: `block` terms fail the gate, `review` terms need a person to accept
    them. Matching ignores case and treats any run of white space, hyphens, underscores or
    dots between the words as one separator. A name that starts a longer token
    (`ACMECORP\\svc`, `acme-dc01`, `acmeindustrial.com`) is a review finding: it is likely
    the name, but a common-word name (`Summit` in `SummitConfig`) may not be, so a person
    decides. Only names of GLUED_MIN characters or more are looked for glued; shorter ones
    match too much."""
    block: list
    review: list
    internal_id: "re.Pattern | None" = None

    def __post_init__(self):
        self._block = _terms_re(self.block)
        self._review = _terms_re(self.review)
        self._glued = _terms_re([x for x in self.block + self.review if len(x.strip()) >= GLUED_MIN],
                                bounded=False)
        self._glued_block = _terms_re([x for x in self.block if len(x.strip()) >= GLUED_MIN],
                                      bounded=False)


GLUED_MIN = 4


def _terms_re(terms, bounded=True):
    terms = [t for t in terms if t.strip()]
    if not terms:
        return None
    # words may be joined by any run of white space, hyphens, underscores or dots, so a term
    # is found in a file name or slug as well as in prose
    # glued, the words may also touch (`acmeindustrial.com`, `ZorblaxHoldings`)
    sep = r"[\s_.-]+" if bounded else r"[\s_.-]*"
    parts = [sep.join(re.escape(w) for w in t.split()) for t in sorted(terms, key=len, reverse=True)]
    body = "(?:" + "|".join(parts) + ")"
    if not bounded:
        return re.compile(body, re.I)
    return re.compile(r"(?<![A-Za-z0-9])" + body + r"(?![A-Za-z0-9])", re.I)


_ALNUM = re.compile(r"[A-Za-z0-9]")
_TOKEN = re.compile(r"[A-Za-z0-9_.-]*")


def _glued_token(line: str, s: "re.Match") -> "str | None":
    """The token a name STARTS and runs on into (`ACMECORP`, `acme-dc01`,
    `acmecorp.com`), or None. A name standing alone is the bounded patterns' finding, except
    that a many-word name written with its words touching (`ZorblaxHoldings`) is not one they
    see, so it is returned as it stands; one starting mid-word (`acme` in `pacmerge`) is almost
    never the name."""
    a, b = s.start(), s.end()
    if a > 0 and _ALNUM.match(line[a - 1]):
        return None
    if b >= len(line) or not _ALNUM.match(line[b]):
        return line[a:b]
    return line[a:b + len(_TOKEN.match(line, b).group(0))]


def mask(cls: str, text: str) -> str:
    if cls in MASKED:
        return f"<{cls}: {len(text)} chars, not shown>"
    t = text.strip()
    return t if len(t) <= 80 else t[:77] + "..."


def _private_ips(line: str) -> list:
    out = []
    for m in _IPV4.finditer(line):
        if any(int(g) > 255 for g in m.groups()[:4]):
            continue
        # zero-padded octets are not refused: a padded private address still names a private host, and a version
        # string such as 1.17.04.3 must not stop the scan
        ip = ipaddress.IPv4Address(".".join(str(int(g)) for g in m.groups()[:4]))
        if m.group(5) is not None:
            try:
                ipaddress.IPv4Network(f"{ip}/{m.group(5)}")   # strict: raises if host bits are set
                continue
            except ValueError:
                pass
        if any(ip in n for n in _PRIVATE_NETS):
            out.append(str(ip))
    return out


def scan_line(line: str, terms: Terms, suffix: str = "", excused: "list | None" = None) -> list:
    """[(class, shown excerpt)] for one line. A `publish-gate: allow=<class>[,<class>]`
    marker on the line excuses those classes on that line only, except a secret or a
    denylisted name (NEVER_EXCUSED). Each excused hit is appended to `excused` so the
    summary can count them."""
    allowed = set()
    m = ALLOW.search(line)
    if m:
        allowed = set(m.group(1).split(",")) - NEVER_EXCUSED
    raw = []                              # (class, text, span) of every hit not excused
    secret_spans = []

    def hit(cls, text, span=None, excusable=True):
        if span is None:
            i = line.find(text)
            span = (i, i + len(text)) if i >= 0 else None
        if cls == "secret" and span:
            secret_spans.append(span)
        if cls in allowed and excusable:
            if excused is not None:
                excused.append(cls)
        else:
            raw.append((cls, text, span))

    for p in SECRET_PATTERNS:
        for s in p.finditer(line):
            hit("secret", s.group(0), s.span())
    for a, b in _context_spans(line):
        hit("secret", line[a:b], (a, b))
    for s in ASSIGNED_SECRET.finditer(line):
        value = s.group(2) if s.group(2) is not None else s.group(3)
        if len(value) < 8 and not _SHORT_OK.match(s.group(0)):
            continue
        if value.startswith("`") and line[:s.start()].rstrip("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-").endswith("`"):
            continue                  # prose: the name itself is the code span, `password=`-style
        if s.group(0).lower().startswith("pwd") and value.startswith(("/", "~/", "./", "../", "$")):
            continue
        if _BARE_WORD.match(s.group(0)) and not _prefixed(line, s.start()) and not _CREDENTIAL_SHAPED.search(value):
            continue                  # `PASS: done`, `second pass: read it`, `pwd=subdir`
        if suffix in _NAMES_ARE_BARE and s.group(2) is None and _BARE_NAME.fullmatch(value):
            continue                  # `password = options.password`
        if _KEY_NAME.match(s.group(0)) and _not_key_material(s.group(0), value, s.group(2) is not None):
            continue
        # a passphrase may hold spaces; under any other name a quoted phrase is prose or a label
        if s.group(2) is not None and re.search(r"\s", value) and not (
                s.group(0).lower().startswith("pass") and re.fullmatch(r"[\w .,!?@#$%&*-]+", value)):
            continue                  # code between two quotes is not a value: "password=" + word) == {"x"}
        if s.group(2) is None:
            if suffix in _SHELL_SUFFIXES:
                if value.startswith(("$", "`")):
                    continue              # an expansion, not a literal
            elif (suffix in _CODE_SUFFIXES and suffix not in _NAMES_ARE_BARE) or _CALL.match(value):
                continue                  # a name or a call, not a literal
        if not _PLACEHOLDER.match(value):
            hit("secret", value, s.span(2) if s.group(2) is not None else s.span(3))
    d = _DEFINE.match(line)
    if d and not _PLACEHOLDER.match(d.group(2)) and (
            re.search(r"(?i)passw(?:or)?d|passphrase", d.group(1))
            or (len(d.group(2)) >= 8 and _CREDENTIAL_SHAPED.search(d.group(2)))):
        hit("secret", d.group(2), d.span(2))
    for ip in _private_ips(line):
        hit("private-ip", ip)
    for s in HOME_PATH.finditer(line):
        u = _HOME_USER.search(s.group(0))
        if u and (u.group(1).lower() in _PLACEHOLDER_USERS or u.group(1)[:1] in "_$<{%"):
            continue
        hit("home-path", s.group(0))
    for s in EMAIL.finditer(line):
        if not _OK_EMAIL.search(s.group(0)):
            hit("email", s.group(0), s.span())
    for s in SESSION_URL.finditer(line):
        hit("session-url", s.group(0))
    if terms._block:
        for s in terms._block.finditer(line):
            hit("denylist", s.group(0))
    if terms._review:
        for s in terms._review.finditer(line):
            hit("review-term", s.group(0))
    if terms._glued:
        bounded = {m.span() for r in (terms._block, terms._review) if r for m in r.finditer(line)}
        for s in terms._glued.finditer(line):
            if s.span() in bounded:
                continue                  # already reported above, as block or review
            tok = _glued_token(line, s)
            if tok:
                # a glued BLOCK name is only reported as a review finding because glued matches
                # are less sure; an inline marker in the file must still not clear it
                is_block = bool(terms._glued_block and terms._glued_block.fullmatch(s.group(0)))
                hit("review-term", tok, excusable=not is_block)
    if terms.internal_id is not None:
        for s in terms.internal_id.finditer(line):
            hit("internal-id", s.group(0))
    if suffix in _MARKDOWN:
        for s in WIKILINK.finditer(line):
            hit("wikilink", s.group(0))
    # A hit that overlaps a secret (`user:PASSWORD@host` also reads as an address) would print
    # part of it: whatever its class, such an excerpt is not shown.
    found = []
    for cls, text, span in raw:
        if cls not in MASKED and span and any(span[0] < b and a < span[1] for a, b in secret_spans):
            found.append((cls, f"<{cls}: {len(text)} chars, overlaps a secret, not shown>"))
        else:
            found.append((cls, mask(cls, text)))
    return found
