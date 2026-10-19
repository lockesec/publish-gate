"""The leak classes, judged one line at a time.

BLOCK classes fail the gate; REVIEW classes fail it unless a person accepts them
(`--accept-review`). Every pattern is a single pass over the line with bounded repetition.
"""
from __future__ import annotations

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
    re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                       # AWS access key id
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),            # Slack
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),                 # Anthropic
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),           # OpenAI-style
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),                   # Google API key
    re.compile(r"\bhvs\.[A-Za-z0-9_-]{20,}\b"),                 # Vault service token
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
ASSIGNED_SECRET = re.compile(
    r"(?i)(?:\b|(?<=_))(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|token|passwd|"
    r"password|client[_-]?secret)\b[\"']?\s*[:=]\s*(?:([\"'])([^\s\"']{8,})[\"']|([^\s\"'#,;]{8,}))")
_PLACEHOLDER = re.compile(r"(?i)^(?:\$\{?|<|\{|%|x{6,}|\*{4,}|changeme|example|placeholder|your[_-]|"
                          r"redacted|dummy|test|none|null|true|false|os\.environ|getenv)")
#: In source code a secret is a quoted literal; an unquoted value there is a name or a call
#: (`password = get_secret()`). In config and env files an unquoted value is the value.
_CALL = re.compile(r"^[A-Za-z_][\w.]*\(")
_CODE_SUFFIXES = frozenset({".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go",
                            ".rs", ".rb", ".java", ".kt", ".cs", ".php", ".sh", ".bash", ".zsh"})

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
_OK_EMAIL = re.compile(r"(?i)^noreply@github\.com$|@(?:users\.noreply\.github\.com|(?:[\w-]+\.)*example\.(?:com|org|net)|"
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
# an address written with a range prefix (/0 to /31) is a network (firewall docs, this table);
# /32, a URL path or a port after it is a host
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
                   r"(?![\d.]|/(?:[12]?\d|3[01])(?!\d))")
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


GLUED_MIN = 4


def _terms_re(terms, bounded=True):
    terms = [t for t in terms if t.strip()]
    if not terms:
        return None
    # words may be joined by any run of white space, hyphens, underscores or dots, so a term
    # is found in a file name or slug as well as in prose
    # glued, the words may also touch (`acmeindustrial.com`)
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
    `acmecorp.com`), or None. A name standing alone is the bounded patterns' finding; one
    starting mid-word (`acme` in `pacmerge`) is almost never the name."""
    a, b = s.start(), s.end()
    if a > 0 and _ALNUM.match(line[a - 1]):
        return None
    if b >= len(line) or not _ALNUM.match(line[b]):
        return None
    return line[a:b + len(_TOKEN.match(line, b).group(0))]


def mask(cls: str, text: str) -> str:
    if cls in MASKED:
        return f"<{cls}: {len(text)} chars, not shown>"
    t = text.strip()
    return t if len(t) <= 80 else t[:77] + "..."


def _private_ips(line: str) -> list:
    out = []
    for m in _IPV4.finditer(line):
        if any(int(g) > 255 for g in m.groups()):
            continue
        ip = ipaddress.IPv4Address(m.group(0))
        if any(ip in n for n in _PRIVATE_NETS):
            out.append(m.group(0))
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
    found = []

    def hit(cls, text):
        if cls in allowed:
            if excused is not None:
                excused.append(cls)
        else:
            found.append((cls, mask(cls, text)))

    for p in SECRET_PATTERNS:
        for s in p.finditer(line):
            hit("secret", s.group(0))
    for s in ASSIGNED_SECRET.finditer(line):
        value = s.group(2) if s.group(2) is not None else s.group(3)
        if s.group(2) is None and (suffix in _CODE_SUFFIXES or _CALL.match(value)):
            continue                      # a name or a call, not a literal
        if not _PLACEHOLDER.match(value):
            hit("secret", value)
    for ip in _private_ips(line):
        hit("private-ip", ip)
    for s in HOME_PATH.finditer(line):
        u = _HOME_USER.search(s.group(0))
        if u and (u.group(1).lower() in _PLACEHOLDER_USERS or u.group(1)[:1] in "_$<{%"):
            continue
        hit("home-path", s.group(0))
    for s in EMAIL.finditer(line):
        if not _OK_EMAIL.search(s.group(0)):
            hit("email", s.group(0))
    for s in SESSION_URL.finditer(line):
        hit("session-url", s.group(0))
    if terms._block:
        for s in terms._block.finditer(line):
            hit("denylist", s.group(0))
    if terms._review:
        for s in terms._review.finditer(line):
            hit("review-term", s.group(0))
    if terms._glued:
        for s in terms._glued.finditer(line):
            tok = _glued_token(line, s)
            if tok:
                hit("review-term", tok)
    if terms.internal_id is not None:
        for s in terms.internal_id.finditer(line):
            hit("internal-id", s.group(0))
    if suffix in _MARKDOWN:
        for s in WIKILINK.finditer(line):
            hit("wikilink", s.group(0))
    return found
