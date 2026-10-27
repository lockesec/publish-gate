"""Scanning a tree or a git history.

Tree mode reads the working tree (``.git`` excluded). History mode reads every blob of every
commit reachable from any ref, and every commit message, because a leak deleted in a later
commit is still published with the history. Each blob is read once however many commits hold it.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .classes import BLOCK, MASKED, REVIEW, SEVERITY, Terms, redact, scan_line

MAX_BYTES = 2_000_000

#: Files that are agent or tool STATE rather than code: memory, transcripts, local settings,
#: databases and serialized objects. They leak the person, not the project.
_STATE_NAMES = re.compile(r"(?i)^(?:MEMORY\.md|CLAUDE\.local\.md|settings\.local\.json|"
                          r"session-state[\w.-]*|\.claude\.json)$")
_STATE_EXT = frozenset({".db", ".sqlite", ".sqlite3", ".duckdb", ".parquet", ".pkl", ".pickle"})
_STATE_DIRS = frozenset({".claude-mem", "claude-mem"})
_ENV = re.compile(r"^\.env(?:\..+)?$")
_ENV_OK = frozenset({".env.example", ".env.sample", ".env.template", ".env.dist"})
SYNTHETIC_MARKER = "SYNTHETIC-DATA"
SYNTHETIC_DECL = "synthetic: true"


class NotEvaluable(Exception):
    """The gate could not look; a verdict would be a guess."""


@dataclass
class Finding:
    cls: str
    where: str
    shown: str
    path: "str | None" = None       # structured location, for SARIF and JSON
    line: "int | None" = None
    commit: "str | None" = None

    def __post_init__(self):
        # every location and excerpt is display-only: a secret in a file name must not print
        self.where, self.path = redact(self.where), redact(self.path)
        if self.cls not in MASKED:
            self.shown = redact(self.shown)

    @property
    def severity(self) -> str:
        return SEVERITY.get(self.cls, BLOCK)


@dataclass
class Result:
    findings: list = field(default_factory=list)
    scanned: int = 0
    unscanned: int = 0
    commits: int = 0
    tags: int = 0            # annotated tag objects judged (their tagger, name and message)
    excused: int = 0         # hits cleared by an inline allow marker (counted, never hidden)
    scope: str = ""          # "git": what git would publish; "walk": every file; "history"


def verdict(res: Result, accept_review: bool = False) -> int:
    """0 clean, 1 findings (REVIEW findings count unless accepted)."""
    for f in res.findings:
        if f.severity == BLOCK or not accept_review:
            return 1
    return 0


def _is_state(rel: PurePosixPath) -> bool:
    parts = rel.parts
    if any(p in _STATE_DIRS for p in parts):
        return True
    if _STATE_NAMES.match(rel.name) or rel.suffix.lower() in _STATE_EXT:
        return True
    # agent session transcripts: .jsonl under a .claude/projects tree
    return rel.suffix == ".jsonl" and ".claude" in parts and "projects" in parts


def _file_class(rel: PurePosixPath, synthetic_dirs: set) -> "str | None":
    if _ENV.match(rel.name) and rel.name not in _ENV_OK:
        return "env-file"
    if _is_state(rel):
        if any(str(rel).startswith(d + "/") for d in synthetic_dirs):
            return "synthetic-data"
        return "agent-state"
    return None


def _declares_synthetic(text: str) -> bool:
    first = text.lstrip().splitlines()[0].strip().lower() if text.strip() else ""
    return first == SYNTHETIC_DECL


_BOMS = ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))


def _text(data: bytes) -> "str | None":
    """The text of a file, or None for a binary one. UTF-16 with a byte-order mark (Windows
    PowerShell and .reg files) is text, although it is full of NUL bytes."""
    for bom, enc in _BOMS:
        if data.startswith(bom):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                break
    head = data[:8192]
    if b"\x00" in head:
        # UTF-16 without a mark: ASCII text puts a NUL in every second byte and nowhere else
        for enc, nul_at in (("utf-16-le", 1), ("utf-16-be", 0)):
            pairs = len(head) // 2
            if pairs >= 4 and head[nul_at::2].count(0) >= 0.9 * pairs \
                    and head[1 - nul_at::2].count(0) == 0:
                try:
                    return data[:len(data) // 2 * 2].decode(enc)
                except UnicodeDecodeError:
                    return None
        return None
    return data.decode("utf-8", errors="replace")


def shown_path(rel: str) -> str:
    """A path for display: a file name that is not valid UTF-8 keeps its place, with the bad
    bytes replaced, so printing never fails."""
    return rel.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _scan_text(where_prefix: str, text: str, terms: Terms, suffix: str, res: Result,
               path: "str | None" = None, commit: "str | None" = None) -> None:
    excused: list = []
    for i, line in enumerate(text.splitlines(), 1):
        # one value matched by two patterns (a token that is also an assigned value) is one leak
        for cls, shown in dict.fromkeys(scan_line(line, terms, suffix, excused)):
            res.findings.append(Finding(cls, f"{where_prefix}:{i}", shown, path, i, commit))
    res.excused += len(excused)


def _judge_blob(rel: str, data: bytes, terms: Terms, synthetic_dirs: set, res: Result,
                max_bytes: int, where: "str | None" = None, link: bool = False,
                commit: "str | None" = None) -> None:
    rel = shown_path(rel)
    p = PurePosixPath(rel)
    label = where or rel
    fc = _file_class(p, synthetic_dirs)
    if fc:
        res.findings.append(Finding(fc, label, rel, rel, None, commit))
    for cls, shown in scan_line(rel, terms, ".path"):     # the path itself can leak
        res.findings.append(Finding(cls, f"{label} (file name)", shown, rel, None, commit))
    if link:
        # git publishes a symlink as its target path: judge that string
        res.scanned += 1
        _scan_text(f"{label} (symlink target)", data.decode("utf-8", errors="replace"), terms,
                   ".path", res, rel, commit)
        return
    text = _text(data)
    if text is None:
        res.unscanned += 1
        return
    if len(data) > max_bytes:
        raise NotEvaluable(f"{label} is {len(data)} bytes, over --max-bytes {max_bytes}: an "
                           "unscanned text file is not a clean one")
    res.scanned += 1
    _scan_text(label, text, terms, p.suffix.lower(), res, rel, commit)


def _git_files(root: Path) -> "list | None":
    """What git would publish from this work tree: tracked files plus untracked ones that are
    not ignored. None when ``root`` is not the top of a git work tree."""
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root.resolve():
        return None
    out = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    # os.fsdecode keeps a file name that is not valid UTF-8 openable (surrogateescape)
    files = []
    for p in sorted({os.fsdecode(b) for b in out.split(b"\0") if b}):
        # lstat, not Path.is_file()/exists(): those return False on a permission error (Python
        # 3.14 does), which read an unreadable file as "deleted" and gave a CLEAN verdict
        try:
            st = os.lstat(root / p)
        except FileNotFoundError:
            continue                      # deleted from the work tree, not yet committed
        except OSError as e:
            raise NotEvaluable(f"cannot read {shown_path(p)}: {e.strerror or e}") from e
        if stat.S_ISLNK(st.st_mode) or stat.S_ISREG(st.st_mode):
            files.append(p)
        else:
            raise NotEvaluable(f"{shown_path(p)} is listed by git but is not a regular file")
    return files


def scan_tree(root: Path, terms: Terms, max_bytes: int = MAX_BYTES) -> Result:
    """In a git work tree, what git would publish (tracked plus untracked files that are not
    ignored); elsewhere, every file (``.git`` excluded)."""
    root = Path(root)
    res = Result()
    files = _git_files(root)
    if files is not None:
        res.scope = "git"
    else:
        res.scope = "walk"
        files = []

        def unreadable(e: OSError) -> None:
            raise NotEvaluable(f"cannot read {e.filename}: {e.strerror or e}")

        for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable):
            dirnames[:] = sorted(d for d in dirnames if d != ".git")
            # a symlink to a directory is listed with the directories and never descended
            links = [d for d in dirnames if (Path(dirpath) / d).is_symlink()]
            for name in sorted(filenames + links):
                full = Path(dirpath) / name
                try:
                    st = os.lstat(full)
                except OSError as e:
                    raise NotEvaluable(f"cannot read {shown_path(str(full))}: {e.strerror or e}") from e
                if not (stat.S_ISLNK(st.st_mode) or stat.S_ISREG(st.st_mode)):
                    continue
                files.append(full.relative_to(root).as_posix())
    synthetic = {str(PurePosixPath(r).parent) for r in files
                 if PurePosixPath(r).name == SYNTHETIC_MARKER
                 and _declares_synthetic((root / r).read_text(encoding="utf-8", errors="replace"))}
    for rel in files:
        full = root / rel
        try:
            link = full.is_symlink()
            data = os.fsencode(os.readlink(full)) if link else full.read_bytes()
        except OSError as e:
            raise NotEvaluable(f"cannot read {shown_path(rel)}: {e.strerror or e}") from e
        _judge_blob(rel, data, terms, synthetic, res, max_bytes, link=link)
    return res


def _git(root: Path, *args: str) -> bytes:
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise NotEvaluable(f"git could not run ({e.__class__.__name__})") from e
    if r.returncode != 0:
        raise NotEvaluable(f"git {' '.join(args[:2])} failed: "
                           f"{r.stderr.decode(errors='replace').strip()[:200]}")
    return r.stdout


def _tree(root: Path, c: str) -> list:
    """(path, blob sha, is symlink) for every file in commit ``c``."""
    entries = []
    for item in _git(root, "ls-tree", "-r", "-z", c).split(b"\0"):
        if not item:
            continue
        meta, _, path = item.partition(b"\t")
        mode, kind, sha = meta.decode().split()
        if kind == "blob":
            entries.append((path.decode("utf-8", errors="replace"), sha, mode.startswith("120")))
    return entries


def _changed(root: Path, c: str) -> list:
    """(path, blob sha, is symlink) for every file commit ``c`` adds or changes against each
    parent (``--root``: a first commit adds everything). This is what a push of ``c`` sends;
    a file already published unchanged is not judged again."""
    out = _git(root, "diff-tree", "-r", "-z", "-m", "--no-commit-id", "--root", c).split(b"\0")
    entries, i = [], 0
    while i < len(out) - 1:
        meta = out[i].decode()
        if not meta.startswith(":"):
            i += 1
            continue
        _om, nm, _os, nsha, status = meta[1:].split()
        path = out[i + 1].decode("utf-8", errors="replace")
        i += 2
        if status.startswith("D") or nm.startswith("160"):   # deleted, or a submodule
            continue
        entries.append((path, nsha, nm.startswith("120")))
    return list(dict.fromkeys(entries))


def scan_history(root: Path, terms: Terms, max_bytes: int = MAX_BYTES,
                 rev_range: "list | None" = None) -> Result:
    """Every commit reachable from any ref: its message, author, committer and every blob in
    its tree. A dirty working tree is refused (what is about to be committed would not be
    judged). With ``rev_range`` (``rev-list`` arguments, e.g. ``["A..B"]`` or
    ``["B", "--not", "--remotes"]``) only those commits are judged: what one push sends. The
    work tree is then irrelevant, and an empty range is a push of no new commits."""
    root = Path(root)
    if rev_range is None and _git(root, "status", "--porcelain").strip():
        raise NotEvaluable("the working tree has uncommitted changes; commit or stash them, "
                           "then judge the history")
    for arg in rev_range or []:
        if arg.startswith("-") and arg not in ("--not", "--remotes", "--branches", "--all") \
                and not re.fullmatch(r"--remotes=[\w.-]+", arg):
            raise NotEvaluable(f"--range accepts revisions, ranges and --not/--remotes[=NAME]/"
                               f"--branches/--all, not {arg!r}")
    try:
        # oldest first, so a leak is reported at the commit that introduced it
        commits = _git(root, "rev-list", "--reverse",
                       *(rev_range or ["--all"])).decode().split()
    except NotEvaluable as e:
        raise NotEvaluable(f"no commits to judge ({e})") from e
    if not commits and rev_range is None:
        raise NotEvaluable("no commits to judge")
    res = Result(commits=len(commits), scope="range" if rev_range else "history")
    seen: set = set()
    for c in commits:
        who, _, msg = _git(root, "log", "-1", "--format=%an <%ae>%n%cn <%ce>%x00%B",
                           c).decode("utf-8", errors="replace").partition("\0")
        author, _, committer = who.partition("\n")
        # the author and committer lines are published with the history too
        _scan_text(f"commit {c[:12]} author", author, terms, ".msg", res, commit=c)
        _scan_text(f"commit {c[:12]} committer", committer, terms, ".msg", res, commit=c)
        _scan_text(f"commit {c[:12]} message", msg, terms, ".msg", res, commit=c)
        entries = _changed(root, c) if rev_range else _tree(root, c)
        synthetic = set()
        for path, sha, _link in entries:
            if PurePosixPath(path).name == SYNTHETIC_MARKER:
                if _declares_synthetic(_git(root, "cat-file", "blob", sha).decode(errors="replace")):
                    synthetic.add(str(PurePosixPath(path).parent))
        for path, sha, link in entries:
            key = (path, sha)
            if key in seen:
                continue
            seen.add(key)
            data = _git(root, "cat-file", "blob", sha)
            _judge_blob(path, data, terms, synthetic, res, max_bytes,
                        where=f"{path} @ {c[:12]}", link=link, commit=c)
    # Annotated tags are published objects too: their tagger line, name and message travel with
    # a pushed tag (outside review 2026-10-19: a token in a release-tag message read CLEAN).
    for tag in _tag_objects(root, rev_range):
        body = _git(root, "cat-file", "tag", tag).decode("utf-8", errors="replace")
        head, _, msg = body.partition("\n\n")
        fields = dict(ln.split(" ", 1) for ln in head.splitlines() if " " in ln)
        name = fields.get("tag", tag[:12])
        tagger = re.sub(r"\s+\d+\s+[+-]\d{4}$", "", fields.get("tagger", ""))
        _scan_text(f"tag {name} tagger", tagger, terms, ".msg", res, commit=tag)
        _scan_text(f"tag {name} name", name, terms, ".msg", res, commit=tag)
        _scan_text(f"tag {name} message", msg, terms, ".msg", res, commit=tag)
        res.tags += 1
    return res


def _tag_objects(root: Path, rev_range: "list | None") -> list[str]:
    """Annotated tag objects to judge: every one under refs/tags for the whole history, or the
    ones a ranged scan names (a pushed tag arrives as its tag object's sha). Nested tags (a tag
    of a tag) are followed. Lightweight tags are refs, not objects: nothing to read."""
    if rev_range is None:
        starts = _git(root, "for-each-ref", "--format=%(objectname)", "refs/tags").decode().split()
    else:
        starts = [part for arg in rev_range if not arg.startswith("-")
                  for part in re.split(r"\.\.\.?", arg) if part]
    out, seen = [], set()
    for sha in starts:
        while sha and sha not in seen:
            try:
                kind = _git(root, "cat-file", "-t", sha).decode().strip()
            except NotEvaluable:
                break                    # not an object this repo holds (rev-list judged the range)
            if kind != "tag":
                break
            seen.add(sha)
            out.append(sha)
            target = _git(root, "cat-file", "tag", sha).decode(errors="replace").split("\n", 1)[0]
            sha = target.split(" ", 1)[1].strip() if target.startswith("object ") else ""
    return out
