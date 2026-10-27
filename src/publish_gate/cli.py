"""publish-gate: check a repository for leaks before you make it public, and prove it can see.

    publish-gate PATH                     scan the working tree
    publish-gate PATH --history           scan every commit and commit message
    publish-gate PATH --history --range R scan only the commits in R (a pre-push hook)
    publish-gate --self-test              plant one leak per class and check each is seen

Exit codes: 0 clean, 1 findings, 2 NOT EVALUABLE (it could not look; never a pass), 64 usage.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import sys
from pathlib import Path

from . import __version__, sarif, scan, selftest
from .classes import BLOCK, Terms, redact

EXIT_CLEAN, EXIT_FINDINGS, EXIT_NOT_EVALUABLE, EXIT_USAGE = 0, 1, 2, 64
DEFAULT_DENYLIST = Path("~/.config/publish-gate/denylist")


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="publish-gate", description=__doc__.split("\n\n")[0],
        epilog="exit codes: 0 clean, 1 findings, 2 NOT EVALUABLE (it could not look), "
               "64 usage error")
    ap.add_argument("path", nargs="?", type=Path, help="the repository or tree to judge")
    ap.add_argument("--history", action="store_true",
                    help="judge every commit's tree and message (use before the first push)")
    ap.add_argument("--denylist", type=Path, default=None,
                    help="private names, one per line (`review: term` for review-only); default "
                         "$PUBLISH_GATE_DENYLIST, else ~/.config/publish-gate/denylist. Keep it "
                         "OUTSIDE the repository")
    ap.add_argument("--no-denylist", action="store_true",
                    help="run without private names (otherwise a missing denylist is NOT EVALUABLE)")
    ap.add_argument("--internal-id", default=None, metavar="REGEX",
                    help="a pattern for internal ticket ids, reported for review (e.g. 'PROJ-\\d+')")
    ap.add_argument("--allow-term", action="append", default=[], metavar="TERM",
                    help="a review term that is legitimate in this repository (e.g. its own name); "
                         "also read from <path>/.publish-gate-allow, one per line. Block terms "
                         "are never excused this way")
    ap.add_argument("--accept-review", action="store_true",
                    help="review findings (names, ids, wikilinks, synthetic data) do not fail the gate")
    ap.add_argument("--max-bytes", type=int, default=scan.MAX_BYTES,
                    help="largest text file to read, in bytes; a bigger one makes the run "
                         "NOT EVALUABLE (default %(default)s)")
    ap.add_argument("--range", default=None, metavar="REVS",
                    help="with --history: judge only these commits, as `git rev-list` takes them "
                         "('A..B', or 'SHA --not --remotes' for a new branch); what one push sends")
    ap.add_argument("--format", choices=("text", "json", "sarif"), default="text",
                    help="sarif: SARIF 2.1.0 for code-scanning tools (block = error, review = "
                         "warning); NOT EVALUABLE is a failed run, never an empty one")
    ap.add_argument("--json", action="store_true", help="the same as --format json")
    ap.add_argument("--self-test", action="store_true", help="run only the negative control")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def load_denylist(path: Path) -> tuple:
    block, review = [], []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower().startswith("review:"):
            review.append(line[7:].strip())
        else:
            block.append(line[6:].strip() if line.lower().startswith("block:") else line)
    return [b for b in block if b], [r for r in review if r]


ALLOW_FILE = ".publish-gate-allow"


def _allowed_terms(a, terms: Terms) -> tuple:
    """(review terms to drop, block terms the allow list tried to excuse). The allow file lives
    in the scanned tree, so it may excuse only REVIEW terms: content must not be able to clear
    a block-class finding about itself."""
    asked = [t.strip() for t in a.allow_term]
    f = a.path / ALLOW_FILE
    if f.is_file():
        asked += [ln.split("#", 1)[0].strip() for ln in f.read_text(encoding="utf-8").splitlines()]
    asked = {t.lower() for t in asked if t}
    refused = sorted(t for t in asked if t in {b.lower() for b in terms.block})
    for t in refused:
        print(f"note: '{t}' is a block term; an allow list cannot excuse it", file=sys.stderr)
    return asked - set(refused), refused


def _inside(child: Path, parent: Path) -> bool:
    c, p = child.resolve(), parent.resolve()
    return c == p or p in c.parents


def _denylist_path(a) -> Path:
    path = a.denylist or (Path(os.environ["PUBLISH_GATE_DENYLIST"])
                          if os.environ.get("PUBLISH_GATE_DENYLIST") else DEFAULT_DENYLIST)
    return path.expanduser()


def _terms(a) -> tuple:
    """(Terms, note). The machine's hostname is always a block term."""
    path = _denylist_path(a)
    block, review, note = [], [], ""
    if a.no_denylist:
        note = "denylist: not used (--no-denylist)"
    elif not path.is_file():
        raise scan.NotEvaluable(f"no denylist at {path}: private names cannot be checked. Write "
                                "one (one name per line, outside the repository) or pass "
                                "--no-denylist")
    else:
        try:
            block, review = load_denylist(path)
        except (OSError, UnicodeDecodeError) as e:
            raise scan.NotEvaluable(f"denylist {path} could not be read ({e.__class__.__name__})") from e
        if not block and not review:
            raise scan.NotEvaluable(f"denylist {path} holds no names")
        note = f"denylist: {len(block)} block, {len(review)} review term(s) from {path}"
    host = socket.gethostname().split(".")[0]
    if len(host) >= 4 and host.lower() not in ("localhost", "ubuntu", "debian", "fedora"):
        block.append(host)
    try:
        idp = re.compile(a.internal_id) if a.internal_id else None
    except re.error as e:
        raise ValueError(f"--internal-id is not a valid pattern: {e}") from e
    return Terms(block, review, idp), note


def main(argv=None) -> int:
    try:
        a = _parser().parse_args(argv)
    except SystemExit as e:
        return EXIT_CLEAN if e.code in (0, None) else EXIT_USAGE
    if not a.self_test and a.path is None:
        print("publish-gate: error: give a PATH, or --self-test", file=sys.stderr)
        return EXIT_USAGE
    if a.json:
        a.format = "json"
    if a.range is not None and not a.history:
        print("publish-gate: error: --range needs --history", file=sys.stderr)
        return EXIT_USAGE
    try:
        terms, note = _terms(a)
        st = selftest.run(terms, history=a.history, ranged=a.range is not None)
        if a.self_test:
            print(f"self-test: all {st['classes']} classes seen"
                  + (" (history mode)" if a.history else ""))
            return EXIT_CLEAN
        if not a.path.is_dir():
            raise scan.NotEvaluable(f"{a.path} is not a directory")
        dl = _denylist_path(a)
        if not a.no_denylist and _inside(dl, a.path):
            raise scan.NotEvaluable(f"the denylist {dl} is inside the tree being published, so "
                                    "the private names it lists would be published with it; "
                                    "keep it outside the repository")
        allow, refused = _allowed_terms(a, terms)
        if allow:
            terms = Terms(terms.block, [t for t in terms.review if t.lower() not in allow],
                          terms.internal_id)
        rng = shlex.split(a.range) if a.range is not None else None
        res = (scan.scan_history(a.path, terms, a.max_bytes, rng) if a.history
               else scan.scan_tree(a.path, terms, a.max_bytes))
    except ValueError as e:
        print(f"publish-gate: error: {e}", file=sys.stderr)
        return EXIT_USAGE
    except scan.NotEvaluable as e:
        why = redact(str(e))                  # a NOT EVALUABLE reason can name a file
        print(f"NOT EVALUABLE: {why}. This is not a pass.", file=sys.stderr)
        if a.format == "json":
            print(json.dumps({"verdict": "not-evaluable", "reason": why}, indent=1))
        elif a.format == "sarif":
            print(json.dumps(sarif.document([], ok=False, reason=why), indent=1))
        return EXIT_NOT_EVALUABLE
    code = scan.verdict(res, a.accept_review)
    blocks = sum(1 for f in res.findings if f.severity == BLOCK)
    reviews = len(res.findings) - blocks
    if a.format == "sarif":
        print(json.dumps(sarif.document(res.findings, ok=True, summary={
            "scanned": res.scanned, "unscanned_binary": res.unscanned, "commits": res.commits,
            "excused_inline": res.excused, "self_test_classes": st["classes"],
            "denylist": note}), indent=1))
        return code
    if a.format == "json":
        print(json.dumps({"verdict": ["clean", "findings"][code], "scanned": res.scanned,
                          "unscanned_binary": res.unscanned, "commits": res.commits,
                          "excused_inline": res.excused,
                          "self_test_classes": st["classes"], "denylist": note,
                          "findings": [{"class": f.cls, "severity": f.severity, "where": f.where,
                                        "shown": f.shown} for f in res.findings]}, indent=1))
        return code
    for f in res.findings:
        print(f"{f.severity.upper():6} {f.cls:14} {f.where}  {f.shown}")
    tags = f"{res.tags} annotated tag(s), " if a.history else ""
    scope = (f"{res.commits} commit(s) in {a.range}, {tags}" if res.scope == "range" else
             f"{res.commits} commit(s), {tags}" if a.history else
             "files git would publish, " if res.scope == "git" else "every file (not a git work tree), ")
    print(f"{'CLEAN' if code == 0 else 'FINDINGS'}: {scope}{res.scanned} text file(s) scanned, "
          f"{res.unscanned} binary file(s) not scanned, {blocks} block and {reviews} review "
          f"finding(s)" + (f", {res.excused} excused by an inline allow marker" if res.excused
                           else "") + f"; self-test: all {st['classes']} classes seen; {note}")
    return code
