"""The negative control: before every scan, plant one known leak per class in a throwaway tree
and scan it with the same code. A class that is not seen makes the run NOT EVALUABLE: a gate
that cannot see its own seeds cannot fail, and a clean verdict from it would be decoration.

The seeds are assembled from fragments at run time, so this file holds no literal secret,
address or path for another scanner (or a push-protection service) to trip over.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from . import scan
from .classes import Terms

SEED_BLOCK = "Zorblax" + " Holdings"      # synthetic names that exist only for the self-test
SEED_REVIEW = "quuxfrob"
SEED_ID = "ZZQ-" + "4242"


def _j(*p: str) -> str:
    return "".join(p)


def seeds() -> dict:
    """{class: (relative path, content)} — one planted leak per class."""
    return {
        "secret": ("seed/secret.txt", _j("token: ghp", "_", "Zq9" * 12, "\n")),
        "private-ip": ("seed/ip.txt", _j("db at 10", ".20.30.40\n")),
        "home-path": ("seed/home.txt", _j("open /ho", "me/seeduser/notes\n")),
        "email": ("seed/email.txt", _j("mail seed.person", "@corp-seed.io\n")),
        "session-url": ("seed/url.txt", _j("https://claude", ".ai/code/session_", "SeedSeed01\n")),
        "denylist": ("seed/name.txt", f"built for {SEED_BLOCK}\n"),
        "review-term": ("seed/review.txt", f"the {SEED_REVIEW} module\n"),
        "internal-id": ("seed/id.txt", f"see {SEED_ID}\n"),
        "wikilink": ("seed/link.md", _j("see [", "[A Private Note]", "]\n")),
        "env-file": ("seed/.env", "X=1\n"),
        "agent-state": ("seed/MEMORY.md", "notes\n"),
        "synthetic-data": ("seed/demo/MEMORY.md", "invented\n"),
    }


SUPPORT = {"seed/demo/" + scan.SYNTHETIC_MARKER: scan.SYNTHETIC_DECL + "\n"}


def seed_terms(terms: Terms) -> Terms:
    """The user's terms plus the synthetic seed terms (and the seed id pattern)."""
    idp = terms.internal_id.pattern if terms.internal_id is not None else None
    combined = re.compile(f"(?:{idp})|{re.escape(SEED_ID)}" if idp else re.escape(SEED_ID))
    return Terms(list(terms.block) + [SEED_BLOCK], list(terms.review) + [SEED_REVIEW], combined)


def _plant(root: Path) -> None:
    for rel, text in list(seeds().values()) + list(SUPPORT.items()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def run(terms: Terms, history: bool = False, ranged: bool = False) -> dict:
    """{"classes": n, "missed": [...]}. Raises scan.NotEvaluable when a seed is missed.
    ``ranged`` seeds through the same path ``--range`` uses (what one commit changes)."""
    t = seed_terms(terms)
    with tempfile.TemporaryDirectory(prefix="publish-gate-selftest-") as d:
        root = Path(d)
        _plant(root)
        if history:
            env = {"GIT_AUTHOR_NAME": "seed", "GIT_AUTHOR_EMAIL": "seed@example.com",
                   "GIT_COMMITTER_NAME": "seed", "GIT_COMMITTER_EMAIL": "seed@example.com",
                   "PATH": "/usr/bin:/bin:/usr/local/bin"}
            for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "seed"],
                         ["rm", "-rq", "seed"], ["commit", "-q", "-m", "remove the seeds"]):
                r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, env=env)
                if r.returncode != 0:
                    raise scan.NotEvaluable("the history self-test could not build its git "
                                            f"repository ({r.stderr.decode(errors='replace')[:120]})")
            # HEAD~1 is the commit that added the seeds; HEAD removed them
            res = (scan.scan_history(root, t, rev_range=["HEAD~1"]) if ranged
                   else scan.scan_history(root, t))
        else:
            res = scan.scan_tree(root, t)
    seen = {f.cls for f in res.findings}
    missed = sorted(set(seeds()) - seen)
    if missed:
        raise scan.NotEvaluable(f"self-test: the gate did not see its own seeded leak(s) for "
                                f"{', '.join(missed)}; a clean verdict would mean nothing")
    return {"classes": len(seeds()), "missed": missed}
