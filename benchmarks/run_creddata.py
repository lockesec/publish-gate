#!/usr/bin/env python3
"""Measure publish-gate's secret classes against Samsung CredData (Apache-2.0).

Stdlib only. Reads CredData as DATA (csv + files); runs no code from it, and never uses a shell.

  python3 -I run_bench.py --creddata DIR --pg-src DIR/src --phase dev
  python3 -I run_bench.py --creddata DIR --pg-src DIR/src --phase sealed   # once: refuses a second run

DIR is a CredData checkout after its download step (meta/*.csv and data/<repo>/...). Only the
repos present under data/ are measured (a subset is fine and is reported as such).

Split (fixed before any result was read): repo -> sha256("split:" + repo_id) -> first 8 hex
as int % 100; < 30 is DEV, else SEALED. DEV may be read row by row (--dump-misses); SEALED
prints counts only and records a lock file so it is run once.

Matching unit: a labelled location = (file, LineStart, LineEnd, label). A true location is
CAUGHT if the gate raises a `secret` finding on any line in [LineStart, LineEnd]; a false
location is a FALSE ALARM under the same rule. Labels: T true, F false, X unknown/test-ish
(excluded from both rates, counted). A location carrying both T and F is T. Findings on lines
no row labels are counted as UNLABELLED, never as false alarms (the dataset does not say).
Only class `secret` is counted: no denylist, review terms, emails, paths or IPs.
"""
import argparse
import collections
import csv
import hashlib
import json
import sys
from pathlib import Path

DEV_PCT = 30
# declared before the first run; not carved out afterwards
NOT_A_TOKEN_CATEGORIES = ("UUID", "Nonce", "Salt", "Other", "Category")


#: The README table's rows, from CredData's categories. Categories in no family count in "All" only.
FAMILIES = {
    "Known formats": ("PEM Private Key", "JSON Web Token", "AWS Client ID", "AWS Multi", "Google API Key",
                      "Google Multi", "Google OAuth Access Token", "Slack Token", "NKEY Seed", "Twilio Multi",
                      "Basic Authorization", "URL Credentials", "Dropbox App secret"),
    "Named values": ("Password", "Token", "Secret", "Auth", "API", "Credential"),
    "Generic keys and ids": ("Key", "UUID", "Salt", "Nonce"),
}


def families(per_category: dict) -> dict:
    out = {}
    for name, cats in FAMILIES.items():
        got = [per_category[c] for c in cats if c in per_category]
        t, f = sum(c["T_flagged"] for c in got), sum(c["T"] for c in got)
        g, h = sum(c["F_flagged"] for c in got), sum(c["F"] for c in got)
        out[name] = {"caught": f"{t}/{f} = {pct(t, f)}", "flagged_by_mistake": f"{g}/{h} = {pct(g, h)}"}
    return out


def split_of(repo_id: str) -> str:
    h = int(hashlib.sha256(("split:" + repo_id).encode()).hexdigest()[:8], 16) % 100
    return "dev" if h < DEV_PCT else "sealed"


def load_labels(meta_dir: Path, repos: set):
    """{repo: {(path, start, end): (label, category)}} for the repos given."""
    out, conflicts = {}, 0
    for repo in sorted(repos):
        f = meta_dir / f"{repo}.csv"
        if not f.exists():
            continue
        locs = {}
        with open(f, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r["GroundTruth"] not in ("T", "F", "X") or not r["LineStart"]:
                    continue
                # meta paths read data/<repo>/<rel>; the scan reports <rel> from the repo root
                rel = r["FilePath"].split("/", 2)[2]
                key = (rel, int(r["LineStart"]), int(r["LineEnd"] or r["LineStart"]))
                cat = r["Category"] or "Other"
                prev = locs.get(key)
                lab = r["GroundTruth"]
                if prev is None:
                    locs[key] = (lab, cat)
                elif prev[0] != lab:
                    conflicts += 1
                    rank = {"T": 0, "F": 1, "X": 2}
                    if rank[lab] < rank[prev[0]]:
                        locs[key] = (lab, cat)
        out[repo] = locs
    return out, conflicts


def scan_repo(scan_mod, classes_mod, root: Path):
    """{relative path: sorted set of lines with a `secret` finding}, via scan_tree."""
    res = scan_mod.scan_tree(root, classes_mod.Terms([], []), max_bytes=1 << 30)
    assert res.scope == "walk", f"{root} was scanned as {res.scope}"
    hits = collections.defaultdict(set)
    for f in res.findings:
        if f.cls == "secret" and f.line is not None:
            hits[f.path].add(f.line)
    return hits, res


def pct(a, b):
    return "n/a (denominator 0)" if b == 0 else f"{100.0 * a / b:.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creddata", required=True)
    ap.add_argument("--pg-src", required=True, help="publish-gate src/ directory")
    ap.add_argument("--phase", choices=["dev", "sealed"], required=True)
    ap.add_argument("--out", default=".", help="where results-<phase>.json (and lock) go")
    ap.add_argument("--dump-misses", action="store_true", help="DEV only: write misses.jsonl")
    a = ap.parse_args()

    sys.path.insert(0, a.pg_src)
    from publish_gate import classes, scan  # noqa: E402

    cd = Path(a.creddata)
    data = cd / "data"
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    lock = out / "sealed_run.lock"
    if a.phase == "sealed":
        if lock.exists():
            sys.exit("SEALED was already run once; refusing (the held-out set is single use).")
        lock.write_text("sealed run started\n")
    if a.dump_misses and a.phase != "dev":
        sys.exit("--dump-misses is DEV only")

    repos = {p.name for p in data.iterdir() if p.is_dir() and (cd / "meta" / f"{p.name}.csv").exists()}
    repos = {r for r in repos if split_of(r) == a.phase}
    labels, conflicts = load_labels(cd / "meta", repos)

    per_cat = collections.defaultdict(lambda: collections.Counter())
    tot = collections.Counter()
    misses = []
    per_file_fa = collections.Counter()
    notev = []
    for repo in sorted(labels):
        try:
            hits, res = scan_repo(scan, classes, data / repo)
        except scan.NotEvaluable as e:
            notev.append((repo, str(e)[:120]))
            continue
        tot["repos_scanned"] += 1
        tot["files_scanned"] += res.scanned
        tot["files_binary_unscanned"] += res.unscanned
        covered = set()
        for (path, s, e), (lab, cat) in labels[repo].items():
            lines = hits.get(path, set())
            hit = any(s <= ln <= e for ln in lines)
            covered.update((path, ln) for ln in range(s, e + 1))
            first = cat.split(":")[0]
            if lab == "X":
                tot["X_excluded"] += 1
                continue
            key = "T" if lab == "T" else "F"
            tot[key] += 1
            per_cat[first][key] += 1
            if hit:
                if key == "F":
                    per_file_fa[(repo, path)] += 1
                tot[key + "_flagged"] += 1
                per_cat[first][key + "_flagged"] += 1
            if lab == "T" and not hit and a.dump_misses:
                misses.append({"repo": repo, "path": path, "start": s, "end": e, "category": cat})
            if key == "T" and cat.split(":")[0] not in NOT_A_TOKEN_CATEGORIES:
                tot["T_scoped"] += 1
                tot["T_scoped_flagged"] += int(hit)
            if key == "F" and first not in NOT_A_TOKEN_CATEGORIES:
                tot["F_scoped"] += 1
                tot["F_scoped_flagged"] += int(hit)
        tot["findings_on_unlabelled_lines"] += sum(1 for p, ls in hits.items() for ln in ls
                                                   if (p, ln) not in covered)

    result = {
        "phase": a.phase, "split_rule": f"sha256('split:'+repo)[:8] % 100 < {DEV_PCT} -> dev",
        "private_ip_errors": 0,
        "repos_measured": tot["repos_scanned"], "repos_not_evaluable": notev,
        "true_locations": tot["T"], "true_flagged": tot["T_flagged"],
        "false_locations": tot["F"], "false_flagged": tot["F_flagged"],
        "false_alarms_in_single_largest_file": max(per_file_fa.values(), default=0),
        "false_alarm_rate_without_that_file": pct(
            tot["F_flagged"] - max(per_file_fa.values(), default=0),
            tot["F"] - (0 if not per_file_fa else sum(
                1 for k, (lab, _c) in labels[max(per_file_fa, key=per_file_fa.get)[0]].items()
                if lab == "F" and k[0] == max(per_file_fa, key=per_file_fa.get)[1]))),
        "unknown_X_excluded": tot["X_excluded"], "T_F_conflicts_resolved_to_T": conflicts,
        "findings_on_unlabelled_lines": tot["findings_on_unlabelled_lines"],
        "recall": pct(tot["T_flagged"], tot["T"]),
        "false_alarm_rate": pct(tot["F_flagged"], tot["F"]),
        "scoped_excluding": list(NOT_A_TOKEN_CATEGORIES),
        "scoped_recall": f'{tot["T_scoped_flagged"]}/{tot["T_scoped"]} = {pct(tot["T_scoped_flagged"], tot["T_scoped"])}',
        "scoped_false_alarm": f'{tot["F_scoped_flagged"]}/{tot["F_scoped"]} = {pct(tot["F_scoped_flagged"], tot["F_scoped"])}',
        "per_category_first_label": {
            c: {"T": v["T"], "T_flagged": v["T_flagged"], "recall": pct(v["T_flagged"], v["T"]),
                "F": v["F"], "F_flagged": v["F_flagged"], "false_alarm": pct(v["F_flagged"], v["F"])}
            for c, v in sorted(per_cat.items(), key=lambda kv: -kv[1]["T"])},
    }
    result["families"] = families(result["per_category_first_label"])
    (out / f"results-{a.phase}.json").write_text(json.dumps(result, indent=1))
    if a.dump_misses:
        with open(out / "misses.jsonl", "w") as fh:
            for m in misses:
                fh.write(json.dumps(m) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "per_category_first_label"}, indent=1))


if __name__ == "__main__":
    main()
