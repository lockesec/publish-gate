"""SARIF 2.1.0 output, for code-scanning dashboards and CI annotations.

One rule per leak class; a block finding is level `error`, a review finding `warning`. A
finding in a file carries its path and line; one in a commit message, author or committer
carries the commit as a logical location (there is no file to point at), and a history
finding names its commit in `properties.commit`. The secret's text is never included: the
message carries the same masked excerpt as the text output.

A run that could not look (NOT EVALUABLE) is written as a FAILED invocation
(`executionSuccessful: false`) with the reason as a notification and no results, so a
dashboard that counts results cannot read it as zero findings.
"""
from __future__ import annotations

from . import __version__
from .classes import BLOCK, SEVERITY

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/lockesec/publish-gate"

DESCRIPTIONS = {
    "secret": "A private key, access token or assigned credential",
    "private-ip": "A private (RFC 1918, link-local or carrier-grade NAT) address",
    "home-path": "A home directory, agent scratch root or agent project slug naming a user",
    "email": "An email address that is not a noreply or reserved example address",
    "session-url": "A link to a private AI-agent or chat session",
    "denylist": "A private name from your denylist",
    "env-file": "A committed .env file",
    "agent-state": "Agent memory or state: memory files, local settings, transcripts, databases",
    "synthetic-data": "Agent-state files in a folder declared synthetic (review)",
    "review-term": "A name marked review: in your denylist",
    "internal-id": "An internal ticket id matching --internal-id",
    "wikilink": "An Obsidian double-bracket link",
}


def _rules() -> list:
    return [{"id": cls, "name": cls.replace("-", " ").title().replace(" ", ""),
             "shortDescription": {"text": DESCRIPTIONS.get(cls, cls)},
             "defaultConfiguration": {"level": "error" if sev == BLOCK else "warning"}}
            for cls, sev in sorted(SEVERITY.items())]


def _result(f) -> dict:
    r = {"ruleId": f.cls, "level": "error" if f.severity == BLOCK else "warning",
         "message": {"text": f"{f.cls}: {f.shown} ({f.where})"}}
    if f.path:
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.path}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        r["locations"] = [loc]
    elif f.commit:
        r["locations"] = [{"logicalLocations": [{"name": f.commit, "kind": "commit"}]}]
    if f.commit:
        r["properties"] = {"commit": f.commit}
    return r


def document(findings: list, ok: bool, reason: str = "", summary: dict | None = None) -> dict:
    invocation = {"executionSuccessful": ok}
    if not ok:
        invocation["toolExecutionNotifications"] = [
            {"level": "error", "message": {"text": f"NOT EVALUABLE: {reason}. This is not a pass."}}]
    run = {"tool": {"driver": {"name": "publish-gate", "version": __version__,
                               "informationUri": INFO_URI, "rules": _rules()}},
           "invocations": [invocation],
           "results": [_result(f) for f in findings] if ok else []}
    if summary:
        run["properties"] = summary
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
