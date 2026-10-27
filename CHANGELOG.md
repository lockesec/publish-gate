# Changelog

## 0.1.0 (2026-10-19)

First public release. What it does:

- **Finds leaks in twelve classes:** secrets, private IP addresses, home paths and agent scratch
  paths, email addresses, AI-session links, your own private names (a denylist), committed `.env`
  files, agent state (memory, transcripts, local settings, databases), synthetic data, review
  names, internal ticket ids and Obsidian wikilinks. The last four are review findings that
  need a person's eye; the rest block. A denylist name that starts a longer token (a domain,
  host or account name such as `ACMECORP\svc`) is a review finding, so a glued name is not missed.
- **Reads what git would publish.** In a git work tree it scans tracked files plus untracked ones
  that are not ignored. Elsewhere it scans every file. It also judges file names and symlink
  targets, and reads UTF-16 text.
- **Reads the history.** `--history` reads every commit's tree, message, author and committer,
  and every annotated tag's name, tagger and message. A finding is reported at the commit
  that introduced it.
- **Judges what a push sends to THIS destination.** The pre-push hook excludes only commits
  the destination's own remote-tracking refs already hold; a commit another remote has (a
  private mirror) is judged again, and a push to a bare URL judges everything it sends.
- **Never prints a secret,** including through a location: a file named after a token is
  reported with the token replaced by its length in text, JSON and SARIF.
- **Proves it can see on every run.** One planted leak per class must be found before a scan
  counts. A class that goes unseen makes the run NOT EVALUABLE (exit 2).
- **Says NOT EVALUABLE instead of guessing.** No denylist, a denylist inside the tree, a dirty
  tree in `--history` mode, an unreadable file or folder, a failed git call or an oversized text
  file all stop the run with the cause named.
- **Excuses only what is safe to excuse.** `.publish-gate-allow`, `--allow-term` and an inline
  `publish-gate: allow=<class>` comment can excuse review terms and sample values. None of them
  can excuse a secret or a denylisted name, and the summary counts every excused hit.
- **Fits a push and CI.** `--history --range REVS` and `examples/pre-push` judge only what a push
  sends. `--format sarif` (validated against the SARIF 2.1.0 schema) and `--format json` report
  NOT EVALUABLE as a failed run with the reason.

The hardening history, including the gaps an outside review found and the real run that found a
leaked scratch path in a requirements file, is in [DESIGN.md](DESIGN.md#adversarial-review).
