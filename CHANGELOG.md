# Changelog

## Unreleased

- A `SYNTHETIC-DATA` marker that is a symlink is no longer followed: a dangling link no longer crashes the run, a link to a device is not read without limit, and a link to a file outside the tree cannot mark a folder synthetic. Only the first 512 bytes of a marker are read.
- `--history` and the tree scan run git with replace refs off, so a `git replace` can no longer make a leaking commit read as clean.
- An inline `allow=review-term` marker no longer clears a block-list name written glued (`ExampleIndustries`, `acmecorp.com`). Such a name is still a review finding, but only `--accept-review` clears it.
- A password in a URL (`postgres://user:PASSWORD@host`) was printed in clear by the `email` class, because `PASSWORD@host` also reads as an address. Now any finding whose text overlaps a secret is masked, in text, JSON and SARIF.
- A private address that ends a sentence (`at 10.x.y.z.`) is found. A private-key header written with four dashes or a digit in its type (SSH2) is found. A quoted secret in a C `#define` is found.
- A measured catch rate on CredData (`benchmarks/run_creddata.py`).
- A version string such as 1.17.04.3 no longer stops the scan. A zero-padded private address is still found.
- NATS seeds, Grafana tokens, `Authorization: Basic`, passwords of 6 or 7 characters, and `pwd`, `pass` and `secret_key_base` names are found. C, C++, Elixir, Swift and Scala files read an unquoted name as a name.

- Property tests from the docs, run with Hypothesis. It is a test dependency only; nothing is added at
  install.

Fixes found by a verification pass:

- More credential forms are secrets: AWS temporary keys, Stripe, npm, GitLab, Hugging Face and PyPI
  tokens, Slack webhook URLs, `Authorization: Bearer` values, a password in a URL with any host, and
  values named `private_key` or `passphrase`.
- A UTF-8 byte-order mark in the denylist (or `.publish-gate-allow`) no longer disables its first
  term.
- A many-word name written with its words touching (`ZorblaxHoldings`, `zorblaxholdings.com`) is
  now a review finding even when nothing alphanumeric follows it.
- A PGP private key block header is a secret.
- A value that merely starts with a placeholder word (`testing_...`, `nullPointer...`,
  `Exampleton_...`) is no longer treated as a placeholder; only the whole word is.
- A private address with host bits and a prefix (`192.x.y.50/24`, an interface address) is a
  host and blocks; a network address (`192.x.y.0/24`) is still fine.
- UTF-32 text (with a byte-order mark) is decoded as UTF-32, not mis-read as UTF-16.
- A tree with no files to judge (empty, or every file ignored by git) is NOT EVALUABLE, not CLEAN.
- An assigned credential in a file name (a name, an equals sign, then the value) is redacted in the displayed location.
- `.ENV` and other case variants of `.env` are env files.
- A bare `secret`, `*_SECRET`, `aws_secret_access_key` and quoted passwords with spaces count as
  assigned credentials. This can add findings on config and prose.
- A `SYNTHETIC-DATA` file now downgrades only database and pickle fixtures. `MEMORY.md`, other
  agent memory and transcripts stay `agent-state` (block) in that folder. Rename a demo file if
  you relied on this.

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
