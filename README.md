# publish-gate

**Find secrets, private names and AI-agent leftovers in a repository before you make it public.
It will not say "clean" until it has shown its own checks work.**

Once you push a key, a client's name, your home path or an AI agent's session link, it is
cached and indexed even if you delete it a minute later. Making a private project public is the
one step you cannot take back.

AI coding agents make this easier to get wrong. They write scratch paths, session links and
co-author trailers into files and commit messages, and they keep memory and transcript files
next to the code.

publish-gate reads what git would publish, or the whole history, and lists every leak with its
file and line. It also refuses to say "clean" until it has shown it can catch each kind of leak.
Every run first plants one known leak per class in a throwaway tree and scans it with the same
code. If any class goes unseen, the run is NOT EVALUABLE (exit 2), never a pass. It runs
offline, has no dependencies and never prints a secret.

## Quick start

Install:

    pip install git+https://github.com/sethpsonnier/publish-gate

The first run finds a committed `.env` file and a private name. After both are fixed, the same
command prints CLEAN. From a clone, `sh examples/demo.sh` plays this in a temporary directory,
and CI checks this block against its output.

```console
$ publish-gate repo --denylist denylist
BLOCK  env-file       .env  .env
BLOCK  denylist       README.md:3  Example Industries
FINDINGS: every file (not a git work tree), 2 text file(s) scanned, 0 binary file(s) not scanned, 2 block and 0 review finding(s); self-test: all 12 classes seen; denylist: 1 block, 0 review term(s) from denylist
(exit 1)
$ publish-gate repo --denylist denylist
CLEAN: every file (not a git work tree), 1 text file(s) scanned, 0 binary file(s) not scanned, 0 block and 0 review finding(s); self-test: all 12 classes seen; denylist: 1 block, 0 review term(s) from denylist
```

## How it works

1. **Keep your private names outside the repository.** Put one name per line in
   `~/.config/publish-gate/denylist` (or pass `--denylist FILE`, or set `$PUBLISH_GATE_DENYLIST`):
   clients, employers, people, internal project names. A `review:` line marks a name that is
   fine once a person has looked. The machine's hostname is always added.
2. **Run it on the tree.** In a git repository it reads what git would publish (tracked files
   plus untracked ones that are not ignored), so a `.venv` or build output does not drown the
   report; elsewhere, every file. Each finding names its class, its file and line, and a masked
   excerpt.
3. **Run it on the history before the first push.** `--history` reads every commit's tree,
   message, author and committer, because a leak removed in a later commit is still published
   with the history.
4. **Decide, then publish.** Fix every block finding. A review finding (an internal ticket id,
   an Obsidian double-bracket link, a name marked `review:`, deliberately synthetic data) needs
   a person to look. It fails the gate until you pass `--accept-review`. A line that must keep
   an otherwise flagged value, such as a sample address in a test, says so in a
   `publish-gate: allow=<class>` comment. That comment cannot excuse a secret or a denylisted
   name, and the summary counts every hit it excused.

## Before every push, and in CI

`examples/pre-push` is a git hook that judges only what the push sends: the commits the remote
does not have yet and, in each, the files it adds or changes. A file already published
unchanged is not judged again. The negative control runs through that same path.

    cp examples/pre-push .git/hooks/pre-push && chmod +x .git/hooks/pre-push

The hook runs `publish-gate . --history --range "<remote>..<local>"`. Findings and NOT EVALUABLE
both stop the push.

For CI, `--format sarif` writes SARIF 2.1.0 for a code-scanning upload: block findings are
errors, review findings are warnings, and history findings name their commit. `--format json`
writes the same data as plain JSON. A run that could not look is a failed SARIF run with the
reason, never an empty result list.

## What it catches

| Class | Blocks or review | What |
|---|---|---|
| `secret` | block | private keys; AWS, GitHub, Slack, Anthropic, OpenAI-style, Google and Vault tokens; JWTs; an assigned credential (`password = "..."` in code, `password=...` or `DB_PASSWORD: ...` in config), placeholders and `${VAR}` excepted |
| `private-ip` | block | RFC 1918, link-local and carrier-grade NAT addresses, in a URL or with a port too (documentation ranges, loopback and network ranges such as `/24` are fine) |
| `home-path` | block | `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `/mnt/<drive>/`, an agent scratch root `/tmp/claude-<uid>/`, a Claude Code project slug `-home-<user>-`; placeholder users such as `alice`, `user`, `runner` are fine |
| `email` | block | any address, in files, messages and commit authors, except GitHub noreply addresses and reserved example domains |
| `session-url` | block | links to a private AI-agent or chat session (Claude, ChatGPT, Gemini) |
| `denylist` | block | your private names, matched across spaces, hyphens, underscores and dots, so file names and slugs count too |
| `env-file` | block | a committed `.env` (`.env.example` and friends are fine) |
| `agent-state` | block | agent memory and state: `MEMORY.md`, `CLAUDE.local.md`, `.claude/settings.local.json`, session transcripts, databases and pickles |
| `synthetic-data` | review | agent-state files in a folder whose `SYNTHETIC-DATA` file declares `synthetic: true` |
| `review-term`, `internal-id`, `wikilink` | review | your `review:` names, a `--internal-id` pattern, Obsidian double-bracket links in Markdown |

The gate judges the file name as well as the text, and a symlink's target (git publishes it as
a path). It reads UTF-16 text (Windows PowerShell, `.reg`) as text. It counts binary files
without reading them and prints the count. A text file over `--max-bytes` makes the run NOT
EVALUABLE, because an unscanned text file is not a clean one.

## Why you can trust a clean result

- **It proves it can see, every run.** One planted leak per class (assembled from fragments,
  so the tool itself holds no literal secret) must be found before the real scan counts; in
  `--history` mode the seeds are committed and then deleted, so the history path is tested too.
  A test switches a class off and checks the run becomes NOT EVALUABLE.
- **It refuses to guess.** No denylist (without `--no-denylist`), a denylist inside the tree
  being published, a file or folder it cannot read, a dirty working tree in `--history` mode, a
  failed git call or an oversized text file: each is NOT EVALUABLE (exit 2), never clean.
- **Content cannot excuse itself.** A `.publish-gate-allow` file in the repository may name
  review terms that are legitimate there (the project's own name); it can never excuse a block
  term, and an inline `allow=` comment can never excuse a secret or a denylisted name.
- **It never prints a secret**, not even a prefix.

## Exit codes

| code | meaning |
|---|---|
| 0 | clean |
| 1 | findings |
| 2 | NOT EVALUABLE: it could not look (the cause is named in the output). Never a pass |
| 64 | usage error |

## See it used

The [case studies](https://github.com/sethpsonnier/case-studies) each ship a `reproduce.sh`
that runs this gate.

## Known limits

- Patterns, not a secret scanner's full catalogue: a token format it does not list, a secret
  split across lines or encoded is not seen. Pair it with a dedicated secret scanner for depth.
- A private name is caught only if it is on your denylist; a misspelling is a different word.
- A home path under a placeholder user name (`alice`, `jane`, `user`, `runner` and a few more,
  listed in `classes.py`) is not reported; if your own user name is one of them, it is missed.
- `--history` reads commits reachable from your refs; reflog-only or unreachable objects are not
  read (they are not pushed either).
- Binary files are counted, not read: an image's metadata or a PDF's text is not checked.

## Prior art

Secret scanners such as gitleaks, trufflehog and detect-secrets cover far more token formats and
are worth running too. publish-gate adds what a public release of an AI-assisted project needs on
top: agent state and scratch paths, session links, your own private names, and a negative control
that makes a silent scanner fail instead of pass.

## Docs, credits, license

- [DESIGN.md](DESIGN.md): the decisions and why. [CHANGELOG.md](CHANGELOG.md): what changed.

The gate was built in a private AI-experimentation environment, where it checked every public
release, and then extracted as a standalone tool. The maintainer designed and directed it. AI
coding agents wrote much of the code, and separate AI sessions reviewed it.

Apache-2.0 - see [LICENSE](https://github.com/sethpsonnier/publish-gate/blob/main/LICENSE) and
[NOTICE](NOTICE).
