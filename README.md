<h1 align="center">publish-gate</h1>

<p align="center"><b>Check a repository for leaks before you make it public.</b><br>
It says "clean" only after it has shown its own checks work.</p>

publish-gate finds secrets, private names and AI-agent leftovers in a repository, and lists
each one with its file and line.

Making a private project public is the one step you cannot take back: a pushed key, client
name or home path is cached and indexed within minutes. AI coding agents add their own leaks:
scratch paths, links to private chat sessions, co-author trailers, memory and transcript files.
publish-gate looks for both kinds. It runs offline, has no dependencies and never prints a secret.

Every run first plants one known leak of each kind in a throwaway tree and scans it. If any
goes unseen, the result is NOT EVALUABLE (exit 2) instead of clean.

Designed for:

- **Your own list of private names.** You need it. Without a denylist the names cannot be checked,
  and the run is NOT EVALUABLE unless you pass `--no-denylist`.
- **A dedicated secret scanner beside it.** You need one for wider secret coverage. publish-gate knows
  the common token formats, not every format.
- **A person to read review findings.** They fail the gate until you pass `--accept-review`.
- **Git, for the history check.** `--history` and the pre-push hook need it. A plain folder can be
  scanned without it.

Try it (Python 3.11+). List your private names, one per line, in `~/.config/publish-gate/denylist`, then:

    pip install git+https://github.com/lockesec/publish-gate
    publish-gate .
    publish-gate . --history

## See it work

A throwaway folder `repo` holds a `.env` file and a README that names a client.
The file `denylist` holds the private names.

```sh
mkdir repo
printf '# App\n\nBuilt for Example Industries.\n' > repo/README.md
printf 'DB_PASSWORD=dev\n' > repo/.env
printf 'Example Industries\n' > denylist
```

```console
$ publish-gate repo --denylist denylist
BLOCK  env-file       .env  .env
BLOCK  denylist       README.md:3  Example Industries
FINDINGS: every file (not a git work tree), 2 text file(s) scanned, 0 binary file(s) not scanned, 2 block and 0 review finding(s); self-test: all 12 classes seen; denylist: 1 block, 0 review term(s) from denylist
(exit 1)
```

The last line is a receipt: what was scanned, and that all 12 leak classes were seen. Fix both
leaks and run it again:

```sh
printf '# App\n\nBuilt for a client.\n' > repo/README.md
rm repo/.env
```

```console
$ publish-gate repo --denylist denylist
CLEAN: every file (not a git work tree), 1 text file(s) scanned, 0 binary file(s) not scanned, 0 block and 0 review finding(s); self-test: all 12 classes seen; denylist: 1 block, 0 review term(s) from denylist
```

`sh examples/demo.sh` plays this in a temporary directory; CI checks these transcripts against its output.

## How it works

| When | Run | What it reads |
|---|---|---|
| While you work | `publish-gate .` | what git would publish: tracked files plus untracked ones not ignored |
| Before the first push | `publish-gate . --history` | every commit's tree, message, author and committer |
| On every push | `examples/pre-push` hook | only the commits and files the push sends |
| In CI | `--format sarif` or `--format json` | the same findings, as SARIF 2.1.0 or JSON |

A **block** finding must be fixed. A **review** finding (an internal ticket id, a wikilink, a
name marked `review:`) needs a person to look, and fails the gate until you pass
`--accept-review`. Steps, the pre-push hook, allow comments and CI: [docs/usage.md](docs/usage.md).

## What it catches

| Class | What |
|---|---|
| `secret` | private keys, cloud and API tokens, JWTs, assigned credentials |
| `private-ip` | private network addresses |
| `home-path` | personal paths such as `/home/<user>`, agent scratch roots |
| `email` | any address in files, messages and commit authors |
| `session-url` | links to a private AI-agent or chat session |
| `denylist` | your private names |
| `env-file` | a committed `.env` |
| `agent-state` | agent memory, state and transcripts |
| `synthetic-data` | database and pickle fixtures declared synthetic (review) |
| `review-term`, `internal-id`, `wikilink` | names marked `review:`, internal ticket ids, Obsidian links (review) |

Exact patterns and exceptions: [docs/classes.md](docs/classes.md).

Measured on real credentials in [Samsung CredData](https://github.com/Samsung/CredData) (Apache-2.0), on
98 repositories set aside from the fixes, `secret` class only:

| Kind of secret | Caught | Flagged by mistake |
|---|---|---|
| Known formats: private keys, JWTs, AWS, Google, Slack and others | **94.5%** of 1,312 | 26.7% of 161 |
| Named values: `password=`, `token=` and similar | **49.2%** of 2,843 | 10.3% of 8,931 |
| Generic keys and ids: UUIDs, salts, unlabelled keys | **0.9%** of 4,492 | 6.9% of 11,427 |
| All | **30.5%** of 8,793 | 8.5% of 20,586 |

CredData's "false" rows are lines other scanners flagged by mistake, so the last column is a rate over hard
cases, not over ordinary code. How to read and rerun it: [docs/limits.md](docs/limits.md).

## Why you can trust a clean result

1. **It proves it can see, every run.** One planted leak per class must be found before the
   real scan counts. The seeds are assembled from fragments, so the tool holds no literal
   secret. In `--history` mode they are committed and then deleted, so the history path is
   tested too. A test switches a class off and checks the run becomes NOT EVALUABLE.
2. **It refuses to guess.** Each of these is NOT EVALUABLE (exit 2), never clean: no denylist
   (without `--no-denylist`), a denylist inside the tree being published, a file or folder it
   cannot read, a dirty working tree in `--history` mode, a failed git call, a text file over
   `--max-bytes`.
3. **Content cannot excuse itself.** A `.publish-gate-allow` file may name legitimate review
   terms, never a block term. An inline `allow=` comment can never excuse a secret or a
   denylisted name, and the summary counts every hit it excused.
4. **It never prints a secret**, not even a prefix.

## Exit codes

| code | meaning |
|---|---|
| 0 | clean |
| 1 | findings |
| 2 | NOT EVALUABLE: it could not look (the cause is named in the output). Never a pass |
| 64 | usage error |

## Where it falls short

- **It misses most credentials overall: 30.5% caught.** It reads known formats and named values, and guesses nothing from randomness, so a bare random key goes unseen (0.9%). Pair it with a dedicated secret scanner.
- **It flags hard cases by mistake:** 8.5% of lines other scanners also got wrong.
- **A private name is caught only if it is on your denylist.** A misspelling is a different word.
- **Binary files are counted, not read.** An image's metadata or a PDF's text is not checked.
- **No head-to-head with another scanner has been run.**

How it was measured, known holes and what is untested: [docs/limits.md](docs/limits.md).

## See it used

The [case studies](https://github.com/lockesec/case-studies) each ship a `reproduce.sh`
that runs this gate.

## Prior art and credits

- Secret scanners such as gitleaks, trufflehog and detect-secrets cover far more token formats
  and are worth running too. publish-gate adds what a public release of an AI-assisted project
  needs on top: agent state and scratch paths, session links, your own private names, and a
  negative control that makes a silent scanner fail instead of pass.
- The gate was built in a private AI-experimentation environment, where it checked every public
  release, then extracted as a standalone tool. The maintainer designed and directed it. Much
  of the code was written with AI coding agents, and separate AI sessions reviewed it
  adversarially; the tests and [DESIGN.md](DESIGN.md) show what was checked.
- Attribution corrections are welcome.

## Docs

- [docs/usage.md](docs/usage.md): steps, pre-push hook, allow comments, CI output.
- [docs/classes.md](docs/classes.md): every leak class. [docs/limits.md](docs/limits.md): all known limits.
- [DESIGN.md](DESIGN.md): the decisions and why. [CHANGELOG.md](CHANGELOG.md): what changed.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
