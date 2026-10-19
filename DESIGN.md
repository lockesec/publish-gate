# Design

## The problem

The first public commit of a project is the point of no return. A leak in it is cached by
mirrors and search indexes within minutes, and deleting it does not take it back. Projects built
with AI coding agents carry leak shapes ordinary secret scanners were not built for: the agent's
scratch directory and project slug in a path, a link to the private chat session in a commit
trailer, memory and transcript files beside the code, and the names of the clients and people
the work was for.

## Decisions

**A negative control on every run.** A scanner that cannot see is indistinguishable from a
clean tree: both print nothing. So before every scan the gate plants one known leak per class
in a throwaway tree, scans it with the same code, and refuses to give a verdict (exit 2) if any
class goes unseen. In `--history` mode the seeds are committed and then deleted, so the path
that reads history is tested too. The seeds are assembled from fragments at run time, so the
tool holds no literal secret for another scanner or a push-protection service to trip over.

**Absence is not a measurement.** No denylist means private names were not checked, so the run
is NOT EVALUABLE unless you say `--no-denylist`. A text file too large to read, a git call that
fails, or a dirty working tree in history mode is the same: exit 2, with the cause, never 0.
Binary files are counted and the count is printed, so the denominator is always visible.

**The tree is what would be published.** In a git work tree the gate reads tracked files plus
untracked ones that are not ignored; that is what `git add -A && git push` would send. Reading
`.venv` and build output instead buried the real findings under hundreds of irrelevant ones on
the first real run.

**Content cannot excuse itself.** The repository may carry a `.publish-gate-allow` file naming
review terms that are legitimate there (its own name, for instance). It cannot excuse a block
term: a file in the content being judged must not be able to clear a finding about that content.
The same holds for a `publish-gate: allow=<class>` comment on a line: it can keep a deliberate
example address or path, never a secret or a denylisted name, and every hit it excuses is
counted in the summary, so an allow marker is never silent.
The denylist itself must live outside the tree, or it would publish the very names it protects.

**A push is judged by what it sends.** `--range` hands its revisions to `git rev-list` and,
for each commit, judges the files that commit adds or changes against each parent, oldest
commit first, so a leak is reported where it entered. Re-judging every file of every pushed
commit would block each push on leaks already public, which teaches people to bypass the hook;
the full `--history` run is the check for what is already out. The negative control seeds
through the same changed-file path, so a blind range path cannot pass.

**Never print a secret.** Secret findings show the class, the place and the length, not even a
prefix.

**In code, a secret is a literal.** `password = get_secret()` is a call, not a password; in
source files only a quoted value counts, while in config and `.env` files an unquoted value is
the value. This came from the first real run, which flagged test code that read a secret.

## What the first real run found

Run over six repositories being prepared for public release (all of which had passed an
earlier, narrower gate), history mode found a `requirements-ci.txt` whose pip-compile comments
recorded the absolute path of an agent's scratch directory (`# via -r /tmp/claude-<uid>/...`).
It was on the main branch of one repository. That shape is now a test.

## Adversarial review

Separate AI sessions that had not written the code reviewed it adversarially. Each finding was reproduced
against the source and pinned to a test before it was fixed.

The first review ran the gate on real repositories and on leak trees it built, and found twelve
ways the gate said less than it promised. All twelve are fixed, each with a test:

- an inline `allow=` comment could clear a secret or a denylisted name (now refused, and excused
  hits are counted);
- an unreadable file or folder crashed the run or was skipped (now NOT EVALUABLE);
- a tracked file with a non-UTF-8 name was skipped;
- these were not read: `DB_PASSWORD=`-style names, a private host in a URL or as `/32`, a home
  path with no trailing slash, symlink targets, commit author and committer addresses, UTF-16
  text;
- `noreply@github.com` was flagged;
- `python -m pytest` needed `PYTHONPATH` from a clone.

Re-running the gate on six sibling repositories then showed that placeholder users such as
`/home/alice` and the POSIX class `[[:alpha:]]` were reported. Both are now passed.
