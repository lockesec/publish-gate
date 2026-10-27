# Using publish-gate

## The four steps

1. **Keep your private names outside the repository.** Put one name per line in
   `~/.config/publish-gate/denylist` (or pass `--denylist FILE`, or set `$PUBLISH_GATE_DENYLIST`):
   clients, employers, people, internal project names. A `review:` line marks a name that is
   fine once a person has looked. The machine's hostname is always added. With no denylist the
   run is NOT EVALUABLE unless you pass `--no-denylist`, and a denylist inside the tree being
   published is NOT EVALUABLE too, because it would publish the names it protects.
2. **Run it on the tree.** In a git repository it reads what git would publish (tracked files
   plus untracked ones that are not ignored), so a `.venv` or build output does not drown the
   report; elsewhere, every file. Each finding names its class, its file and line, and a masked
   excerpt.
3. **Run it on the history before the first push.** `--history` reads every commit's tree,
   message, author and committer, because a leak removed in a later commit is still published
   with the history. The working tree must be clean in this mode.
4. **Decide, then publish.** Fix every block finding. A review finding (an internal ticket id,
   an Obsidian double-bracket link, a name marked `review:`, deliberately synthetic data) needs
   a person to look. It fails the gate until you pass `--accept-review`.

## Keeping a flagged value on purpose

- A line that must keep an otherwise flagged value, such as a sample address in a test, says so
  in a `publish-gate: allow=<class>` comment. That comment cannot excuse a secret or a
  denylisted name, and the summary counts every hit it excused.
- A `.publish-gate-allow` file in the repository (or `--allow-term TERM`) names review terms
  that are legitimate there, such as the project's own name. It can never excuse a block term.

## Before every push

`examples/pre-push` is a git hook that judges only what the push sends: the commits the remote
does not have yet and, in each, the files it adds or changes. A file already published
unchanged is not judged again. The negative control runs through that same path.

    cp examples/pre-push .git/hooks/pre-push && chmod +x .git/hooks/pre-push

The hook runs `publish-gate . --history --range "<remote>..<local>"` (for a new branch, the
commits that destination does not hold yet). Findings and NOT EVALUABLE both stop the push.
The header of `examples/pre-push` explains how each ref is turned into a range.

## In CI

`--format sarif` writes SARIF 2.1.0 for a code-scanning upload: block findings are errors,
review findings are warnings, and history findings name their commit. `--format json` (or
`--json`) writes the same data as plain JSON. A run that could not look is a failed SARIF run
with the reason, never an empty result list.
