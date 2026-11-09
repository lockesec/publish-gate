# Limits

## How well it works

`benchmarks/run_creddata.py` measures the `secret` class on [Samsung CredData](https://github.com/Samsung/CredData)
(Apache-2.0) at commit `fc9b64b`. It reads a checkout after CredData's own download step and runs no code from it.

- **Subset.** 135 of its 337 repositories, because a full fetch passes 5 GB. Taken in a hash order that ignores size. The script measures whatever is present, so a full run will give other numbers.
- **Split.** Repository name, hashed, 30% DEV and 70% held back. Fixes came from DEV only: 60.4% recall and 4.0% false alarms there, which flatters. The README table is the other 98 repositories.
- **Those 98 have been read more than once.** The first read, before the fixes, gave 22.5% and 8.2%, as counts by category. No fix came from them. Later fixes, from a review on other files, moved the counts by a handful and were checked against these repositories only to update the table. Three fixes made after that, from a review of a port into another gate (a private address that ends a sentence, a key header with four dashes or a digit in its type, a quoted secret in a C `#define`), are not in the table: the held-out run is single use and was not repeated for them. `benchmarks/run_creddata.py` prints the table's three families.
- **Unit.** A labelled location (file and line range) counts when a `secret` finding falls inside it. Rows labelled unknown are excluded: 1,459.
- **False alarms cluster.** One file holds 375 of the 1,756; without it the rate is 7.4%.
- **Everything else is not measured:** private names, paths, addresses and agent leftovers have no public test set.

## Not tested

- Another scanner on the same data. None was run, so this table does not rank it.
- The rest of CredData's repositories.

## Out of scope on purpose

- Guessing from randomness. An entropy rule would catch more generic keys and flag more ordinary text, in a tool that blocks a publish. That is a dedicated scanner's job.

## Known holes

- **Code that follows a quoted name can read as a value,** as in a JavaScript ternary after `'PASS'`. One real file out of several trees did this.
- **A C-style `#define` is read only with a quoted literal** of 6 or more characters and no space or slash. Under a name that is not a password's, the literal must also mix letters with a digit or symbol, so `#define API_KEY "abcdefghij"` is missed.
- **An unquoted word with no digit in C, C++, Elixir, Swift or Scala reads as a name,** so a plain word as a password there is missed.
- **Bare `pass` and `pwd` need a value mixing letters with a digit or symbol.** A plain word after `PASS:` is missed; after `db_pass:` or `export PASS=` it is found.

- Patterns, not a secret scanner's full catalogue: a token format it does not list, a secret
  split across lines or encoded is not seen. Pair it with a dedicated secret scanner for depth.
- A private name is caught only if it is on your denylist; a misspelling is a different word. A
  name glued into a longer token is found only when it starts the token, and only for names of
  4 or more characters: `acme` inside `pacmerge` is not reported.
- A home path under a placeholder user name (`alice`, `jane`, `user`, `runner` and a few more,
  listed in `classes.py`) is not reported; if your own user name is one of them, it is missed.
- `--history` reads commits reachable from your refs; reflog-only or unreachable objects are not
  read (they are not pushed either).
- Binary files are counted, not read: an image's metadata or a PDF's text is not checked.
- Tree mode reads the working copy, not the index: a secret staged and then overwritten on disk
  reads CLEAN there and is still committed. `--history` reads commits and refuses a dirty tree, so
  run it before you push.
- An inline `publish-gate: allow=<class>` comment sits in the scanned file, so a file can excuse
  its own home paths, emails, private addresses and session links. It never excuses a secret or a
  denylist name, and the excused count is printed: read it.
- Secrets are matched by keyword (`password`, `token`, `secret`, `private_key`, `passphrase`,
  `*_secret_access_key` and a few more). A credential under another name is not seen, and a quoted
  value with spaces counts only under `password`, `passwd` or `passphrase`.
- A password in a URL needs 6 or more characters and no raw `/`, `?` or `#` (a real one is
  percent-encoded). A rare address shaped like `name:value@tag` is reported as a password.
- A placeholder is not reported. That covers a value in brackets holding only letters (`[word]`,
  `{word}`, `<word>`) and a literal wrapped whole in a template (`${word}`), so a real password
  written that way is missed.
- `user:user@localhost` is taken as a local default and not reported. Other well-known defaults are.
- `private_key` and `passphrase` values count when quoted, or when they hold a digit, mixed case or
  all capitals. An unquoted lowercase word or identifier beside those names is not seen.
- Token formats it does not list include Stripe `rk_live_`, webhook secrets such as `whsec_`,
  Discord webhooks, a `Bearer` value with no `Authorization` beside it, and `Authorization: Token ...`.
