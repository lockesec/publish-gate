# What publish-gate catches

Twelve classes. Every run plants one known leak of each and checks it is seen before the real scan counts.

| Class | Blocks or review | What |
|---|---|---|
| `secret` | block | private keys (including PGP key blocks); AWS, GitHub, Slack, Anthropic, OpenAI-style, Google, Vault, Stripe, npm, GitLab, Hugging Face and PyPI tokens; Slack webhook URLs; `Authorization: Bearer` values; a password in a URL; JWTs; an assigned credential (`password = "..."` in code, `password=...` or `DB_PASSWORD: ...` in config), placeholders and `${VAR}` excepted |
| `private-ip` | block | RFC 1918, link-local and carrier-grade NAT addresses, in a URL or with a port too (documentation ranges, loopback and network ranges such as `10.0.0.0/8` are fine; an address with host bits set and a prefix, such as an interface `x.y.z.50/24`, is a host) |
| `home-path` | block | `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `/mnt/<drive>/`, an agent scratch root `/tmp/claude-<uid>/`, a Claude Code project slug `-home-<user>-`; placeholder users such as `alice`, `user`, `runner` are fine |
| `email` | block | any address, in files, messages and commit authors, except GitHub's noreply and support addresses (web commits, Dependabot's sign-off) and reserved example domains |
| `session-url` | block | links to a private AI-agent or chat session (Claude, ChatGPT, Gemini) |
| `denylist` | block | your private names, matched across spaces, hyphens, underscores and dots, so file names and slugs count too |
| `env-file` | block | a committed `.env` (any case) (`.env.example` and friends are fine) |
| `agent-state` | block | agent memory and state: `MEMORY.md`, `CLAUDE.local.md`, `.claude/settings.local.json`, session transcripts, databases and pickles |
| `synthetic-data` | review | databases and pickles in a folder whose `SYNTHETIC-DATA` file declares `synthetic: true`. Agent memory and transcripts stay `agent-state` even there: a file in the repo cannot vouch for them |
| `review-term`, `internal-id`, `wikilink` | review | your `review:` names; any denylist name of 4+ characters that starts a longer token, such as a domain, host or account name (`acmecorp.com`, `ACMECORP\svc`, `acmeind-dc01`), or a many-word name written with its words touching (`ZorblaxHoldings`); a `--internal-id` pattern; Obsidian double-bracket links in Markdown |

The gate judges the file name as well as the text, and a symlink's target (git publishes it as
a path). It reads UTF-16 text (Windows PowerShell, `.reg`) as text. It counts binary files
without reading them and prints the count. A text file over `--max-bytes` makes the run NOT
EVALUABLE, because an unscanned text file is not a clean one. A tree with no files at all to
judge (empty, or everything ignored by git) is NOT EVALUABLE too: nothing was looked at.
