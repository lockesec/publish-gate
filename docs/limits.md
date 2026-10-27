# Known limits

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
