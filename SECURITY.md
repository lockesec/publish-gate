# Security

publish-gate exists to stop leaks. These count as vulnerabilities:

- a leak it misses in a class the README lists;
- a clean verdict on a tree it did not fully read;
- a secret printed in its output.

Please report one privately through GitHub's private vulnerability reporting for this
repository, not as a public issue. Include the input that shows it, built from fragments if it
holds a real secret.

Out of scope: token formats [docs/classes.md](docs/classes.md) does not list, and private names that
are not on the denylist you ran with.
