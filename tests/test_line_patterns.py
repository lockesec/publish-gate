"""Line-level rules: what the patterns catch, and the look-alikes they must leave alone."""
import pytest
from publish_gate.classes import Terms, scan_line

NONE = Terms([], [])


def j(*parts):
    return "".join(parts)


TOKEN = j("ghp", "_", "Rv7" * 13)


def classes(line, terms=NONE, suffix=""):
    return {c for c, _ in scan_line(line, terms, suffix)}


# content cannot excuse a block term, not even with an inline marker
def test_an_inline_marker_cannot_excuse_a_secret_or_a_private_name():
    terms = Terms(["Example Industries"], [])
    assert "secret" in classes(f"token: {TOKEN}  # publish-gate: allow=secret")
    assert "denylist" in classes("built for Example Industries  # publish-gate: allow=denylist",
                                 terms)


# the credential names compose files and .env files actually use
@pytest.mark.parametrize("line", [j("POSTGRES_PASS", "WORD: s3cretpassw0rd"),
                                  j("DB_PASS", "WORD=anotherRealOne99"),
                                  j("STRIPE_SECRET", "_KEY=liveValue12345")])
def test_a_prefixed_credential_name_in_config_is_a_secret(line):
    assert "secret" in classes(line, suffix=".yml")


@pytest.mark.parametrize("line", ["PASSWORD_FILE=/run/secrets/db", "DB_PASSWORD=${DB_PASSWORD}"])
def test_a_password_file_path_or_a_variable_is_not(line):
    assert "secret" not in classes(line, suffix=".env")


# a private address in a URL, or written as a /32 host, is a host
@pytest.mark.parametrize("line", [j("curl http://192.", "168.1.10/admin"),
                                  j("gateway 10.", "20.30.40/32"), j("db 10.", "1.2.3:5432")])
def test_a_private_host_in_a_url_or_as_a_slash_32_is_found(line):
    assert "private-ip" in classes(line)


def test_a_range_prefix_is_still_a_network():
    assert classes(j("allow 10.", "0.0.0/8 and 192.", "168.1.0/24")) == set()


# a home path with no trailing slash still names the user
@pytest.mark.parametrize("line", [j("cd /ho", "me/mara && make"), j("export HOME=/ho", "me/mara"),
                                  j("PATH=/usr/bin:/Us", "ers/mara")])
def test_a_home_path_without_a_slash_is_found(line):
    assert "home-path" in classes(line)


@pytest.mark.parametrize("line", ["see https://example.com/home/index", "/home/<user>/x",
                                  "/home/alice/x", "/Users/Jane Doe/venv", "/home/runner/work",
                                  "/home/_home_", "/home/$USER/x"])
def test_a_url_path_or_a_placeholder_is_not_a_home_path(line):
    assert "home-path" not in classes(line)


# GitHub's own committer address is fine
def test_githubs_own_noreply_address_is_fine():
    assert classes("Committer: GitHub <noreply@github.com>") == set()


def test_a_posix_character_class_is_not_a_wikilink():
    assert classes("grep '[[:alpha:]]' x", suffix=".md") == set()
