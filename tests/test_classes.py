"""Each leak class catches its leak and stays quiet on the realistic look-alike."""
import pytest
from publish_gate.classes import Terms, scan_line

NONE = Terms([], [])


def j(*parts):
    """Fixtures are joined at run time, so this file holds no literal leak for a scanner
    (this one included) to find."""
    return "".join(parts)


def classes(line, terms=NONE, suffix=".md"):
    return {c for c, _ in scan_line(line, terms, suffix)}


# Fragments are joined at run time so this file holds no literal secret.
AWS = "AKIA" + "IOSFODNN7" + "EXAMPLX"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"
SLACK = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
ANTH = "sk-ant-" + "api03-" + "a" * 40


@pytest.mark.parametrize("line", [AWS, GH, PEM, SLACK, JWT, ANTH,
                                  'api_key = "' + "q8Zt" + "3vLm9Kx2" + 'Rw7Ty"',
                                  "password: " + "Hunter2" + "Secure99"])
def test_secrets(line):
    assert "secret" in classes(line)


@pytest.mark.parametrize("line", ['api_key = "${API_KEY}"', 'api_key = "<your key>"',
                                  "password: changeme", 'token = "xxxxxxxx"',
                                  "Set API_KEY in your environment."])
def test_placeholders_are_not_secrets(line):
    assert "secret" not in classes(line)


@pytest.mark.parametrize("line", [j("host 192.", "168.1.20"), j("10.", "0.4.7:5432"), j("172.", "20.0.3"), j("169.", "254.10.1")])
def test_private_ips(line):
    assert "private-ip" in classes(line)


@pytest.mark.parametrize("line", ["192.0.2.44", "198.51.100.23", "203.0.113.9", "8.8.8.8",
                                  "version 10.0.19041.1234", "127.0.0.1"])
def test_documentation_public_loopback_and_version_strings_are_not_private_ips(line):
    assert "private-ip" not in classes(line)


@pytest.mark.parametrize("line", [j("/ho", "me/mara/projects/x"), j("/Us", "ers/ivo/Library"), j("C:", "\\Users\\tamsin\\AppData"),
                                  j("/mnt", "/c/Users/dave"), j("/tmp/cla", "ude-1000/x/scratchpad"),
                                  j("~/.claude/projects/-ho", "me-alice-proj/memory")])
def test_home_and_agent_scratch_paths(line):
    assert "home-path" in classes(line)


@pytest.mark.parametrize("line", ["/home/<user>/x", "~/projects", "$HOME/x", "/usr/local/bin"])
def test_generic_paths_are_not_home_paths(line):
    assert "home-path" not in classes(line)


@pytest.mark.parametrize("line", [j("contact alice", "@corp.io"), j("Signed-off-by: A <a.b", "@gmail.com>")])
def test_emails(line):
    assert "email" in classes(line)


@pytest.mark.parametrize("line", ["someone@users.noreply.github.com", "a@example.com",
                                  "x@test.example", "user@localhost"])
def test_noreply_and_example_emails_are_allowed(line):
    assert "email" not in classes(line)


@pytest.mark.parametrize("line", [j("https://claude.ai/code/", "session_01AbCdEfGh"),
                                  j("https://chatgpt.com/", "share/6721a0b1-aaaa-bbbb-cccc-0123456789ab"),
                                  j("https://claude.ai/", "chat/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")])
def test_agent_session_urls(line):
    assert "session-url" in classes(line)


def test_denylist_terms_block_and_review_terms_review():
    t = Terms(["Acme Industrial"], ["projectx"])
    assert "denylist" in classes("Built for ACME   industrial in 2025.", t)
    assert "review-term" in classes("the projectx scheduler", t)
    assert not classes("acmeindustrial-free text", t) & {"denylist"}


def test_wikilinks_review_only_in_markdown():
    assert "wikilink" in classes(j("see [", "[Private Note]]"), NONE, ".md")
    assert "wikilink" not in classes(j("[", "[tool.mypy.overrides]]"), NONE, ".toml")


def test_an_allow_pragma_excuses_only_its_class():
    line = j("contact alice", "@corp.io  # publish-gate: allow=email")
    assert "email" not in classes(line)
    assert "home-path" in classes(j("/ho", "me/mara/x  # publish-gate: allow=email"))


def test_a_finding_never_echoes_a_secret():
    out = scan_line(GH, NONE, ".md")
    assert out and GH not in out[0][1] and GH[:12] not in out[0][1]


@pytest.mark.parametrize("line,suffix", [
    ("url = 'https://api.example/v1?token={token}'", ".py"),
    ("Call https://api.example.com/v1/items?api_key={API_KEY}", ".md"),
    ("password = get_secret()", ".py"),
    ("token = os.environ['TOKEN']", ".py"),
    ("api_key = settings.API_KEY", ".py"),
])
def test_code_expressions_and_brace_placeholders_are_not_secrets(line, suffix):
    assert "secret" not in classes(line, NONE, suffix)


@pytest.mark.parametrize("line,suffix", [
    ('password = "' + "Hunter2" + 'Secure99"', ".py"),
    ("password=" + "Hunter2" + "Secure99", ".env"),
    ("api_key: " + "q8Zt3vLm9" + "Kx2Rw7Ty", ".yaml"),
])
def test_literal_secrets_still_count(line, suffix):
    assert "secret" in classes(line, NONE, suffix)


def test_a_pip_compile_input_path_is_a_home_path():
    assert "home-path" in classes(j("    # via -r /tmp/cla", "ude-1000/x/scratchpad/ci.in"), NONE, ".txt")


@pytest.mark.parametrize("line", [j("args = [", '["--root", "x"]]'), j("m = [", "[1, 2], [3, 4]]"),
                                  j("[", "[ -f file ]] && echo ok"), j("x = [", "['a']]")])
def test_nested_lists_and_shell_tests_are_not_wikilinks(line):
    assert "wikilink" not in classes(line, NONE, ".md")


@pytest.mark.parametrize("line", [j("allow 10.", "0.0.0/8 and 192.", "168.0.0/16"), j("route 172.", "16.0.0/12")])
def test_a_network_range_is_not_a_private_host(line):
    assert "private-ip" not in classes(line)


@pytest.mark.parametrize("suffix", [".md", ".yaml", ".py"])
def test_a_function_call_is_never_a_secret(suffix):
    assert "secret" not in classes("`password = get_secret()` is a call", NONE, suffix)
    assert "secret" not in classes("api_key: vault.read('kv/app')", NONE, suffix)
