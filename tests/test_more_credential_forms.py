"""Credential forms the gate did not know. Fake values are assembled from parts so this file
passes its own gate."""
import pytest
from publish_gate import classes as c

NONE = c.Terms([], [])
def U(value):
    return "https://u:" + value + "@host"


B = "Authorization: " + "Bearer "
R = "q7Zp2Lk9Xv4Tn8Wm3Bc6Rd1Hs5Gf0Jy2Ua7Ee4Oi9Pt"


def classes(line, suffix=".txt"):
    return {cls for cls, _ in c.scan_line(line, NONE, suffix)}


@pytest.mark.parametrize("value", [
    "AS" + "IA" + "Q7ZP2LK9XV4TN8WM",
    "sk_" + "live_" + R[:24],
    "np" + "m_" + R[:36],
    "gl" + "pat-" + R[:20],
    "h" + "f_" + R[:34],
    "py" + "pi-" + (R * 2)[:60],
    "https://hooks." + "slack.com/services/T0AB1CD2E/B0FG3HI4J/" + R[:24],
    "Authorization: " + "Bearer " + R[:30],
    "https://svc:" + R[:14] + "@intranet/x",
    "postgres://app:" + R[:14] + "@db.internal:5432/main",
])
def test_each_form_is_a_secret_and_is_never_shown(value):
    found = c.scan_line(value, NONE, ".txt")
    assert any(cls == "secret" for cls, _ in found), value
    assert R[:14] not in c.redact(value) and "Q7ZP2LK9" not in c.redact(value)


@pytest.mark.parametrize("name", ["private_key", "private-key", "passphrase"])
def test_more_credential_names_are_assigned_secrets(name):
    assert "secret" in classes(f'{name} = "{R[:16]}"', ".yaml")


@pytest.mark.parametrize("line", [
    "see https://user:" + "${PASS}" + "@host/x",
    "https://user:" + "<password>" + "@host/x",
    "postgres://app:" + "password" + "@localhost/db",
    "Authorization: " + "Bearer " + "<token>",
    "Authorization: " + "Bearer " + "${TOKEN}",
    "the hf_ prefix and the npm_ prefix are token families",
    "sk_" + "live_ is the Stripe prefix",
    "ASIA is a continent",
])
def test_placeholders_and_prose_stay_clean(line):
    assert "secret" not in classes(line), line


@pytest.mark.parametrize("line", [
    '{"Authorization": "Bearer ' + R[:30] + '"}',
    "{'Authorization':'Bearer " + R[:30] + "'}",
    "redis://:" + "Kp29xQ7zLm" + "@cache",
    U("test-R3alS3cret"),
    U("example!Pw9z"),
    U("password!23"),
    U("%41bcdefgh9"),
    U("$ecretPa55"),
    U("p@ssw0rd99"),
    U("hunter2"),
])
def test_review_misses_are_secrets(line):
    assert "secret" in classes(line), line


@pytest.mark.parametrize("line", [
    "hooks." + "slack.com/services/T00000000/B00000000/" + "X" * 24,
    B + "YOUR_ACCESS_TOKEN_HERE",
    B + "your-token-goes-here-now",
    B + "x" * 24,
    U("[REDACTED]"),
    U("........"),
    U("yourpassword"),
    "private_key: /etc/ssl/private/server.key",
    'private_key = "keys/deploy.pem"',
    "The passphrase: required for every signing operation",
    "passphrase=args.passphrase",
    "private_key=private_key_bytes",
    "sk_" + "live_" + "x" * 24,
])
def test_review_false_blocks_stay_clean(line):
    assert "secret" not in classes(line), line


def test_a_long_dotted_line_stays_fast():
    import time
    line = "a." * 100_000
    start = time.perf_counter()
    c.scan_line(line, NONE, ".txt")
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("line", [
    "mysql://root:" + "123456" + "@db",
    "postgres://admin:" + "8675309123" + "@db",
    "s3://MYKEYID:" + "Kp29xQ7zLm" + "@bucket",
    "docker://bot:" + "Kp29xQ7zLm" + "@registry",
    "npm://bot:" + "Kp29xQ7zLm" + "@registry",
    U("mysterious"),
    U("mysecretpassword"),
    U("yoursuperpass"),
    U("my-horse-battery"),
    U("[Kp29xQ7zLm]"),
    "--url-postgres://u:" + "Kp29xQ7zLm" + "@db",
    "averyveryveryverylongschemenamehere+x://u:" + "Kp29xQ7zLm" + "@db",
    B + "mysupersecretletterstoken",
    'req.Header.Set("Authorization", "Bearer ' + R[:30] + '")',
    "Authorization: `Bearer " + R[:30] + "`",
    "private_key: /9j4AAQSkZJRgABAQEASABI",
    "private_key: ABCDEFGHJKLMNPQR",
    "passphrase: /Kp29xQ7zLm",
    "passphrase: ../Kp29xQ7z",
    "passphrase: " + '"' + "Kp29xQ7zLm.key" + '"',
])
def test_round_two_misses_are_secrets(line):
    assert "secret" in classes(line), line


@pytest.mark.parametrize("line", [
    U("{{db_password}}"),
    U("$(DB_PASS)"),
    U("%{db_pass}"),
    U("#{pw}aaa"),
    U("__DB_PASS__"),
    U("$db_pass"),
    "https://example.com:8443?email=me" + "@x.io",
    "http://localhost:3000#a" + "@b.io",
    U("PASSWORD_HERE"),
    U("changeme_please"),
    U("your_password"),
    U("my-token"),
    B + "ACCESS_TOKEN_GOES_HERE",
    "postgres://postgres:" + "postgres" + "@localhost/app",
])
def test_round_two_false_blocks_stay_clean(line):
    assert "secret" not in classes(line), line


def test_a_default_password_off_localhost_is_still_a_secret():
    assert "secret" in classes("postgres://postgres:" + "postgres1" + "@db.internal/app")
    assert "secret" in classes("postgres://app:" + "s3cretpw1" + "@localhost/app")


K = "Kp29xQ7zLm"


@pytest.mark.parametrize("line", [
    U(K + "$" + "{x}"),
    U("{{x}}" + K),
    U("Kp29xQ7z" + "$(x)"),
    U("Kp29" + "%{x}" + "xQ7zLm"),
    U("#{a}" + K),
    U("__" + K + "__"),
    B + "abcdEFGH1234abcd" + "$" + "{x}" + "EFGH1234",
])
def test_a_literal_beside_a_template_is_a_secret(line):
    assert "secret" in classes(line), line


@pytest.mark.parametrize("line", [
    U("$" + "{a}" + "{{b}}"),
    U("$(a)" + "-" + "$(b)"),
    B + "$" + "{A_VERY_LONG_TOKEN_NAME_HERE}",
])
def test_a_value_of_only_templates_stays_clean(line):
    assert "secret" not in classes(line), line


@pytest.mark.parametrize("opener", ["{{", "$" + "{", "$(", "%{", "#{"])
def test_a_line_of_bare_template_openers_stays_fast(opener):
    import time
    line = U(opener * 80_000)
    start = time.perf_counter()
    c.scan_line(line, NONE, ".txt")
    assert time.perf_counter() - start < 1.0


def test_a_function_call_after_bearer_is_not_a_token():
    assert "secret" not in classes(B + "getAccessTokenForService()")
