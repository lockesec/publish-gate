"""Shapes a public credential benchmark showed were missed, and a version string that stopped the
whole scan. Fixtures are built from fragments."""
import pytest

from publish_gate.classes import Terms, _private_ips, redact, scan_line

NONE = Terms([], [])


def secrets(line, suffix=""):
    return [c for c, _ in scan_line(line, NONE, suffix) if c == "secret"]


@pytest.mark.parametrize("v", ["1.17.04.3", "2.0.00.1", "01.02.03.04", "1.2.3.09"])
def test_a_version_string_does_not_stop_the_scan(v):
    assert _private_ips(f"version {v} here") == []


def test_a_zero_padded_private_address_is_still_found():
    assert _private_ips("host 01" + "0.0.0.1 up") == ["10" + ".0.0.1"]


@pytest.mark.parametrize("line", ["The server is at 10" + ".0.0.1.", "at 192" + ".168.1.20. Then", "(10" + ".0.0.1.)"])
def test_an_address_that_ends_a_sentence_is_found(line):
    assert _private_ips(line) != []


@pytest.mark.parametrize("v", ["10" + ".0.0.1.5", "192" + ".168.1.2.3 build"])
def test_a_longer_dotted_number_is_still_not_an_address(v):
    assert _private_ips(v) == []


@pytest.mark.parametrize("dashes,kind", [("----", " SSH2 ENCRYPTED"), ("-----", " OPENSSH"), ("-----", ""),
                                         ("-----", " ENCRYPTED")])
def test_every_private_key_header_is_found(dashes, kind):
    sp = " " if len(dashes) == 4 else ""
    assert secrets(dashes + sp + "BEGIN" + kind + " PRIVATE " + "KEY" + sp + dashes) == ["secret"]


@pytest.mark.parametrize("line", ['#define PASSWORD "Zq9' + 'wXk7pLm"', '#define DB_PASSWD "hun' + 'ter2"',
                                  '  #  define API_KEY "Zq9wXk7' + 'pLmN2"', '#define SECRET_TOKEN "a1b2' + 'c3d4e5"'])
def test_a_secret_in_a_c_macro_is_found(line):
    assert secrets(line, ".h") == ["secret"]


@pytest.mark.parametrize("line", ['#define PASSWORD_MAX 64', '#define SECRET_FILE "/etc/app/secret.conf"',
                                  '#define TOKEN_HEADER "Authorization"', '#define PASSWORD_PROMPT "Enter password"',
                                  '#define API_KEY "${API_KEY}"', '#define TOKEN "abc"'])
def test_a_macro_that_holds_no_secret_stays_quiet(line):
    assert secrets(line, ".h") == []


@pytest.mark.parametrize("line", [
    "seed SU" + "A" * 56,
    "t = glsa_" + "a" * 32 + "_" + "0a1b2c3d",
    "t = glc_" + "a" * 40,
    "Authorization: Basic " + "c3ZjOlpx" + "OXdYazdw",
    "secret_key_base: " + "Zq9w" + "Xk7pLmN2",
    "pass: " + "Zq9w" + "Xk",
    "password = 'Zq9" + "wXk'",
    "PWD=Zq9" + "wXk7",
    "The password is password=`V1" + "0abc` on staging.",
    "pwd=`V1" + "0abc`", "pwd=.V1" + "0abc",
    "db_pass: hunter", "MYSQL_PWD=hunter", "export PASS=hunter",
    "PASS: Zq9w" + "Xk7",
])
def test_a_shape_the_benchmark_missed_is_found(line):
    assert secrets(line) == ["secret"]
    assert "Zq9wXk" not in redact(line) and "aaaaaaaa" not in redact(line)
    assert "V10abc" not in redact(line)


@pytest.mark.parametrize("line", [
    "not read: `DB_PASSWORD=`-style names", "use `pass=`-shaped keys",
    "PASS: all good", "second pass: optimize the plan.", "First pass: reading the file.", "pass: failed",
    "tests pass: 142312", "pwd=subdir", "pwd: project", "pass: 1" + ".2.3.4",
    "Authorization: Basic " + "dXNlcjpw" + "YXNz",
    "PWD=/home/" + "x/project", "pwd=$PWD", "pwd: ~/work", "pass: abc", "token = abcdefg",
    "secret: short1", "password = 'abcde'", "Authorization: Basic short",
    "seed SUA" + "a" * 55, "compass: northwest", "bypass = enabled1",
])
def test_the_near_shapes_stay_quiet(line):
    assert secrets(line) == []


@pytest.mark.parametrize("suffix", [".c", ".h", ".cpp", ".hpp", ".ex", ".swift", ".scala"])
def test_an_unquoted_name_in_compiled_code_is_not_a_literal(suffix):
    assert secrets("Auth Token: fake_token", suffix) == []
    assert secrets("password = options.password", suffix) == []
    assert secrets("pass = argv[1];", suffix) == []
    assert secrets("password = get(1);", suffix) == []
    assert secrets("password = a.b[2];", suffix) == []
    assert secrets('token = "Zq9w' + 'Xk7pLmN2"', suffix) == ["secret"]
    assert secrets("password = V1" + "0abc;", suffix) == ["secret"]
    assert secrets("# password=V1" + "0abc", suffix) == ["secret"]
