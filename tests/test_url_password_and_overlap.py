"""A hit that overlaps a secret must not print any part of it, whatever its class."""
import json

from publish_gate import cli
from publish_gate.classes import Terms, scan_line

NONE = Terms([], [])
PW = "Zx9Qw7" + "Lm2Rt5"


def test_a_url_password_is_not_printed_by_the_email_class():
    line = f"DATABASE_URL=postgres://admin:{PW}@db.corp.io:5432/app"
    shown = [t for _, t in scan_line(line, NONE)]
    assert shown
    assert not any(PW in t for t in shown), shown
    assert "email" in {c for c, _ in scan_line(line, NONE)}   # still reported, just masked


def test_no_output_format_prints_the_url_password(tmp_path, capsys):
    (tmp_path / "config.txt").write_text(f"postgres://admin:{PW}@db.corp.io:5432/app\n")
    for fmt in ("text", "json", "sarif"):
        cli.main([str(tmp_path), "--no-denylist", "--format", fmt])
        out = capsys.readouterr()
        assert PW not in out.out + out.err, fmt


def test_an_address_beside_a_secret_is_still_shown():
    addr = "ops" + "@corp.io"  # split, so this file does not trip the gate it tests
    line = f"mail {addr} and postgres://admin:{PW}@db.corp.io/app"
    shown = [t for c, t in scan_line(line, NONE) if c == "email"]
    assert addr in shown
