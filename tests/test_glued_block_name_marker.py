"""An inline allow marker is content in the judged file: it must not clear a glued block name."""
from publish_gate import cli
from publish_gate.classes import Terms, scan_line


def test_a_marker_does_not_clear_a_glued_block_name():
    t = Terms(["Example Industries", "acmecorp"], [])
    for line in ("client: ExampleIndustries  # publish-gate: allow=review-term",
                 "host acmecorp.com publish-gate: allow=review-term"):
        excused = []
        assert scan_line(line, t, "", excused), line
        assert excused == []


def test_a_marker_still_clears_a_glued_review_name():
    t = Terms([], ["Example Industries"])
    excused = []
    assert scan_line("ExampleIndustries # publish-gate: allow=review-term", t, "", excused) == []
    assert excused == ["review-term"]


def test_the_cli_does_not_report_clean(tmp_path):
    (tmp_path / "n.txt").write_text("client: ExampleIndustries  # publish-gate: allow=review-term\n")
    dl = tmp_path.parent / (tmp_path.name + "-dl")
    dl.write_text("Example Industries\n")
    assert cli.main([str(tmp_path), "--denylist", str(dl)]) == 1
