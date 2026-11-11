"""A name of several words is found when a line wrap splits it (the scan reads one line at a time,
so "Example\nIndustries" in prose passed as clean). Any joining on one line was already found."""
from publish_gate import cli, scan
from publish_gate.classes import Terms


def findings(text, block=("Example Industries",), review=()):
    res = scan.Result()
    scan._scan_text("f.md", text, Terms(list(block), list(review)), ".md", res)
    return [(f.cls, f.shown, f.line) for f in res.findings]


def test_a_block_name_split_by_a_line_wrap_is_found_once_on_the_first_line():
    assert findings("we worked for Example\nIndustries last year\n") == [
        ("denylist", "Example Industries", 1)]
    assert findings("Example-\nIndustries\n") == [("denylist", "Example- Industries", 1)]


def test_a_review_name_split_by_a_wrap_is_a_review_finding():
    assert findings("ask Example\nIndustries\n", block=(), review=("Example Industries",)) == [
        ("review-term", "Example Industries", 1)]


def test_a_name_wholly_inside_one_line_is_not_counted_twice():
    assert findings("Example Industries\nnext line\n") == [("denylist", "Example Industries", 1)]
    assert findings("first\nExample Industries\n") == [("denylist", "Example Industries", 2)]


def test_words_that_only_meet_across_a_blank_line_or_far_apart_are_not_joined():
    assert findings("Example\n\nIndustries\n") == []
    assert findings("Example\nnothing Industries\n") == []


def test_one_word_names_are_unchanged():
    assert findings("Zorb\nlax\n", block=("Zorblax",)) == []


def test_the_cli_fails_on_a_wrapped_name(tmp_path):
    (tmp_path / "n.md").write_text("built for Example\nIndustries\n")
    dl = tmp_path.parent / (tmp_path.name + "-dl")
    dl.write_text("Example Industries\n")
    assert cli.main([str(tmp_path), "--denylist", str(dl)]) == 1
