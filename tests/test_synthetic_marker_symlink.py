"""A SYNTHETIC-DATA symlink is judged as a link and never followed."""
import os

import pytest
from publish_gate import scan
from publish_gate.classes import Terms

NONE = Terms([], [])


def test_a_dangling_marker_link_does_not_crash(tmp_path):
    (tmp_path / "a.txt").write_text("hi\n")
    os.symlink("/nonexistent/x", tmp_path / "SYNTHETIC-DATA")
    scan.scan_tree(tmp_path, NONE)          # a traceback here is the bug


def test_a_marker_link_to_a_device_is_not_read(tmp_path):
    (tmp_path / "a.txt").write_text("hi\n")
    os.symlink("/dev/zero", tmp_path / "SYNTHETIC-DATA")
    scan.scan_tree(tmp_path, NONE)          # an unbounded read here is the bug


def test_a_marker_link_outside_the_tree_does_not_declare_synthetic(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "marker").write_text("synthetic: true\n")
    tree = tmp_path / "tree"
    (tree / "d").mkdir(parents=True)
    (tree / "d" / "real.db").write_bytes(b"x")
    os.symlink(out / "marker", tree / "d" / "SYNTHETIC-DATA")
    res = scan.scan_tree(tree, NONE)
    assert "synthetic-data" not in {f.cls for f in res.findings}
    assert "agent-state" in {f.cls for f in res.findings}


def test_a_real_marker_still_works(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "SYNTHETIC-DATA").write_text("synthetic: true\n")
    (tmp_path / "d" / "real.db").write_bytes(b"x")
    res = scan.scan_tree(tmp_path, NONE)
    assert "synthetic-data" in {f.cls for f in res.findings}
