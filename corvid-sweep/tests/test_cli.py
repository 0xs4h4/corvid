"""Smoke tests for the corvid-sweep CLI."""

import sys

import pytest

from corvid_sweep import __version__
from corvid_sweep.cli import fix_output_ownership, give_back, main


def test_help_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["corvid-sweep", "--help"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--targets" in out
    assert "--resume" in out


def test_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["corvid-sweep", "--version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_missing_targets_file_errors(monkeypatch, tmp_path, capsys):
    missing = tmp_path / "nope.txt"
    monkeypatch.setattr(sys, "argv", ["corvid-sweep", "-i", str(missing)])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code != 0


def test_fix_output_ownership_noop_for_non_root(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text("x")
    fix_output_ownership(tmp_path)          # must not raise as a normal user
    assert report.read_text() == "x"


def test_give_back_noop_for_non_root(tmp_path):
    out = tmp_path / "runs"
    out.mkdir()
    give_back(out)                          # must not raise without SUDO_UID
    assert out.is_dir()
