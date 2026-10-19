"""Smoke tests for the corvid-sweep CLI."""

import sys

import pytest

from corvid_sweep import __version__
from corvid_sweep.cli import main


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
