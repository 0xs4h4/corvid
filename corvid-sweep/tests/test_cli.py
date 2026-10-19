"""Smoke tests for the corvid-sweep CLI."""

import sys

import pytest

from corvid_sweep import __version__
from corvid_sweep.cli import (count_open_ports, create_run_folder, fix_output_ownership,
                              give_back, main)


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


def test_create_run_folder_names_and_increments(tmp_path):
    first = create_run_folder(tmp_path, date="20261019")
    second = create_run_folder(tmp_path, date="20261019")
    assert first.name == "corvid-sweep-20261019-1"
    assert second.name == "corvid-sweep-20261019-2"


def test_count_open_ports():
    records = [
        {"target": "10.0.0.1", "scans": [("tcp", {"ports": [22, 80]})]},
        {"target": "10.0.0.2", "scans": [("tcp", {"ports": []})]},
    ]
    assert count_open_ports(records) == 2
    assert count_open_ports([{"target": "x", "scans": []}]) == 0
