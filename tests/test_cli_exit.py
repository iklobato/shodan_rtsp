"""The command line exits 1 on a refusal and 2 on a bad command line (cli.md).

A refusal is a value the operator can fix, and it is reported as the message the
exception carries: the run exits 1 instead of dying with a traceback.
"""

import sys
from pathlib import Path

import pytest

import main

_FAILURE_EXIT = 1
_ARGUMENT_EXIT = 2
_CONFIG_NAME = "config.yaml"
_MISSING_PAIRS = "no-such-pairs"
_NOT_A_TIMESTAMP = "yesterday"
_CONFIG_TEXT = (
    "shodan:\n"
    "  api_key: lab\n"
    "checkers:\n"
    "  wordlist_users: users.txt\n"
    "  wordlist_passwords: passwords.txt\n"
    "  wordlist_rtsp_urls: urls.txt\n"
    "nmap:\n"
    "  ip_range: 127.0.0.1/32\n"
    "database:\n"
    "  user: lab\n"
    "  password: lab\n"
    "  host: 127.0.0.1\n"
    "  db: lab\n"
)
_THRESHOLD_COMMAND: tuple[str, ...] = ("measure", "threshold")
_SEARCH_COMMAND: tuple[str, ...] = ("search",)


class Invocation:
    """One run of main() from a temporary directory that holds the config."""

    @classmethod
    def prepared(cls, directory: Path) -> str:
        """Write the config the run reads, and hand back its path."""
        path = directory / _CONFIG_NAME
        path.write_text(_CONFIG_TEXT)
        return str(path)

    @classmethod
    def exit_code_of(
        cls, monkeypatch: pytest.MonkeyPatch, directory: Path, argv: tuple[str, ...]
    ) -> int:
        """Call main() with that command line, and hand back the exit code."""
        monkeypatch.chdir(directory)
        monkeypatch.setattr(sys, "argv", list(argv))
        with pytest.raises(SystemExit) as stopped:
            main.main()
        return stopped.value.code


def test_a_pair_set_that_is_not_a_directory_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = Invocation.prepared(tmp_path)
    argv = (
        "main.py",
        "--config",
        config,
        *_THRESHOLD_COMMAND,
        "--pairs",
        str(tmp_path / _MISSING_PAIRS),
    )

    assert Invocation.exit_code_of(monkeypatch, tmp_path, argv) == _FAILURE_EXIT


def test_a_since_that_is_not_a_timestamp_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = Invocation.prepared(tmp_path)
    argv = (
        "main.py",
        "--config",
        config,
        *_SEARCH_COMMAND,
        "--since",
        _NOT_A_TIMESTAMP,
    )

    assert Invocation.exit_code_of(monkeypatch, tmp_path, argv) == _FAILURE_EXIT


def test_a_command_line_without_a_command_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """argparse's own code for a command line that is wrong, never a refusal."""
    Invocation.prepared(tmp_path)

    assert (
        Invocation.exit_code_of(monkeypatch, tmp_path, ("main.py",)) == _ARGUMENT_EXIT
    )
