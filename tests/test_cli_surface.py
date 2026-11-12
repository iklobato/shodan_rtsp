"""The command tree of D72, and the two global options of D71.

The suite goes through the real parser, so a rename that forgets the dispatch
table or a group that stops taking `--config` fails here.
"""

import sys

import pytest

import main

_CONFIG_AFTER = "target list --config /tmp/lab.yaml"
_VERBOSE_FIRST = "-v scan faces"
_DEFAULT_CONFIG = "config.yaml"
_ARGUMENT_EXIT = 2

# Every command of the tree, with the arguments argparse needs to accept it.
_COMMAND_LINES = (
    "find nmap 10.0.0.0/24",
    "find shodan net:10.0.0.0/24",
    "scan credentials",
    "scan credentials --camera-id 7",
    "scan vulns",
    "scan faces",
    "report faces",
    "report faces --person-id 3",
    "search appearance --since 2026-11-11T00:00:00Z",
    "search person",
    "search person --name maria",
    "search person --image photo.jpg --name maria",
    "target add --name maria --image photo.jpg",
    "target list",
    "target remove maria",
    "measure threshold",
)

# The names the surface carried before this batch: none of them survives (D69).
_OLD_LINES = (
    "scan nmap 10.0.0.0/24",
    "scan shodan net:10.0.0.0/24",
    "scan check",
    "scan cve",
    "search person --forget 1",
)


class Parsed:
    """One command line through the parser that main() uses."""

    @classmethod
    def of(cls, monkeypatch: pytest.MonkeyPatch, line: str) -> object:
        monkeypatch.setattr(sys, "argv", ["main.py", *line.split()])
        return main.CommandParser.parsed()


@pytest.mark.parametrize("line", _OLD_LINES)
def test_the_old_names_are_refused(line: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """D69: no alias, so an old command line stops at argparse with exit 2."""
    with pytest.raises(SystemExit) as stopped:
        Parsed.of(monkeypatch, line)

    assert stopped.value.code == _ARGUMENT_EXIT


def test_every_command_of_the_tree_is_dispatched(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tree parses, and the dispatch table knows all of its lines."""
    dispatched = {
        main.CommandLine._key(Parsed.of(monkeypatch, line)) for line in _COMMAND_LINES
    }

    assert dispatched == {
        "find nmap",
        "find shodan",
        "scan credentials",
        "scan vulns",
        "scan faces",
        "report faces",
        "search appearance",
        "search person",
        "target add",
        "target list",
        "target remove",
        "measure threshold",
    }


def test_a_config_after_the_command_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """D71: the value used to be unreadable anywhere but before the group."""
    assert Parsed.of(monkeypatch, _CONFIG_AFTER).config == "/tmp/lab.yaml"


def test_a_verbose_before_the_group_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    assert Parsed.of(monkeypatch, _VERBOSE_FIRST).verbose is True


def test_the_config_default_survives_the_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """The groups suppress the default, so the root one is the only one left."""
    parsed = Parsed.of(monkeypatch, "target list")

    assert parsed.config == _DEFAULT_CONFIG
    assert parsed.verbose is False


def test_target_add_without_a_name_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit) as stopped:
        Parsed.of(monkeypatch, "target add --image photo.jpg")

    assert stopped.value.code == _ARGUMENT_EXIT


def test_target_remove_without_a_target_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SystemExit) as stopped:
        Parsed.of(monkeypatch, "target remove")

    assert stopped.value.code == _ARGUMENT_EXIT
