"""The database address comes from DATABASE_HOST when it is set.

A run on the host reaches the published port, a run in a container reaches the
service name, and everything else in the file stays the same.
"""

from pathlib import Path

import pytest

from scanners.config import load_config

_CONFIG_NAME = "config.yaml"
_ENV_NAME = "DATABASE_HOST"
_FILE_HOST = "127.0.0.1:5440"
_CONTAINER_HOST = "postgres:5432"
_CONFIG_TEXT = (
    "shodan:\n"
    "  api_key: lab\n"
    "checkers:\n"
    "  wordlist_users: users.txt\n"
    "  wordlist_passwords: passwords.txt\n"
    "  wordlist_rtsp_urls: urls.txt\n"
    "nmap:\n"
    "  ip_range: 127.0.0.1/32\n"
    "targets:\n"
    "  allowed_cidrs: [\"127.0.0.1/32\"]\n"
    "database:\n"
    "  user: lab\n"
    "  password: lab\n"
    f"  host: {_FILE_HOST}\n"
    "  db: lab\n"
)


class ConfigFile:
    """The config a run reads, written once per test."""

    @classmethod
    def written(cls, directory: Path) -> str:
        path = directory / _CONFIG_NAME
        path.write_text(_CONFIG_TEXT)
        return str(path)


def test_the_environment_host_wins_over_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_ENV_NAME, _CONTAINER_HOST)
    config = load_config(ConfigFile.written(tmp_path))

    assert config.database.host == _CONTAINER_HOST


def test_the_file_host_stands_when_the_environment_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_ENV_NAME, raising=False)
    config = load_config(ConfigFile.written(tmp_path))

    assert config.database.host == _FILE_HOST


def test_the_rest_of_the_file_is_untouched_by_the_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ranges and the credentials are the ones in the file, not defaults."""
    monkeypatch.setenv(_ENV_NAME, _CONTAINER_HOST)
    config = load_config(ConfigFile.written(tmp_path))

    assert config.database.db == "lab"
    assert config.database.user == "lab"
    assert config.targets.allowed_cidrs == ["127.0.0.1/32"]
