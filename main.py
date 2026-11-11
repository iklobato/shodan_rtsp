import logging
import os
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Callable
from typing import Any

from models.base import InvalidEntity
from models.managers import AppearanceFilters, PersonReader
from scanners.brand_probe import BrandBook, Identifier
from scanners.config import AppConfig, NmapConfig, ShodanConfig, load_config
from scanners.face_recognizer import (
    FaceRecognizer,
    PairSet,
    PairSetError,
    ThresholdMeasurement,
)
from scanners.face_task import FaceScanDeps, FaceScanTask
from scanners.frames import FrameWriteFailed
from scanners.reports import (
    Boundary,
    PersonReport,
    ReportDeps,
    Runnable,
    SearchReport,
    StdoutLines,
    ThresholdReport,
    TimestampNotParsed,
)
from scanners.task import (
    CheckDeps,
    CheckTask,
    NmapTask,
    ShodanDeps,
    ShodanTask,
    TargetOutsideScopeError,
    UnknownCameraError,
)
from scanners.vuln_task import CveDeps, CveTask

__version__ = "0.1.0"

# The exit code of a run that could not do its job (contracts/cli.md). Exit 2 is
# argparse's own, for a command line that is wrong.
_FAILURE_EXIT = 1

# The refusals of this project: a value the operator can fix, reported as the
# message the exception carries. Anything else is a bug and keeps its traceback.
_REFUSALS = (
    InvalidEntity,
    FrameWriteFailed,
    PairSetError,
    TargetOutsideScopeError,
    TimestampNotParsed,
    UnknownCameraError,
)


class TaskFactory:
    """Builds the task of one registered command from the config."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def build_nmap(self, arguments: Namespace) -> NmapTask:
        """The nmap task, over the target given or the configured range."""
        return NmapTask(self._nmap_config(arguments.argument), self._identifier())

    def build_shodan(self, arguments: Namespace) -> ShodanTask:
        return ShodanTask(
            ShodanDeps(
                config=self._shodan_config(arguments.argument),
                targets=self._config.targets,
                identifier=self._identifier(),
            )
        )

    def build_check(self, arguments: Namespace) -> CheckTask:
        return CheckTask(
            CheckDeps(
                config=self._config.checkers,
                targets=self._config.targets,
                identifier=self._identifier(),
                camera_id=arguments.camera_id,
            )
        )

    def build_cve(self, arguments: Namespace) -> CveTask:
        """The CVE task, over every camera waiting for a frame or the named one."""
        return CveTask(
            CveDeps(
                config=self._config.vuln,
                frames=self._config.frames,
                targets=self._config.targets,
                camera_id=arguments.camera_id,
            )
        )

    def build_faces(self, arguments: Namespace) -> FaceScanTask:
        """The face scan, over every camera holding a frame or the named one."""
        return FaceScanTask(
            FaceScanDeps(
                config=self._config.face,
                frames=self._config.frames,
                targets=self._config.targets,
                camera_id=arguments.camera_id,
            )
        )

    def build_report_faces(self, arguments: Namespace) -> PersonReport:
        """What the face scan found, for one person or for all of them."""
        return PersonReport(
            self._report_deps(AppearanceFilters(person_id=arguments.person_id))
        )

    def build_search(self, arguments: Namespace) -> SearchReport:
        """Who appeared, where and when, narrowed by whatever was given."""
        return SearchReport(
            self._report_deps(
                AppearanceFilters(
                    person_id=arguments.person_id,
                    camera_id=arguments.camera_id,
                    since=Boundary.parsed(arguments.since),
                    until=Boundary.parsed(arguments.until),
                )
            )
        )

    def build_threshold(self, arguments: Namespace) -> ThresholdReport:
        """The measurement, over the pair set the option or the config names."""
        return ThresholdReport(
            ThresholdMeasurement(
                FaceRecognizer(self._config.face),
                PairSet(arguments.pairs or self._config.face.pairs_path),
            ),
            StdoutLines(),
        )

    def _report_deps(self, filters: AppearanceFilters) -> ReportDeps:
        """What both read-only reports need: the reader, the lines, the narrowing."""
        return ReportDeps(people=PersonReader(), lines=StdoutLines(), filters=filters)

    def _identifier(self) -> Identifier:
        """The brand book, read from the configured file, once per command."""
        return Identifier(BrandBook.load(self._config.brands.signature_path))

    def _nmap_config(self, target: str | None) -> NmapConfig:
        if target is None:
            return self._config.nmap
        return self._config.nmap.model_copy(update={"ip_range": target})

    def _shodan_config(self, query: str | None) -> ShodanConfig:
        if query is None:
            return self._config.shodan
        return self._config.shodan.model_copy(update={"query": query})


class CommandLine:
    """Dispatches the parsed command line to the command it names (D34, D38)."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def execute(self, arguments: Namespace) -> None:
        """Run the command the command line asks for."""
        self._commands()[self._key(arguments)](arguments).run()

    @classmethod
    def _key(cls, arguments: Namespace) -> str:
        """The group and the command as one key: `scan nmap`, `search` (D38)."""
        parts = (arguments.group, getattr(arguments, "command", ""))
        return " ".join(part for part in parts if part)

    def _commands(self) -> dict[str, Callable[[Namespace], Runnable]]:
        factory = TaskFactory(self._config)
        return {
            "scan nmap": factory.build_nmap,
            "scan shodan": factory.build_shodan,
            "scan check": factory.build_check,
            "scan cve": factory.build_cve,
            "scan faces": factory.build_faces,
            "report faces": factory.build_report_faces,
            "search": factory.build_search,
            "measure threshold": factory.build_threshold,
        }


class CommandParser:
    """The command line surface of `contracts/cli.md`, group by group.

    `groups` is the action `add_subparsers` returns, whose public name argparse
    does not expose, so it is typed as Any at the four places that take one.
    """

    @classmethod
    def parsed(cls) -> Namespace:
        """The command line, parsed and validated by argparse itself."""
        parser = cls._root()
        groups = parser.add_subparsers(dest="group", required=True)
        cls._scan(groups)
        cls._report(groups)
        cls._search(groups)
        cls._measure(groups)
        return parser.parse_args()

    @classmethod
    def _root(cls) -> ArgumentParser:
        parser = ArgumentParser(description="Camera Scanner")
        parser.add_argument(
            "--config",
            action="store",
            help="Path to the configuration file",
            default="config.yaml",
        )
        parser.add_argument(
            "-v", "--verbose", action="store_true", help="Verbose mode", default=False
        )
        return parser

    @classmethod
    def _scan(cls, groups: Any) -> None:
        """The commands that reach a device and write what they saw."""
        commands = cls._group(groups, "scan", "Scans that write to the database")
        cls._found(commands)
        cls._framed(commands)

    @classmethod
    def _found(cls, commands: Any) -> None:
        """The two commands that find cameras and store them."""
        commands.add_parser(
            "nmap", help="Find cameras on a range with nmap"
        ).add_argument(
            "argument", nargs="?", help="CIDR to scan; defaults to nmap.ip_range"
        )
        commands.add_parser(
            "shodan", help="Find cameras through the Shodan API"
        ).add_argument(
            "argument", nargs="?", help="Shodan query; defaults to shodan.query"
        )

    @classmethod
    def _framed(cls, commands: Any) -> None:
        """The three commands that go back to a camera to obtain a frame."""
        waiting = "every camera waiting for a frame"
        cls._with_camera_id(
            commands.add_parser(
                "check", help="Try credentials against the stored cameras"
            ),
            waiting,
        )
        cls._with_camera_id(
            commands.add_parser("cve", help="Read a camera through the CVE classes"),
            waiting,
        )
        cls._with_camera_id(
            commands.add_parser(
                "faces", help="Detect faces and cluster them into people"
            ),
            "every camera holding a frame",
        )

    @classmethod
    def _report(cls, groups: Any) -> None:
        """The commands that only read what is already stored."""
        commands = cls._group(groups, "report", "Read-only reports")
        commands.add_parser(
            "faces", help="What the face scan found, person by person"
        ).add_argument(
            "--person-id",
            type=int,
            default=None,
            help="Only this person; defaults to every person stored",
        )

    @classmethod
    def _search(cls, groups: Any) -> None:
        """Who appeared, where and when: the monitoring answer (FR-027)."""
        search = groups.add_parser("search", help="Who appeared, where and when")
        search.add_argument(
            "--person-id", type=int, default=None, help="Only this person"
        )
        search.add_argument(
            "--camera-id", type=int, default=None, help="Only this camera"
        )
        search.add_argument(
            "--since",
            default=None,
            help="Only appearances at or after this instant (ISO 8601, read as UTC)",
        )
        search.add_argument(
            "--until",
            default=None,
            help="Only appearances at or before this instant (ISO 8601, read as UTC)",
        )

    @classmethod
    def _measure(cls, groups: Any) -> None:
        """The measurements: they read a labelled set, and they write nothing."""
        commands = cls._group(groups, "measure", "Measurements that write nothing")
        commands.add_parser(
            "threshold", help="Measure the face match threshold on a pair set"
        ).add_argument(
            "--pairs",
            default=None,
            help="Directory of identities; defaults to face.pairs_path",
        )

    @classmethod
    def _group(cls, groups: Any, name: str, description: str) -> Any:
        """One group of commands, and the action its own commands hang off."""
        return groups.add_parser(name, help=description).add_subparsers(
            dest="command", required=True
        )

    @classmethod
    def _with_camera_id(cls, parser: Any, default_help: str) -> None:
        """The one option `scan check`, `scan cve` and `scan faces` share."""
        parser.add_argument(
            "--camera-id",
            type=int,
            default=0,
            help=f"Restrict the run to one camera id; defaults to {default_help}",
        )


def _configure_logging(verbose: bool) -> None:
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler("logs/rtsp_scanner.log"),
            logging.StreamHandler(),
        ],
    )


def main():
    args = CommandParser.parsed()
    _configure_logging(args.verbose)
    if args.verbose:
        logging.info("Verbose mode enabled")
    try:
        CommandLine(load_config(args.config)).execute(args)
    except _REFUSALS as refused:
        logging.error("%s", refused)
        sys.exit(_FAILURE_EXIT)


if __name__ == "__main__":
    main()
