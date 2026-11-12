import logging
import os
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from models.base import InvalidEntity
from models.managers import (
    AppearanceFilters,
    PersonReader,
    PersonRepository,
    TargetHitRepository,
    TargetReader,
    TargetRepository,
)
from scanners.brand_probe import BrandBook, Identifier
from scanners.config import AppConfig, NmapConfig, ShodanConfig, load_config
from scanners.face_recognizer import (
    FaceRecognizer,
    PairSet,
    PairSetError,
    ThresholdMeasurement,
)
from scanners.face_task import FaceScanDeps, FaceScanTask
from scanners.frames import FrameStore, FrameWriteFailed
from scanners.reports import (
    Boundary,
    ForgetTargetCommand,
    PersonReport,
    ReportDeps,
    Runnable,
    SearchPersonCommand,
    SearchPersonDeps,
    SearchReport,
    StdoutLines,
    TargetRankingReport,
    TargetThreshold,
    ThresholdReport,
    TimestampNotParsed,
)
from scanners.target_search import (
    ReferencePhotoError,
    ReferencePhotoReader,
    RegistrationDeps,
    RemovalDeps,
    TargetRegistration,
    TargetRemoval,
    TargetSearch,
    TargetSearchDeps,
    UnknownTargetError,
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
_USAGE_EXIT = 2

# The refusals of this project: a value the operator can fix, reported as the
# message the exception carries. Anything else is a bug and keeps its traceback.
_REFUSALS = (
    InvalidEntity,
    FrameWriteFailed,
    PairSetError,
    ReferencePhotoError,
    TargetOutsideScopeError,
    TimestampNotParsed,
    UnknownCameraError,
    UnknownTargetError,
)


class UsageError(Exception):
    """A combination argparse cannot refuse alone: the command line is wrong."""


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
        filters = AppearanceFilters(person_id=arguments.person_id)
        return PersonReport(
            replace(
                self._report_deps(filters),
                targets=TargetReader().matches_of(filters.person_id),
            )
        )

    def build_search_appearance(self, arguments: Namespace) -> SearchReport:
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

    def build_search_person(self, arguments: Namespace) -> Runnable:
        """The named target search, or the removal of a target (D52, D64)."""
        return TargetFactory(self._config).build(arguments)

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


class TargetFactory:
    """Builds the two commands of `search person` from the config (D52, D64)."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def build(self, arguments: Namespace) -> Runnable:
        """The removal when `--forget` is set, the search otherwise."""
        if arguments.forget is not None:
            self._require_alone(arguments)
            return self._forget_command(arguments.forget)
        return SearchPersonCommand(
            SearchPersonDeps(
                registration=self._registration(),
                search=TargetSearch(self._search_deps(arguments)),
                report=TargetRankingReport(
                    StdoutLines(),
                    TargetThreshold(self._config.person_search.match_threshold),
                    self._scope_of(arguments),
                ),
                name=self._target_name(arguments),
                images=tuple(arguments.image),
                live=self._live_scan(arguments),
            )
        )

    def _registration(self) -> TargetRegistration:
        """What registers a reference photo: the reader, the table, the files."""
        return TargetRegistration(
            RegistrationDeps(
                reader=ReferencePhotoReader(FaceRecognizer(self._config.face)),
                targets=TargetRepository(),
                frames=FrameStore(self._config.frames.root_path),
            )
        )

    def _forget_command(self, target_id: int) -> ForgetTargetCommand:
        return ForgetTargetCommand(
            TargetRemoval(
                RemovalDeps(
                    targets=TargetRepository(),
                    people=PersonRepository(),
                    frames=FrameStore(self._config.frames.root_path),
                )
            ),
            StdoutLines(),
            target_id,
        )

    def _search_deps(self, arguments: Namespace) -> TargetSearchDeps:
        """The tables and the narrowing of one `search person` run (D65)."""
        return TargetSearchDeps(
            faces=TargetReader(),
            targets=TargetRepository(),
            hits=TargetHitRepository(),
            people=PersonRepository(),
            threshold=self._config.person_search.match_threshold,
            filters=AppearanceFilters(
                camera_id=arguments.camera_id,
                since=Boundary.parsed(arguments.since),
                until=Boundary.parsed(arguments.until),
            ),
            target_id=arguments.target_id,
        )

    def _live_scan(self, arguments: Namespace) -> FaceScanTask | None:
        """The face scan `--live` runs first, over the cameras the run names (D61).

        None without the flag: no run reaches a camera unless the operator asked
        for it, and that scan carries the `targets.allowed_cidrs` gate itself.
        """
        if not arguments.live:
            return None
        return FaceScanTask(
            FaceScanDeps(
                config=self._config.face,
                frames=self._config.frames,
                targets=self._config.targets,
                camera_id=arguments.camera_id or 0,
            )
        )

    def _target_name(self, arguments: Namespace) -> str:
        """The name a registration needs, refused when a photo came without one."""
        if arguments.image and not arguments.name:
            raise UsageError("--name is required with --image")
        return (arguments.name or "").strip()

    def _scope_of(self, arguments: Namespace) -> str:
        """What the report names when nothing matched: the target or every one."""
        if arguments.target_id is not None:
            return f"target {arguments.target_id}"
        if arguments.name:
            return f"target {arguments.name}"
        return "any target"

    def _require_alone(self, arguments: Namespace) -> None:
        """`--forget` removes a target, so it cannot carry a search as well."""
        combined = (
            arguments.image
            or arguments.target_id is not None
            or arguments.live
            or arguments.camera_id is not None
            or arguments.since
            or arguments.until
        )
        if combined:
            raise UsageError("--forget removes one target and takes no search options")


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
            "search appearance": factory.build_search_appearance,
            "search person": factory.build_search_person,
            "measure threshold": factory.build_threshold,
        }


class SearchParser:
    """The `search` group: a named target, and who appeared where (D52).

    `search` is a group of two commands, so the old one-command surface moved to
    `search appearance` unchanged (contracts/cli.md).
    """

    @classmethod
    def add(cls, groups: Any) -> None:
        commands = groups.add_parser("search", help="Searches that only read")
        commands = commands.add_subparsers(dest="command", required=True)
        cls._appearance(commands)
        cls._person(commands)

    @classmethod
    def _appearance(cls, commands: Any) -> None:
        """Who appeared, where and when: the monitoring answer (FR-027)."""
        appearance = commands.add_parser(
            "appearance", help="Who appeared, where and when"
        )
        appearance.add_argument(
            "--person-id", type=int, default=None, help="Only this person"
        )
        cls._narrowing(appearance)

    @classmethod
    def _person(cls, commands: Any) -> None:
        """Search a named target, or remove it: one verb, two forms (D52)."""
        person = commands.add_parser(
            "person", help="Search a named target, or remove one with --forget"
        )
        cls._target_options(person)
        cls._narrowing(person)
        person.add_argument(
            "--live",
            action="store_true",
            default=False,
            help="Scan the cameras first; without it no camera is contacted",
        )

    @classmethod
    def _target_options(cls, person: Any) -> None:
        """The three forms of `search person`, and the name a photo needs."""
        person.add_argument(
            "--image",
            action="append",
            default=[],
            metavar="PATH",
            help="Reference photo; repeatable, and it registers or adds to --name",
        )
        person.add_argument(
            "--name", default=None, help="Target name; required with --image"
        )
        cls._target_ids(person)

    @classmethod
    def _target_ids(cls, person: Any) -> None:
        """The two id forms: one target to search, or one to remove."""
        person.add_argument(
            "--target-id",
            type=int,
            default=None,
            help="An already registered target; defaults to every target",
        )
        person.add_argument(
            "--forget",
            type=int,
            default=None,
            metavar="N",
            help="Remove target N with its photos, hits and the label it wrote",
        )

    @classmethod
    def _narrowing(cls, parser: Any) -> None:
        """The camera and the two instants both searches narrow on (D65)."""
        parser.add_argument(
            "--camera-id", type=int, default=None, help="Only this camera"
        )
        parser.add_argument(
            "--since",
            default=None,
            help="Only appearances at or after this instant (ISO 8601, read as UTC)",
        )
        parser.add_argument(
            "--until",
            default=None,
            help="Only appearances at or before this instant (ISO 8601, read as UTC)",
        )


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
        """The searches: a named target, and who appeared where (FR-027, D52)."""
        SearchParser.add(groups)

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
    except UsageError as wrong:
        logging.error("%s", wrong)
        sys.exit(_USAGE_EXIT)
    except _REFUSALS as refused:
        logging.error("%s", refused)
        sys.exit(_FAILURE_EXIT)


if __name__ == "__main__":
    main()
