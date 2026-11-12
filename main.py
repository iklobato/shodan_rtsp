import logging
import os
import sys
from argparse import SUPPRESS, ArgumentParser, Namespace
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from models.base import InvalidEntity
from models.managers import (
    AppearanceFilters,
    PersonReader,
    PersonRepository,
    TargetHitRepository,
    TargetListReader,
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
    AddTargetCommand,
    AddTargetDeps,
    Boundary,
    PersonReport,
    RemoveTargetCommand,
    RemoveTargetDeps,
    ReportDeps,
    Runnable,
    SearchPersonCommand,
    SearchPersonDeps,
    SearchReport,
    StdoutLines,
    TargetListingReport,
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
    TargetSelection,
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


class RegistrationBuilder:
    """The one registration `target add` and `search person --image` share."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def build(self) -> TargetRegistration:
        """The photo reader, the target table and the file store."""
        return TargetRegistration(
            RegistrationDeps(
                reader=ReferencePhotoReader(FaceRecognizer(self._config.face)),
                targets=TargetRepository(),
                frames=FrameStore(self._config.frames.root_path),
            )
        )


class ReportDepsBuilder:
    """What both read-only commands need: the reader, the lines, the narrowing."""

    @classmethod
    def of(cls, filters: AppearanceFilters) -> ReportDeps:
        """The deps one read-only command renders its lines from."""
        return ReportDeps(people=PersonReader(), lines=StdoutLines(), filters=filters)


class ScanFactory:
    """Builds the commands that reach a stored camera and write what they saw."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def build_nmap(self, arguments: Namespace) -> NmapTask:
        """The nmap task, over the target given or the configured range."""
        return NmapTask(self._nmap_config(arguments.argument), self._identifier())

    def build_shodan(self, arguments: Namespace) -> ShodanTask:
        """The Shodan task, over the query given or the configured one."""
        return ShodanTask(
            ShodanDeps(
                config=self._shodan_config(arguments.argument),
                targets=self._config.targets,
                identifier=self._identifier(),
            )
        )

    def build_credentials(self, arguments: Namespace) -> CheckTask:
        """The credential check, under the reach gate of `targets.allowed_cidrs`."""
        return CheckTask(
            CheckDeps(
                config=self._config.checkers,
                targets=self._config.targets,
                identifier=self._identifier(),
                camera_id=arguments.camera_id,
            )
        )

    def build_vulns(self, arguments: Namespace) -> CveTask:
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


class ReportFactory:
    """Builds the two commands that only read what is already stored."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def build_faces_report(self, arguments: Namespace) -> PersonReport:
        """What the face scan found, with the targets each person matches."""
        filters = AppearanceFilters(person_id=arguments.person_id)
        return PersonReport(
            replace(
                ReportDepsBuilder.of(filters),
                targets=TargetReader().matches_of(filters.person_id),
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


class SearchFactory:
    """Builds the two searches: who appeared, and one named target (D52, D74)."""

    def __init__(self, config: AppConfig, registration: RegistrationBuilder) -> None:
        self._config = config
        self._registration = registration

    def build_appearance(self, arguments: Namespace) -> SearchReport:
        """Who appeared, where and when, narrowed by whatever was given."""
        return SearchReport(
            ReportDepsBuilder.of(
                AppearanceFilters(
                    person_id=arguments.person_id,
                    camera_id=arguments.camera_id,
                    since=Boundary.parsed(arguments.since),
                    until=Boundary.parsed(arguments.until),
                )
            )
        )

    def build_person(self, arguments: Namespace) -> Runnable:
        """One named target, or every one: the search, and the live pass."""
        return SearchPersonCommand(
            SearchPersonDeps(
                registration=self._registration.build(),
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


class TargetFactory:
    """Builds `target add`, `target list` and `target remove` (D76, D79, D80)."""

    def __init__(self, config: AppConfig, registration: RegistrationBuilder) -> None:
        self._config = config
        self._registration = registration

    def build_add(self, arguments: Namespace) -> Runnable:
        """The registration of one name and its photos, and what it holds after."""
        return AddTargetCommand(
            AddTargetDeps(
                registration=self._registration.build(),
                targets=TargetRepository(),
                lines=StdoutLines(),
            ),
            arguments.name,
            tuple(arguments.image),
        )

    def build_list(self, arguments: Namespace) -> Runnable:
        """Every registered target, with its photo and hit counts (D80)."""
        return TargetListingReport(TargetListReader(), StdoutLines())

    def build_remove(self, arguments: Namespace) -> Runnable:
        """The removal of the target that argument names, by name or by id."""
        return RemoveTargetCommand(
            RemoveTargetDeps(
                selection=TargetSelection(TargetRepository()),
                removal=self._removal(),
                lines=StdoutLines(),
            ),
            arguments.target,
        )

    def _removal(self) -> TargetRemoval:
        """What one removal deletes: the target rows, the files, the labels."""
        return TargetRemoval(
            RemovalDeps(
                targets=TargetRepository(),
                people=PersonRepository(),
                frames=FrameStore(self._config.frames.root_path),
            )
        )


class CommandLine:
    """Dispatches the parsed command line to the command it names (D34, D38)."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def execute(self, arguments: Namespace) -> None:
        """Run the command the command line asks for."""
        self._commands()[self._key(arguments)](arguments).run()

    @classmethod
    def _key(cls, arguments: Namespace) -> str:
        """The group and the command as one key: `scan credentials` (D38)."""
        parts = (arguments.group, getattr(arguments, "command", ""))
        return " ".join(part for part in parts if part)

    def _commands(self) -> dict[str, Callable[[Namespace], Runnable]]:
        registration = RegistrationBuilder(self._config)
        scan = ScanFactory(self._config)
        report = ReportFactory(self._config)
        search = SearchFactory(self._config, registration)
        targets = TargetFactory(self._config, registration)
        return {
            "find nmap": scan.build_nmap,
            "find shodan": scan.build_shodan,
            "scan credentials": scan.build_credentials,
            "scan vulns": scan.build_vulns,
            "scan faces": scan.build_faces,
            "report faces": report.build_faces_report,
            "search appearance": search.build_appearance,
            "search person": search.build_person,
            "target add": targets.build_add,
            "target list": targets.build_list,
            "target remove": targets.build_remove,
            "measure threshold": report.build_threshold,
        }


class CommonOptions:
    """`--config` and `-v`, read before or after the command (D71)."""

    @classmethod
    def parent(cls) -> ArgumentParser:
        """A parent parser carrying both, whose suppressed defaults never win.

        The real defaults live on the root alone, so a value given before the
        group survives the group own parse.
        """
        parent = ArgumentParser(add_help=False)
        parent.add_argument(
            "--config", action="store", default=SUPPRESS, help="Configuration file"
        )
        parent.add_argument(
            "-v", "--verbose", action="store_true", default=SUPPRESS, help="Verbose"
        )
        return parent


class GroupParser:
    """The one way this CLI opens a group and one of its commands (D72)."""

    @classmethod
    def opened(cls, groups: Any, name: str, description: str) -> Any:
        """One group, and the action its own commands hang off."""
        parser = groups.add_parser(
            name, help=description, parents=[CommonOptions.parent()]
        )
        return parser.add_subparsers(dest="command", required=True)

    @classmethod
    def leaf(cls, commands: Any, name: str, description: str) -> Any:
        """One command of a group, which takes the two global options as well."""
        return commands.add_parser(
            name, help=description, parents=[CommonOptions.parent()]
        )


class FindParser:
    """The discovery commands: they store the cameras they find."""

    @classmethod
    def add(cls, groups: Any) -> None:
        commands = GroupParser.opened(groups, "find", "Discovery that stores cameras")
        cls._nmap(commands)
        cls._shodan(commands)

    @classmethod
    def _nmap(cls, commands: Any) -> None:
        found = GroupParser.leaf(
            commands, "nmap", "Find cameras on a range with nmap"
        )
        found.add_argument(
            "argument", nargs="?", help="CIDR to scan; defaults to nmap.ip_range"
        )

    @classmethod
    def _shodan(cls, commands: Any) -> None:
        found = GroupParser.leaf(
            commands, "shodan", "Find cameras through the Shodan API"
        )
        found.add_argument(
            "argument", nargs="?", help="Shodan query; defaults to shodan.query"
        )


class ScanParser:
    """The commands that go back to a camera already stored (D72)."""

    @classmethod
    def add(cls, groups: Any) -> None:
        commands = GroupParser.opened(
            groups, "scan", "Scans of the cameras already stored"
        )
        cls._credentials(commands)
        cls._vulns(commands)
        cls._faces(commands)

    @classmethod
    def _credentials(cls, commands: Any) -> None:
        """Try the credential sets against the cameras waiting for a frame."""
        command = GroupParser.leaf(
            commands, "credentials", "Try credentials against the stored cameras"
        )
        cls._camera_id(command, "every camera waiting for a frame")

    @classmethod
    def _vulns(cls, commands: Any) -> None:
        """Read a camera through the CVE classes, one match at a time."""
        command = GroupParser.leaf(
            commands, "vulns", "Read a camera through the CVE classes"
        )
        cls._camera_id(command, "every camera waiting for a frame")

    @classmethod
    def _faces(cls, commands: Any) -> None:
        """Detect the faces of the stored frames and cluster them into people."""
        command = GroupParser.leaf(
            commands, "faces", "Detect faces and cluster them into people"
        )
        cls._camera_id(command, "every camera holding a frame")

    @classmethod
    def _camera_id(cls, command: Any, default_help: str) -> None:
        """The one option the three commands of this group share."""
        command.add_argument(
            "--camera-id",
            type=int,
            default=0,
            help=f"Restrict the run to one camera id; defaults to {default_help}",
        )


class ReportParser:
    """The commands that only read what is already stored."""

    @classmethod
    def add(cls, groups: Any) -> None:
        commands = GroupParser.opened(groups, "report", "Read-only reports")
        cls._faces(commands)

    @classmethod
    def _faces(cls, commands: Any) -> None:
        """What the face scan found, person by person, with the target matches."""
        command = GroupParser.leaf(
            commands, "faces", "What the face scan found, person by person"
        )
        command.add_argument(
            "--person-id",
            type=int,
            default=None,
            help="Only this person; defaults to every person stored",
        )


class SearchParser:
    """The `search` group: who appeared where, and one named target (D52)."""

    @classmethod
    def add(cls, groups: Any) -> None:
        commands = GroupParser.opened(groups, "search", "Searches that only read")
        cls._appearance(commands)
        cls._person(commands)

    @classmethod
    def _appearance(cls, commands: Any) -> None:
        """Who appeared, where and when: the monitoring answer (FR-027)."""
        appearance = GroupParser.leaf(
            commands, "appearance", "Who appeared, where and when"
        )
        appearance.add_argument(
            "--person-id", type=int, default=None, help="Only this person"
        )
        cls._narrowing(appearance)

    @classmethod
    def _person(cls, commands: Any) -> None:
        """One named target, at the camera and instants the run narrows to (D74)."""
        person = GroupParser.leaf(
            commands,
            "person",
            "Find where a registered target appeared; --image registers first",
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
        """Which target is searched, and the name a photo needs."""
        person.add_argument(
            "--name", default=None, help="Target name; searched, required with --image"
        )
        person.add_argument(
            "--target-id",
            type=int,
            default=None,
            help="An already registered target; defaults to every target",
        )
        person.add_argument(
            "--image",
            action="append",
            default=[],
            metavar="PATH",
            help="Reference photo; repeatable, and it registers or adds to --name",
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


class TargetParser:
    """The `target` group: register a person, list them, remove one (D76, D79)."""

    @classmethod
    def add(cls, groups: Any) -> None:
        commands = GroupParser.opened(
            groups, "target", "The named people this build looks for"
        )
        cls._add(commands)
        cls._list(commands)
        cls._remove(commands)

    @classmethod
    def _add(cls, commands: Any) -> None:
        """Register a name with its reference photos, adding to a known name."""
        target = GroupParser.leaf(
            commands, "add", "Register a name with its reference photos"
        )
        target.add_argument("--name", required=True, help="Target name; required")
        target.add_argument(
            "--image",
            action="append",
            required=True,
            default=None,
            metavar="PATH",
            help="Reference photo, holding one face; repeatable",
        )

    @classmethod
    def _list(cls, commands: Any) -> None:
        """Every registered target, with its photos and the hits recorded."""
        GroupParser.leaf(
            commands, "list", "Every registered target with its photos and hits"
        )

    @classmethod
    def _remove(cls, commands: Any) -> None:
        """Drop one target with its photos, its hits and the label it wrote."""
        target = GroupParser.leaf(
            commands, "remove", "Drop a target with its photos, hits and label"
        )
        target.add_argument("target", help="Target name, or its id in the table")


class MeasureParser:
    """The measurements: they read a labelled set, and they write nothing."""

    @classmethod
    def add(cls, groups: Any) -> None:
        commands = GroupParser.opened(
            groups, "measure", "Measurements that write nothing"
        )
        cls._threshold(commands)

    @classmethod
    def _threshold(cls, commands: Any) -> None:
        """The face match threshold, measured on a labelled pair set."""
        threshold = GroupParser.leaf(
            commands, "threshold", "Measure the face match threshold on a pair set"
        )
        threshold.add_argument(
            "--pairs",
            default=None,
            help="Directory of identities; defaults to face.pairs_path",
        )


class CommandParser:
    """The command line surface of `contracts/cli.md`, group by group (D72).

    `groups` is the action `add_subparsers` returns, whose public name argparse
    does not expose, so it is typed as Any at the places that take one.
    """

    @classmethod
    def parsed(cls) -> Namespace:
        """The command line, parsed and validated by argparse itself."""
        parser = cls._root()
        groups = parser.add_subparsers(dest="group", required=True)
        cls._every_group(groups)
        return parser.parse_args()

    @classmethod
    def _every_group(cls, groups: Any) -> None:
        """The six groups of this CLI, in the order the help prints them."""
        FindParser.add(groups)
        ScanParser.add(groups)
        ReportParser.add(groups)
        SearchParser.add(groups)
        TargetParser.add(groups)
        MeasureParser.add(groups)

    @classmethod
    def _root(cls) -> ArgumentParser:
        """The root parser, which holds the real default of both global options."""
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
