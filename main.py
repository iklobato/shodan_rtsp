import logging
import os
from argparse import ArgumentParser, Namespace
from collections.abc import Callable

from scanners.brand_probe import BrandBook, Identifier
from scanners.config import AppConfig, NmapConfig, ShodanConfig, load_config
from scanners.task import CheckDeps, CheckTask, NmapTask, ShodanDeps, ShodanTask, Task

__version__ = "0.1.0"


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
    """Dispatches the parsed command line to the task it names (D34, D38)."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def execute(self, arguments: Namespace) -> None:
        """Run the task the command line asks for."""
        self._scan_commands()[arguments.command](arguments).run()

    def _scan_commands(self) -> dict[str, Callable[[Namespace], Task]]:
        factory = TaskFactory(self._config)
        return {
            "nmap": factory.build_nmap,
            "shodan": factory.build_shodan,
            "check": factory.build_check,
        }


def parse_args() -> Namespace:
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
    groups = parser.add_subparsers(dest="group", required=True)
    scan = groups.add_parser("scan", help="Scans that write to the database")
    commands = scan.add_subparsers(dest="command", required=True)
    commands.add_parser("nmap", help="Find cameras on a range with nmap").add_argument(
        "argument", nargs="?", help="CIDR to scan; defaults to nmap.ip_range"
    )
    commands.add_parser(
        "shodan", help="Find cameras through the Shodan API"
    ).add_argument(
        "argument", nargs="?", help="Shodan query; defaults to shodan.query"
    )
    commands.add_parser(
        "check", help="Try credentials against the stored cameras"
    ).add_argument(
        "--camera-id",
        type=int,
        default=0,
        help="Restrict the run to one camera id; defaults to every camera waiting",
    )
    return parser.parse_args()


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
    args = parse_args()
    _configure_logging(args.verbose)
    if args.verbose:
        logging.info("Verbose mode enabled")
    CommandLine(load_config(args.config)).execute(args)


if __name__ == "__main__":
    main()
