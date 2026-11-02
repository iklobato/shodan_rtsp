import logging
import os
from argparse import ArgumentParser

from scanners.config import AppConfig, load_config
from scanners.face_task import FaceScanTask
from scanners.proxy import TwoCaptchaProxy
from scanners.rtsp_probe import RtspProbe
from scanners.task import CheckTask, NmapTask, ShodanTask
from scanners.vuln_task import VulnScanTask

__version__ = "0.1.0"


def parse_args():
    parser = ArgumentParser(description="Camera Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--start_search",
        dest="mode",
        action="store_const",
        const="search",
        help="Start searching for cameras on Shodan",
    )
    group.add_argument(
        "--start_check",
        dest="mode",
        action="store_const",
        const="check",
        help="Start testing cameras on DB",
    )
    group.add_argument(
        "--start_nmap",
        dest="mode",
        action="store_const",
        const="nmap",
        help="Start nmap scan",
    )
    group.add_argument(
        "--start_face_scan",
        dest="mode",
        action="store_const",
        const="face_scan",
        help="Start face scan on active cameras",
    )
    group.add_argument(
        "--start_vuln_scan",
        dest="mode",
        action="store_const",
        const="vuln_scan",
        help="Report the CVEs of the services in an nmap XML run",
    )
    parser.add_argument(
        "--config",
        action="store",
        help="Path to the configuration file",
        default="config.yaml",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose mode", default=False
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


class TaskFactory:
    """Creates scanner task instances from config."""

    def build_search(config: AppConfig) -> ShodanTask:
        return ShodanTask(config.shodan)

    def build_check(config: AppConfig) -> CheckTask:
        proxy = TaskFactory._proxy(config)
        return CheckTask(config.checkers, probe=RtspProbe(proxy=proxy))

    def build_nmap(config: AppConfig) -> NmapTask:
        # nmap --proxies cannot use socks5, so give it an http proxy regardless
        # of the configured transport (which may be socks5 for the HTTP client).
        proxy = TaskFactory._proxy(config, protocol_update={"protocol": "http"})
        return NmapTask(config.nmap, proxy)

    def _proxy(
        config: AppConfig, protocol_update: dict = None
    ) -> TwoCaptchaProxy | None:
        """The configured proxy, or None when proxy.enabled is false (direct)."""
        if not config.proxy.enabled:
            return None
        proxy_config = (
            config.proxy.model_copy(update=protocol_update)
            if protocol_update
            else config.proxy
        )
        return TwoCaptchaProxy(proxy_config)

    def build_face_scan(config: AppConfig) -> FaceScanTask:
        return FaceScanTask.from_config(config)

    def build_vuln_scan(config: AppConfig) -> VulnScanTask:
        return VulnScanTask.from_config(config)


_TASK_BUILDERS = {
    "search": TaskFactory.build_search,
    "check": TaskFactory.build_check,
    "nmap": TaskFactory.build_nmap,
    "face_scan": TaskFactory.build_face_scan,
    "vuln_scan": TaskFactory.build_vuln_scan,
}


def main():
    args = parse_args()
    _configure_logging(args.verbose)
    if args.verbose:
        logging.info("Verbose mode enabled")
    config = load_config(args.config)
    _TASK_BUILDERS[args.mode](config).run()


if __name__ == "__main__":
    main()
