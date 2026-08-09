import logging
import os
from argparse import ArgumentParser
from configparser import ConfigParser

from dotenv import load_dotenv

from scanners.config import CheckersConfig, NmapConfig, ShodanConfig
from scanners.proxy import TwoCaptchaProxy, TwoCaptchaSettings
from scanners.rtsp_probe import RtspProbe
from scanners.task import CheckTask, NmapTask, ShodanTask

__version__ = "0.1.0"

load_dotenv()


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
    parser.add_argument(
        "--config",
        action="store",
        help="Path to the configuration file",
        default="config.ini",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose mode", default=False
    )
    return parser.parse_args()


def load_config(config_file):
    config = ConfigParser()
    config.read(config_file)
    return config


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


def _build_search(config):
    return ShodanTask(ShodanConfig(**config["shodan_config"]))


def _build_check(config):
    # RTSP probe through the proxy (.env transport) so the login and frame grab
    # leave via the residential exit, not the local IP.
    probe = RtspProbe(proxy=TwoCaptchaProxy())
    return CheckTask(CheckersConfig(**config["checkers_config"]), probe=probe)


def _build_nmap(config):
    # nmap --proxies cannot use socks5, so give it an http proxy regardless of
    # the .env transport (which may be socks5 for the HTTP client).
    nmap_proxy = TwoCaptchaProxy(TwoCaptchaSettings(protocol="http"))
    return NmapTask(NmapConfig(**config["nmap_config"]), nmap_proxy)


_TASK_BUILDERS = {
    "search": _build_search,
    "check": _build_check,
    "nmap": _build_nmap,
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
