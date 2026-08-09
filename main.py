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

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("logs/rtsp_scanner.log"),
        logging.StreamHandler(),
    ],
)


def parse_args():
    parser = ArgumentParser(description="Camera Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--start_search",
        action="store_true",
        help="Start searching for cameras on Shodan",
    )
    group.add_argument(
        "--start_check", action="store_true", help="Start testing cameras on DB"
    )
    group.add_argument("--start_nmap", action="store_true", help="Start nmap scan")
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


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info("Verbose mode enabled")

    config = load_config(args.config)

    if args.start_search:
        ShodanTask(ShodanConfig(**config["shodan_config"])).run()

    if args.start_check:
        # RTSP probe through the proxy (.env transport) so the login and frame
        # grab leave via the residential exit, not the local IP.
        probe = RtspProbe(proxy=TwoCaptchaProxy())
        CheckTask(CheckersConfig(**config["checkers_config"]), probe=probe).run()

    if args.start_nmap:
        # nmap --proxies cannot use socks5, so give it an http proxy regardless
        # of the .env transport (which may be socks5 for the HTTP client).
        nmap_proxy = TwoCaptchaProxy(TwoCaptchaSettings(protocol="http"))
        NmapTask(NmapConfig(**config["nmap_config"]), nmap_proxy).run()


if __name__ == "__main__":
    main()
