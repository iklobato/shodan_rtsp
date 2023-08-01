import logging
from argparse import ArgumentParser
from configparser import ConfigParser

from dotenv import load_dotenv

from scanners.task import ShodanTask, CheckTask, NmapTask


__version__ = '0.1.0'

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler("./logs/rtsp_scanner.log"),
        logging.StreamHandler()
    ]
)


def parse_args():
    parser = ArgumentParser(description='Camera Scanner')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--start_search', action='store_true', help='Start searching for cameras on Shodan')
    group.add_argument('--start_check', action='store_true', help='Start testing cameras on DB')
    group.add_argument('--start_nmap', action='store_true', help='Start nmap scan')
    parser.add_argument('--config', action='store', help='Path to the configuration file', default='config.ini')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode', default=False)

    return parser.parse_args()


def load_config(config_file):
    config = ConfigParser()
    config.read(config_file)
    return config


def main():
    args = parse_args()

    config = load_config(args.config)
    settings = {**config, **vars(args)}

    if args.start_search:
        shodan_config = settings.get('shodan_config')
        shodan_searcher = ShodanTask(shodan_config)
        shodan_searcher.run()

    if args.start_check:
        checkers_config = settings.get('checkers_config')
        checker = CheckTask(checkers_config)
        checker.run()

    if args.start_nmap:
        nmap_config = settings.get('nmap_config')
        nmap_searcher = NmapTask(nmap_config)
        nmap_searcher.run()


if __name__ == '__main__':
    main()
