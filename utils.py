#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import random
import string

from services.storage_service import StorageService


class CryptoUtils:
    @staticmethod
    def generate_random_string(length=32):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def md5_hash(text):
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    @staticmethod
    def base64_encode(text):
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def base64_decode(text):
        return base64.b64decode(text.encode('utf-8')).decode('utf-8')


class LoginParamsGenerator:
    def __init__(self):
        self.crypto = CryptoUtils()

    def generate_login_params(self, email, password, device_info):
        return 'f58489bf967b34c7766e46cd170a524fd4affdda64bf60a9037be449f6eb9ca017603dd99e66d83d13ddae3eaefb280175f5a845f969e07c636b843765124c067db2352673e65e0c26a3e67b3f4e332b354f836d2c49f17fbf7c52cf04245ebf72f585e288e95026b1fb544a98847a828c55592038a4b53492e3ef94f6a5a3c5347a1a749e3d563e2c515e3e015da07b1ff2b5cf1108010b0c0550d96cf356db15da98ac96302f511cd53841447969a5'

    def generate_device_signature(self, device_info):
        device_string = f"{device_info['device_id']}{device_info['mac']}{device_info['udid']}"
        return self.crypto.md5_hash(device_string)


class CookieManager:
    def __init__(self, base_dir='.'):
        self.cookies = {}
        self.storage = StorageService(base_dir)

    def parse_cookies(self, cookie_string):
        cookies = {}
        if cookie_string:
            for item in cookie_string.split(';'):
                if '=' in item:
                    key, value = item.strip().split('=', 1)
                    cookies[key] = value
        self.cookies.update(cookies)
        return cookies

    def get_cookie_string(self):
        return '; '.join([f"{k}={v}" for k, v in self.cookies.items()])

    def save_cookies(self, filename='cookies.json'):
        result = self.storage.save_json(filename, self.cookies)
        result['count'] = len(self.cookies)
        return result

    def load_cookies(self, filename='cookies.json'):
        self.cookies = self.storage.load_json(filename, {})
        return {'status': 'success', 'path': self.storage._path(filename), 'count': len(self.cookies)}

    def update_cookies(self, new_cookies):
        self.cookies.update(new_cookies)
        return {'status': 'success', 'count': len(self.cookies)}

    def get_cookie(self, name):
        return self.cookies.get(name)

    def set_cookie(self, name, value):
        self.cookies[name] = value
        return {'status': 'success', 'name': name}
