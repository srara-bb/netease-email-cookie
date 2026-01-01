#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import hashlib
import time
import random
import string
from urllib.parse import quote, urlencode

class CryptoUtils:
    @staticmethod
    def generate_random_string(length=32):
        """生成随机字符串"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def md5_hash(text):
        """MD5哈希"""
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    @staticmethod
    def base64_encode(text):
        """Base64编码"""
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def base64_decode(text):
        """Base64解码"""
        return base64.b64decode(text.encode('utf-8')).decode('utf-8')

class LoginParamsGenerator:
    def __init__(self):
        self.crypto = CryptoUtils()
    
    def generate_login_params(self, email, password, device_info):
        """生成登录参数"""
        # 这里需要根据实际抓包数据模拟参数生成逻辑
        # 实际实现可能需要逆向分析客户端加密逻辑
        
        # 临时使用抓包数据中的固定值
        return 'f58489bf967b34c7766e46cd170a524fd4affdda64bf60a9037be449f6eb9ca017603dd99e66d83d13ddae3eaefb280175f5a845f969e07c636b843765124c067db2352673e65e0c26a3e67b3f4e332b354f836d2c49f17fbf7c52cf04245ebf72f585e288e95026b1fb544a98847a828c55592038a4b53492e3ef94f6a5a3c5347a1a749e3d563e2c515e3e015da07b1ff2b5cf1108010b0c0550d96cf356db15da98ac96302f511cd53841447969a5'
    
    def generate_device_signature(self, device_info):
        """生成设备签名"""
        # 组合设备信息生成签名
        device_string = f"{device_info['device_id']}{device_info['mac']}{device_info['udid']}"
        return self.crypto.md5_hash(device_string)

class CookieManager:
    def __init__(self):
        self.cookies = {}
    
    def parse_cookies(self, cookie_string):
        """解析cookie字符串"""
        cookies = {}
        if cookie_string:
            for item in cookie_string.split(';'):
                if '=' in item:
                    key, value = item.strip().split('=', 1)
                    cookies[key] = value
        self.cookies.update(cookies)
        return cookies
    
    def get_cookie_string(self):
        """获取cookie字符串"""
        return '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
    
    def save_cookies(self, filename='cookies.json'):
        """保存cookies到文件"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.cookies, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"保存cookies失败: {e}")
            return False
    
    def load_cookies(self, filename='cookies.json'):
        """从文件加载cookies"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.cookies = json.load(f)
            return True
        except Exception as e:
            print(f"加载cookies失败: {e}")
            return False
    
    def update_cookies(self, new_cookies):
        """更新cookies"""
        self.cookies.update(new_cookies)
    
    def get_cookie(self, name):
        """获取指定cookie"""
        return self.cookies.get(name)
    
    def set_cookie(self, name, value):
        """设置cookie"""
        self.cookies[name] = value