#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import base64
import hashlib
import time
import random
import string
import uuid
import os
from urllib.parse import quote, urlencode, urlparse, parse_qs
from security_handler import SecurityVerificationHandler, manual_verification_guide

class NetEaseEmailAuth:
    def __init__(self, use_dynamic_device_id=False):
        self.session = requests.Session()
        # 先尝试加载保存的设备信息
        saved_device = self._load_device_info()
        if saved_device:
            # 使用保存的设备信息
            self.device_id = saved_device.get('device_id')
            self.device_key = saved_device.get('device_key')
            self.udid = saved_device.get('udid')
            self.device_info = self._generate_device_info(use_dynamic_device_id)
            # 使用保存的设备ID和密钥
            self.device_info['device_id'] = self.device_id
            self.device_info['unique_id'] = saved_device.get('unique_id', self.device_info.get('unique_id'))
        else:
            # 没有保存的设备信息，生成新的
            self.device_info = self._generate_device_info(use_dynamic_device_id)
        self.sauth_data = self._load_sauth_data()
        self.security_handler = SecurityVerificationHandler(self.session)
        
    def _load_device_info(self, filename='device_info.json'):
        """加载保存的设备信息"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"加载设备信息失败: {e}")
            return None
    
    def _save_device_info(self, filename='device_info.json'):
        """保存设备信息"""
        try:
            device_data = {
                'device_id': self.device_id,
                'device_key': getattr(self, 'device_key', ''),
                'udid': self.udid,
                'unique_id': self.device_info.get('unique_id', ''),
                'saved_time': int(time.time())
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(device_data, f, ensure_ascii=False, indent=2)
            print(f"✅ 设备信息已保存到 {filename}")
            return True
        except Exception as e:
            print(f"保存设备信息失败: {e}")
            return False
    
    def _load_sauth_data(self):
        """加载sauth数据"""
        try:
            with open('sauth_data.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                return json.loads(data['sauth_json'])
        except Exception as e:
            print(f"加载sauth数据失败: {e}")
            return {}
    
    def _save_sauth_data(self, filename='sauth_data.json'):
        """保存sauth数据到文件"""
        try:
            sauth_json_str = json.dumps(self.sauth_data, ensure_ascii=False, separators=(',', ':'))
            data = {'sauth_json': sauth_json_str}
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"✅ Sauth数据已保存到 {filename}")
            return True
        except Exception as e:
            print(f"保存sauth数据失败: {e}")
            return False
    
    def _save_cookie_format(self, email, filename='cookies.json'):
        """保存为cookie格式的文件"""
        try:
            # 构建cookie格式
            sauth_json_str = json.dumps(self.sauth_data, ensure_ascii=False, separators=(',', ':'))
            cookie_data = {
                "sauth_json": sauth_json_str
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(cookie_data, f, ensure_ascii=False, indent=2)
            print(f"✅ Cookie已保存到 {filename}")
            
            # 同时保存为nemc格式
            self._save_nemc_cookie_format(email)
            
            return True
        except Exception as e:
            print(f"保存cookie失败: {e}")
            return False
    
    def _save_nemc_cookie_format(self, email, filename=None):
        """保存为nemc项目可用的cookie格式，自动生成文件名"""
        try:
            # 检查sauth_data是否为空
            if not self.sauth_data or len(self.sauth_data) == 0:
                print(f"⚠️  sauth_data为空，无法保存NEMC格式Cookie")
                return False
            
            # 检查必要字段是否存在
            required_fields = ['sdkuid', 'sessionid', 'deviceid', 'udid']
            missing_fields = [field for field in required_fields if not self.sauth_data.get(field)]
            if missing_fields:
                print(f"⚠️  sauth_data缺少必要字段: {missing_fields}，无法保存NEMC格式Cookie")
                return False
            
            # 如果没有指定文件名，自动生成基于邮箱和时间戳的文件名
            if filename is None:
                # 从邮箱中提取用户名部分（去掉@后面的内容）
                email_username = email.split('@')[0] if '@' in email else email
                # 生成时间戳
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                # 生成文件名：nemc_cookie_邮箱_时间戳.json
                filename = f"nemc_cookie_{email_username}_{timestamp}.json"
            
            # 直接使用已有的sauth_data，确保格式正确
            # sauth_data已经包含了所有必要字段，只需要确保格式符合nemc要求
            sauth_json_str = json.dumps(self.sauth_data, ensure_ascii=False, separators=(',', ':'))
            cookie_data = {
                "sauth_json": sauth_json_str
            }
            
            # 保存到文件
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(cookie_data, f, ensure_ascii=False, indent=2)
                f.flush()  # 确保数据写入磁盘
                os.fsync(f.fileno())  # 强制同步到磁盘
            
            # 验证文件是否成功写入
            if os.path.exists(filename) and os.path.getsize(filename) > 0:
                print(f"✅ NEMC格式Cookie已保存到 {filename} (文件大小: {os.path.getsize(filename)} 字节)")
                return True
            else:
                print(f"⚠️  文件保存失败: {filename} 文件为空或不存在")
                return False
        except Exception as e:
            print(f"⚠️  保存NEMC格式Cookie失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _generate_device_info(self, use_dynamic_device_id=False):
        """生成设备信息"""
        if use_dynamic_device_id:
            # 动态生成设备号（和注册账号一样使用ascii_lowercase）
            random_prefix = ''.join(random.choices(string.ascii_lowercase, k=16))
            device_id = f"{random_prefix}-d"
        else:
            # 使用原始设备号
            device_id = "amawskiaaxanhk66-d"
        
        # 使用原始抓包数据中的其他固定值
        original_udid = "63989d14cdd45c3d"
        original_urs_udid = "757037f1d188ab5db5e7f3267671027609c695f8"
        original_unique_id = "84dd770f-54bc-420e-83e4-f07fe0c08e521764311947320"
        original_ext_ci = "99547ce7459cc51d936567c699f1a20def3cba69e2c52237a05ff926671bb824"
        
        # 保存到实例变量
        self.device_id = device_id
        self.udid = original_udid
        
        # 动态生成交易ID
        timestamp = int(time.time() * 1000)
        random_num = random.randint(100000000, 999999999)
        self.transid = f"{original_udid}_{timestamp}_{random_num}"
        self.mcount_transaction_id = f"{original_udid}_{timestamp}_{random.randint(100000000, 999999999)}"
        
        return {
            'device_id': device_id,  # 根据参数决定是否动态
            'version': '840282689',
            'mac': '459690b46859bc10ffa9b40c7768d140',
            'urs_udid': original_urs_udid,
            'unique_id': original_unique_id,
            'brand': 'HONOR',
            'device_name': 'MuMu',
            'device_type': 'tablet',
            'device_model': 'BVL-AN20',
            'resolution': '900*1600',
            'system_name': 'Android',
            'system_version': '12',
            'udid': original_udid,
            'app_channel': 'netease.wyzymnqsd_cps_dev',
            'ext_ci': original_ext_ci,
            'ci_code': '3',
            'game_id': 'aecfrxodyqaaaajp-g-x19',
            'gv': '840282689',
            'gvn': '3.6.5.282689',
            'cv': 'a5.9.0',
            'sv': '32',
            'app_type': 'games',
            'app_mode': '2',
            'mcount_app_key': 'EEkEEXLymcNjM42yLY3Bn6AO15aGy4yq',
            '_cloud_extra_base64': 'e30%3D',
            'sc': '1'
        }
    
    def _generate_transid(self):
        """生成交易ID"""
        timestamp = int(time.time() * 1000)
        random_num = random.randint(100000000, 999999999)
        return f"{self.device_info['udid']}_{timestamp}_{random_num}"
    
    def _get_headers(self):
        """获取请求头"""
        return {
            'Accept-Charset': 'UTF-8',
            'Content-type': 'application/x-www-form-urlencoded',
            'Accept-Language': 'zh-cn',
            'User-agent': f'com.netease.x19/{self.device_info["version"]} NeteaseMobileGame/{self.device_info["cv"]} ({self.device_info["device_model"]};{self.device_info["sv"]})',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
    
    def generate_device_key(self):
        """生成设备密钥（第一步：创建设备）"""
        url = f"https://service.mkey.163.com/mpay/games/{self.device_info['game_id']}/devices"
        
        # 使用注册账号的方法计算MAC
        mac_hex = hashlib.md5(f"02:00:00:00:00:00{self.udid}{self.device_id}".encode()).hexdigest()
        
        # 生成unique_id
        uuid_part = str(uuid.uuid4())
        timestamp = int(time.time())
        current_unique_id = f"{uuid_part}{timestamp}20114"
        
        # 计算ext_ci
        ext_ci = hashlib.sha256(f"{self.udid}{self.device_id}{self.device_info['game_id']}".encode()).hexdigest()
        
        data = {
            "mac": mac_hex,
            "urs_udid": self.device_info['urs_udid'],
            "init_urs_device": "0",
            "unique_id": current_unique_id,
            "brand": self.device_info['brand'],
            "device_name": self.device_info['device_name'],
            "device_type": self.device_info['device_type'],
            "device_model": self.device_info['device_model'],
            "resolution": self.device_info['resolution'],
            "system_name": self.device_info['system_name'],
            "system_version": self.device_info['system_version'],
            "udid": self.udid,
            "app_channel": self.device_info['app_channel'],
            "ext_ci": ext_ci,
            "ci_code": "3",
            "game_id": self.device_info['game_id'],
            "gv": self.device_info['gv'],
            "gvn": self.device_info['gvn'],
            "cv": self.device_info['cv'],
            "sv": self.device_info['sv'],
            "app_type": self.device_info['app_type'],
            "app_mode": self.device_info['app_mode'],
            "transid": self.transid,
            "mcount_app_key": self.device_info['mcount_app_key'],
            "mcount_transaction_id": self.mcount_transaction_id,
            "_cloud_extra_base64": "e30=",
            "sc": "1"
        }
        
        headers = {
            "Accept-Charset": "UTF-8",
            "Content-type": "application/x-www-form-urlencoded",
            "Accept-Language": "zh-cn",
            "User-agent": f"com.netease.x19/{self.device_info['version']} NeteaseMobileGame/{self.device_info['cv']} ({self.device_info['device_model']};{self.device_info['sv']})",
            "Host": "service.mkey.163.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
        
        try:
            response = self.session.post(url, data=data, headers=headers, timeout=30)
            if response.status_code == 201:
                result = response.json()
                if "device" in result and "key" in result["device"]:
                    device_key = result["device"]["key"]
                    device_id = result["device"].get("id", self.device_id)
                    self.device_id = device_id
                    # 同步更新device_info中的device_id和unique_id
                    self.device_info['device_id'] = device_id
                    self.device_info['unique_id'] = current_unique_id
                    # 保存device_key用于params计算
                    self.device_key = device_key
                    return device_key
            else:
                # 打印详细错误信息
                try:
                    error_result = response.json()
                    print(f"设备创建失败，状态码: {response.status_code}")
                    print(f"错误信息: {error_result}")
                except:
                    print(f"设备创建失败，状态码: {response.status_code}")
                    print(f"响应内容: {response.text[:200]}")
            return None
        except Exception as e:
            print(f"生成设备密钥失败: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def upload_device_info(self):
        """上传设备信息（实现两步流程：先创建设备，再上传信息）"""
        # 检查是否已有设备密钥
        if hasattr(self, 'device_key') and self.device_key:
            print(f"✅ 使用已有设备: {self.device_id}")
            print(f"✅ 设备密钥: {self.device_key[:20]}...")
            # 直接使用已有设备，跳过创建步骤
            # 但需要上传设备信息（如果之前没上传过）
            print("第二步：上传设备信息...")
            return self._upload_device_details()
        
        # 第一步：创建设备并获取device_key
        print("第一步：创建设备...")
        device_key = self.generate_device_key()
        if not device_key:
            print("❌ 创建设备失败")
            return False
        
        print(f"✅ 设备创建成功，设备密钥: {device_key}")
        # 保存设备信息
        self._save_device_info()
        
        # 第二步：上传设备信息
        print("第二步：上传设备信息...")
        return self._upload_device_details()
    
    def _upload_device_details(self):
        """上传设备详细信息"""
        url = 'https://service.mkey.163.com/mpay/api/devices/upload'
        
        data = {
            'device_id': self.device_id,
            'version': self.device_info['version'],
            'mac': self.device_info['mac'],
            'urs_udid': self.device_info['urs_udid'],
            'unique_id': self.device_info['unique_id'],
            'brand': self.device_info['brand'],
            'device_name': self.device_info['device_name'],
            'device_type': self.device_info['device_type'],
            'device_model': self.device_info['device_model'],
            'resolution': self.device_info['resolution'],
            'system_name': self.device_info['system_name'],
            'system_version': self.device_info['system_version'],
            'udid': self.device_info['udid'],
            'app_channel': self.device_info['app_channel'],
            'ext_ci': self.device_info['ext_ci'],
            'ci_code': self.device_info['ci_code'],
            'game_id': self.device_info['game_id'],
            'gv': self.device_info['gv'],
            'gvn': self.device_info['gvn'],
            'cv': self.device_info['cv'],
            'sv': self.device_info['sv'],
            'app_type': self.device_info['app_type'],
            'app_mode': self.device_info['app_mode'],
            'transid': self.transid,
            'mcount_app_key': self.device_info['mcount_app_key'],
            'mcount_transaction_id': self.mcount_transaction_id,
            '_cloud_extra_base64': self.device_info['_cloud_extra_base64'],
            'sc': self.device_info['sc']
        }
        
        try:
            response = self.session.post(url, data=data, headers=self._get_headers())
            result = response.json()
            print(f"设备信息上传结果: {result}")
            return result.get('upload_time') is not None
        except Exception as e:
            print(f"设备信息上传失败: {e}")
            return False
    
    def calculate_params(self, device_key=None, email=None, password_md5=None):
        """计算登录参数（根据G79实现：加密包含username、password、unique_id的JSON）"""
        if device_key is None:
            device_key = getattr(self, 'device_key', None)
            if device_key is None:
                return hashlib.md5(f"{self.udid}{self.device_id}{self.device_info['game_id']}{self.device_info['gv']}".encode()).hexdigest()
        
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            
            if len(device_key) == 32:
                key_bytes = bytes.fromhex(device_key)
            elif len(device_key) == 64:
                key_bytes = bytes.fromhex(device_key)[:16]
            else:
                key_bytes = device_key.encode()[:16] if isinstance(device_key, str) else device_key[:16]
            
            # 如果提供了邮箱和密码，构建包含这些信息的JSON（参考G79 Go实现）
            if email and password_md5:
                payload = {
                    "username": email,
                    "password": password_md5.lower(),
                    "unique_id": self.device_info.get('unique_id', '')
                }
                plaintext = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            else:
                # 如果没有提供邮箱和密码，使用空JSON（用于游客账号等场景）
                plaintext = b"{}"
            
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            padded_plaintext = pad(plaintext, AES.block_size)
            encrypted = cipher.encrypt(padded_plaintext)
            return encrypted.hex()
        except ImportError as e:
            print(f"❌ 缺少必要的依赖库: {e}")
            print("请运行以下命令安装依赖:")
            print("  pip install pycryptodome")
            print("或者:")
            print("  pip install -r requirements.txt")
            return hashlib.md5(f"{self.udid}{self.device_id}{self.device_info['game_id']}{self.device_info['gv']}".encode()).hexdigest()
        except Exception as e:
            print(f"计算params失败: {e}")
            import traceback
            traceback.print_exc()
            return hashlib.md5(f"{self.udid}{self.device_id}{self.device_info['game_id']}{self.device_info['gv']}".encode()).hexdigest()
    
    def login_email(self, email, password, retry_count=0):
        """邮箱登录
        Args:
            email: 邮箱地址
            password: 密码
            retry_count: 重试次数（用于防止无限递归）
        """
        # Base64编码邮箱
        encoded_email = base64.b64encode(email.encode('utf-8')).decode('utf-8')
        # URL编码Base64字符串（确保=等特殊字符被正确编码）
        url_encoded_email = quote(encoded_email)
        
        # 使用POST请求，URL中包含un参数（Base64编码并URL编码的邮箱）
        url = f'https://service.mkey.163.com/mpay/games/{self.device_info["game_id"]}/devices/{self.device_info["device_id"]}/users?un={url_encoded_email}'
        
        # 计算密码的MD5哈希
        password_md5 = hashlib.md5(password.encode('utf-8')).hexdigest()
        
        # 计算加密参数（包含邮箱和密码MD5）
        params_value = self.calculate_params(email=email, password_md5=password_md5)
        
        # POST body中的数据（requests会自动进行URL编码）
        data = {
            'opt_fields': 'nickname,avatar,realname_status,mobile_bind_status,exit_popup_info,mask_related_mobile,related_login_status,detect_is_new_user',
            'params': params_value,
            'game_id': self.device_info['game_id'],
            'gv': self.device_info['gv'],
            'gvn': self.device_info['gvn'],
            'cv': self.device_info['cv'],
            'sv': self.device_info['sv'],
            'app_type': self.device_info['app_type'],
            'app_mode': self.device_info['app_mode'],
            'app_channel': self.device_info['app_channel'],
            'transid': self.transid,
            'mcount_app_key': self.device_info['mcount_app_key'],
            'mcount_transaction_id': self.mcount_transaction_id,
            '_cloud_extra_base64': self.device_info['_cloud_extra_base64'],
            'sc': self.device_info['sc']
        }
        
        try:
            response = self.session.post(url, data=data, headers=self._get_headers())
            result = response.json()
            print(f"登录结果: {result}")
            
            # 检查错误代码
            error_code = result.get('code')
            if error_code == 1351:
                # 需要安全验证
                verify_url = result.get('verify_url')
                print(f"需要安全验证，验证URL: {verify_url}")
                
                # 提取ticket和code（不保存，只用于当前会话）
                ticket, code = self.extract_verify_info_from_url(verify_url)
                
                # 显示验证码信息
                if code:
                    print(f"\n{'='*60}")
                    print(f"📱 验证码: {code}")
                    print(f"📞 请发送验证码 {code} 到 1069016373035")
                    print(f"{'='*60}\n")
                
                return {'status': 'need_verify', 'verify_url': verify_url, 'ticket': ticket, 'code': code}
            elif error_code == 1311:
                # 用户登录已失效，可能是设备信息问题
                error_reason = result.get('reason', '用户登录已失效')
                print(f"⚠️  错误代码 1311: {error_reason}")
                
                # 防止无限递归，最多重试1次
                if retry_count >= 1:
                    print("❌ 已重试1次，仍然失败")
                    return {'status': 'failed', 'error': result, 'retry_suggestion': '请检查账号密码是否正确，或稍后重试'}
                
                print("尝试重新创建设备并上传设备信息...")
                
                # 清除旧的设备信息
                if hasattr(self, 'device_key'):
                    delattr(self, 'device_key')
                
                # 重新生成交易ID
                import random
                self.transid = self._generate_transid()
                self.mcount_transaction_id = f"{self.udid}_{int(time.time() * 1000)}_{random.randint(100000000, 999999999)}"
                
                # 重新创建设备
                device_key = self.generate_device_key()
                if device_key:
                    print(f"✅ 设备重新创建成功，设备密钥: {device_key}")
                    self._save_device_info()
                    
                    # 重新上传设备信息
                    if self._upload_device_details():
                        print("✅ 设备信息重新上传成功")
                        # 重新尝试登录（增加重试计数）
                        print("重新尝试登录...")
                        return self.login_email(email, password, retry_count + 1)
                    else:
                        print("⚠️  设备信息上传失败")
                        return {'status': 'failed', 'error': result, 'retry_suggestion': '设备信息上传失败，请检查网络连接或稍后重试'}
                else:
                    print("❌ 设备重新创建失败")
                    return {'status': 'failed', 'error': result, 'retry_suggestion': '设备创建失败，请检查网络连接'}
            elif result.get('userid') or result.get('user'):
                # 登录成功
                # 更新sauth_data，保存登录信息
                user_data = result.get('user', {})
                if user_data:
                    # 生成client_login_sn
                    import random
                    import string
                    client_login_sn = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
                    
                    # 更新sauth_data
                    self.sauth_data['sdkuid'] = user_data.get('id', '')
                    self.sauth_data['sessionid'] = user_data.get('token', '')
                    self.sauth_data['udid'] = user_data.get('udid', self.udid)
                    self.sauth_data['deviceid'] = self.device_info['device_id']
                    self.sauth_data['client_login_sn'] = client_login_sn
                    self.sauth_data['gameid'] = 'x19'
                    self.sauth_data['platform'] = 'ad'
                    self.sauth_data['source_platform'] = 'ad'
                    self.sauth_data['app_channel'] = self.device_info.get('app_channel', 'netease.wyzymnqsd_cps_dev')
                    self.sauth_data['source_app_channel'] = 'netease'
                    self.sauth_data['login_channel'] = 'netease'
                    self.sauth_data['sdk_version'] = '5.9.0'
                    self.sauth_data['is_unisdk_guest'] = 0
                    self.sauth_data['get_access_token'] = '1'
                    self.sauth_data['gas_token'] = ''
                    self.sauth_data['ip'] = '127.0.0.1'
                    self.sauth_data['aim_info'] = '{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":""}'
                    
                    # 保存到sauth_data.json
                    self._save_sauth_data()
                    # 保存为cookie格式（使用用户邮箱作为文件名）
                    # 确保sauth_data已正确填充后再保存
                    if self.sauth_data and len(self.sauth_data) > 0 and self.sauth_data.get('sdkuid') and self.sauth_data.get('sessionid'):
                        self._save_cookie_format(email)
                    else:
                        print("⚠️  sauth_data未正确填充，跳过cookie保存")
                        print(f"调试信息: sauth_data keys = {list(self.sauth_data.keys()) if self.sauth_data else 'None'}")
                        print(f"sdkuid存在: {bool(self.sauth_data.get('sdkuid') if self.sauth_data else False)}")
                        print(f"sessionid存在: {bool(self.sauth_data.get('sessionid') if self.sauth_data else False)}")
                
                return {'status': 'success', 'user_info': result}
            else:
                # 其他错误
                error_code = result.get('code')
                error_reason = result.get('reason', '未知错误')
                if error_code:
                    print(f"❌ 登录失败: 错误代码 {error_code}, 原因: {error_reason}")
                else:
                    print(f"❌ 登录失败: {error_reason}")
                return {'status': 'failed', 'error': result}
                
        except Exception as e:
            print(f"登录异常: {e}")
            import traceback
            traceback.print_exc()
            return {'status': 'error', 'error': str(e)}
    
    def get_mailbox_list(self):
        """获取邮箱列表"""
        if not self.sauth_data.get('sessionid'):
            print("未找到有效的sessionid")
            return None
            
        url = 'https://mailbox.g.mkey.163.com/mpay/api/mailbox/fetch_list'
        
        params = {
            'game_id': self.device_info['game_id'],
            'user_id': self.sauth_data.get('sdkuid'),
            'device_id': self.device_info['device_id'],
            'token': self.sauth_data.get('sessionid'),
            'fetch_type': '0',
            'gv': self.device_info['gv'],
            'gvn': self.device_info['gvn'],
            'cv': self.device_info['cv'],
            'sv': self.device_info['sv'],
            'app_type': self.device_info['app_type'],
            'app_mode': self.device_info['app_mode'],
            'app_channel': self.device_info['app_channel'],
            'transid': self.transid,
            'mcount_app_key': self.device_info['mcount_app_key'],
            'mcount_transaction_id': self.mcount_transaction_id,
            '_cloud_extra_base64': self.device_info['_cloud_extra_base64'],
            'sc': self.device_info['sc']
        }
        
        try:
            response = self.session.get(url, params=params, headers=self._get_headers())
            result = response.json()
            print(f"邮箱列表: {result}")
            return result
        except Exception as e:
            print(f"获取邮箱列表失败: {e}")
            return None
    
    def get_cookies(self):
        """获取当前会话的cookies"""
        return self.session.cookies.get_dict()
    
    def save_cookies(self, filename='cookies.json'):
        """保存cookies到文件"""
        cookies = self.get_cookies()
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(cookies, f, ensure_ascii=False, indent=2)
            print(f"Cookies已保存到 {filename}")
            return True
        except Exception as e:
            print(f"保存cookies失败: {e}")
            return False
    
    def load_cookies(self, filename='cookies.json'):
        """从文件加载cookies"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                cookies = json.load(f)
                self.session.cookies.update(cookies)
            print(f"Cookies已从 {filename} 加载")
            return True
        except Exception as e:
            print(f"加载cookies失败: {e}")
            return False
    
    def extract_verify_info_from_url(self, verify_url):
        """从验证URL中提取ticket和code（参考nemc项目的extractVerifyInfo实现）"""
        ticket = ""
        code = ""
        
        if not verify_url:
            return ticket, code
        
        # 提取ticket
        if "ticket=" in verify_url:
            parts = verify_url.split("ticket=")
            if len(parts) > 1:
                ticket_part = parts[1].split("&")[0]
                ticket = ticket_part
        
        # 提取code
        if "code=" in verify_url:
            parts = verify_url.split("code=")
            if len(parts) > 1:
                code_part = parts[1].split("&")[0]
                code = code_part
        
        return ticket, code
    
    def extract_ticket_from_url(self, verify_url):
        """从验证URL中提取ticket"""
        try:
            parsed_url = urlparse(verify_url)
            params = parse_qs(parsed_url.query)
            ticket = params.get('ticket', [''])[0]
            return ticket
        except Exception as e:
            print(f"提取ticket失败: {e}")
            return None
    

    
    def verify_with_ticket(self, ticket):
        """使用ticket进行验证"""
        url = "https://service.mkey.163.com/mpay/api/reverify/upload_sms/result"
        
        data = {
            "ticket": ticket,
            "lang": "",
            "cv": self.device_info['cv'],
            "gv": self.device_info['gv'],
            "app_mode": self.device_info['app_mode'],
            "app_channel": self.device_info['app_channel'],
            "chg_pwd": "0"
        }
        
        headers = {
            "Host": "service.mkey.163.com",
            "Connection": "keep-alive",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0 (Linux; Android 12; BVL-AN20 Build/V417IR; wv) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://service.mkey.163.com",
            "Referer": f"https://service.mkey.163.com/mpay/api/reverify/upload_sms?ticket={ticket}",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"
        }
        
        try:
            response = self.session.post(url, data=data, headers=headers, timeout=30)
            result = response.json()
            
            if result.get("user"):
                # 验证成功，更新sauth_data
                user_data = result.get("user", {})
                if user_data:
                    # 生成client_login_sn
                    import random
                    import string
                    client_login_sn = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
                    
                    # 更新sauth_data
                    self.sauth_data['sdkuid'] = user_data.get('id', '')
                    self.sauth_data['sessionid'] = user_data.get('token', '')
                    self.sauth_data['udid'] = user_data.get('udid', self.udid)
                    self.sauth_data['deviceid'] = self.device_info['device_id']
                    self.sauth_data['client_login_sn'] = client_login_sn
                    self.sauth_data['gameid'] = 'x19'
                    self.sauth_data['platform'] = 'ad'
                    self.sauth_data['source_platform'] = 'ad'
                    self.sauth_data['app_channel'] = self.device_info.get('app_channel', 'netease.wyzymnqsd_cps_dev')
                    self.sauth_data['source_app_channel'] = 'netease'
                    self.sauth_data['login_channel'] = 'netease'
                    self.sauth_data['sdk_version'] = '5.9.0'
                    self.sauth_data['is_unisdk_guest'] = 0
                    self.sauth_data['get_access_token'] = '1'
                    self.sauth_data['gas_token'] = ''
                    self.sauth_data['ip'] = '127.0.0.1'
                    self.sauth_data['aim_info'] = '{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":""}'
                    
                    # 保存到文件
                    self._save_sauth_data()
                    # 保存为cookie格式（需要email，但这里没有，所以先不保存，等登录时再保存）
                
                    return {'status': 'success', 'user_info': user_data, 'ticket': ticket}
                else:
                    return {'status': 'failed', 'error': '验证成功但未获取到用户信息'}
            elif result.get("code") == 1351:
                # 验证未完成
                return {'status': 'pending', 'message': '验证未完成'}
            else:
                # 其他错误
                error_reason = result.get('reason', '验证失败')
                error_code = result.get('code', 0)
                return {'status': 'failed', 'error': error_reason, 'code': error_code}
        except Exception as e:
            print(f"使用ticket验证失败: {e}")
            return {'status': 'error', 'error': str(e)}

if __name__ == '__main__':
    auth = NetEaseEmailAuth()
    
    # 测试设备信息上传
    print("上传设备信息...")
    if auth.upload_device_info():
        print("设备信息上传成功")
    else:
        print("设备信息上传失败")
    
    # 测试邮箱登录
    email = input("请输入邮箱: ")
    password = input("请输入密码: ")
    
    print("尝试登录...")
    login_result = auth.login_email(email, password)
    print(f"登录结果: {login_result}")
    
    # 如果登录成功，获取邮箱列表
    if login_result.get('status') == 'success':
        print("获取邮箱列表...")
        mailbox = auth.get_mailbox_list()
        if mailbox:
            print("邮箱列表获取成功")
        
        # 保存cookies
        auth.save_cookies()
    else:
        print("登录失败，无法获取邮箱列表")