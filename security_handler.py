#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import time
from urllib.parse import quote, urlparse, parse_qs

class SecurityVerificationHandler:
    def __init__(self, session):
        self.session = session
        
    def handle_verification(self, verify_url, email):
        """处理安全验证"""
        print("=== 安全验证处理 ===")
        print(f"验证URL: {verify_url}")
        
        # 解析验证URL获取参数
        parsed_url = urlparse(verify_url)
        params = parse_qs(parsed_url.query)
        
        # 提取关键参数
        code = params.get('code', [''])[0]
        ticket = params.get('ticket', [''])[0]
        chg_pwd = params.get('chg_pwd', ['0'])[0]
        
        print(f"验证码: {code}")
        print(f"票据: {ticket}")
        
        if not ticket:
            print("❌ 无法获取验证票据，请手动完成验证")
            return {'status': 'manual_required', 'url': verify_url}
        
        # 尝试自动提交验证结果
        result = self._submit_verification_result(ticket, code, chg_pwd)
        
        if result.get('status') == 'success':
            print("✅ 安全验证完成")
            return result
        else:
            print("⚠️  自动验证失败，需要手动操作")
            print("请按以下步骤操作：")
            print(f"1. 访问: {verify_url}")
            print("2. 完成安全验证（短信验证/邮箱验证等）")
            print("3. 验证成功后重新运行登录程序")
            return {'status': 'manual_required', 'url': verify_url}
    
    def send_sms_code(self, ticket):
        """发送短信验证码"""
        url = 'https://service.mkey.163.com/mpay/api/reverify/send_sms'
        
        headers = {
            'Host': 'service.mkey.163.com',
            'Connection': 'keep-alive',
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; BVL-AN20 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36;MPSDK/5.9.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://service.mkey.163.com',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        
        data = {
            'ticket': ticket,
            'lang': '',
            'cv': 'a5.9.0',
            'gv': '840282689',
            'app_mode': '2',
            'app_channel': 'netease.wyzymnqsd_cps_dev'
        }
        
        try:
            response = self.session.post(url, data=data, headers=headers)
            result = response.json()
            print(f"短信发送结果: {result}")
            
            if result.get('code') == 200:
                print("✅ 短信验证码已发送")
                return {'status': 'success', 'message': '短信验证码已发送'}
            else:
                return {'status': 'failed', 'error': result}
                
        except Exception as e:
            print(f"发送短信验证码失败: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _submit_verification_result(self, ticket, code, chg_pwd='0'):
        """提交验证结果"""
        url = 'https://service.mkey.163.com/mpay/api/reverify/upload_sms/result'
        
        headers = {
            'Host': 'service.mkey.163.com',
            'Connection': 'keep-alive',
            'Content-Length': '111',
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; BVL-AN20 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36;MPSDK/5.9.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://service.mkey.163.com',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        
        data = {
            'ticket': ticket,
            'lang': '',
            'cv': 'a5.9.0',
            'gv': '840282689',
            'app_mode': '2',
            'app_channel': 'netease.wyzymnqsd_cps_dev',
            'chg_pwd': chg_pwd
        }
        
        try:
            response = self.session.post(url, data=data, headers=headers)
            result = response.json()
            print(f"验证提交结果: {result}")
            
            if 'user' in result and result['user'].get('token'):
                # 验证成功，返回用户信息和token
                return {
                    'status': 'success',
                    'user_info': result['user'],
                    'token': result['user']['token']
                }
            else:
                return {'status': 'failed', 'error': result}
                
        except Exception as e:
            print(f"提交验证结果失败: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def check_verification_status(self, ticket):
        """检查验证状态"""
        url = 'https://service.mkey.163.com/mpay/api/reverify/check_status'
        
        data = {
            'ticket': ticket,
            'cv': 'a5.9.0',
            'gv': '840282689',
            'app_mode': '2',
            'app_channel': 'netease.wyzymnqsd_cps_dev'
        }
        
        try:
            response = self.session.post(url, data=data)
            result = response.json()
            return result
        except Exception as e:
            print(f"检查验证状态失败: {e}")
            return None

def manual_verification_guide(verify_url, email):
    """手动验证指南"""
    print("\n" + "="*50)
    print("📱 手动安全验证指南")
    print("="*50)
    print(f"📧 邮箱: {email}")
    print(f"🔗 验证链接: {verify_url}")
    print("\n📋 操作步骤:")
    print("1. 点击上方验证链接或在浏览器中打开")
    print("2. 选择验证方式（短信验证码/邮箱验证码）")
    print("3. 输入收到的验证码")
    print("4. 完成验证后关闭浏览器")
    print("5. 重新运行登录程序")
    print("\n⚠️  注意事项:")
    print("- 验证码有效期通常为5-10分钟")
    print("- 如收不到验证码，检查垃圾邮件箱")
    print("- 验证完成后账号安全性会提升")
    print("="*50)