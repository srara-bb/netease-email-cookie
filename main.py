#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import os
import time
from netease_email_auth import NetEaseEmailAuth
from utils import CookieManager

def main():
    print("=== 网易邮箱登录工具 ===")
    print("1. 登录邮箱")
    print("2. 退出")
    
    auth = NetEaseEmailAuth()
    cookie_manager = CookieManager()
    
    while True:
        choice = input("\n请选择操作 (1-2): ").strip()
        
        if choice == '1':
            # 登录邮箱
            print("\n=== 邮箱登录 ===")
            email = input("请输入邮箱: ").strip()
            password = input("请输入密码: ").strip()
            
            print("上传设备信息...")
            if auth.upload_device_info():
                print("设备信息上传成功")
            else:
                print("设备信息上传失败，继续尝试登录...")
            
            print("尝试登录...")
            login_result = auth.login_email(email, password)
            
            if login_result.get('status') == 'success':
                print("✅ 登录成功!")
                user_info = login_result.get('user_info', {})
                print(f"用户信息: {json.dumps(user_info, ensure_ascii=False, indent=2)}")
                
                # 保存cookie格式文件
                auth._save_cookie_format(email)
                
                # 获取并保存HTTP cookies
                cookies = auth.get_cookies()
                cookie_manager.update_cookies(cookies)
                cookie_manager.save_cookies()
                print("✅ Cookies已保存")
                
                # 获取邮箱列表
                print("\n获取邮箱列表...")
                mailbox = auth.get_mailbox_list()
                if mailbox:
                    print("✅ 邮箱列表获取成功")
                    messages = mailbox.get('messages', [])
                    if messages:
                        print(f"共有 {len(messages)} 条消息:")
                        for msg in messages:
                            print(f"  - {msg.get('title', '无标题')}: {msg.get('abstract', '无内容')}")
                    else:
                        print("暂无消息")
                
            elif login_result.get('status') == 'need_verify':
                print("⚠️  需要安全验证")
                verify_url = login_result.get('verify_url')
                verify_code = login_result.get('code', '')
                verify_ticket = login_result.get('ticket', '')
                
                print(f"\n{'='*60}")
                if verify_code:
                    print(f"📱 验证码: {verify_code}")
                    print(f"📞 请发送验证码 {verify_code} 到 1069016373035")
                if verify_ticket:
                    print(f"🎫 Ticket: {verify_ticket}")
                print(f"🔗 验证链接: {verify_url}")
                print(f"{'='*60}\n")
                
                # 询问用户是否已完成验证
                choice = input("\n您是否已完成安全验证？(y/n): ").strip().lower()
                if choice == 'y':
                    print("正在确认验证状态...")
                    # 使用ticket确认验证
                    if verify_ticket:
                        verify_result = auth.verify_with_ticket(verify_ticket)
                        print(f"验证结果: {verify_result}")
                        if verify_result.get('status') == 'success':
                            print("✅ 验证确认成功！")
                            user_info = verify_result.get('user_info', {})
                            if user_info:
                                # 保存sauth_data和cookie
                                auth._save_sauth_data()
                                auth._save_cookie_format(email)
                                
                                print("✅ 登录成功，信息已保存！")
                                print(f"用户信息: {json.dumps(user_info, ensure_ascii=False, indent=2)}")
                                
                                # 获取并保存HTTP cookies
                                cookies = auth.get_cookies()
                                cookie_manager.update_cookies(cookies)
                                cookie_manager.save_cookies()
                                print("✅ Cookies已保存")
                                
                                # 获取邮箱列表
                                print("\n获取邮箱列表...")
                                mailbox = auth.get_mailbox_list()
                                if mailbox:
                                    print("✅ 邮箱列表获取成功")
                                    messages = mailbox.get('messages', [])
                                    if messages:
                                        print(f"共有 {len(messages)} 条消息:")
                                        for msg in messages:
                                            print(f"  - {msg.get('title', '无标题')}: {msg.get('abstract', '无内容')}")
                                    else:
                                        print("暂无消息")
                            else:
                                print("⚠️  验证成功但未获取到用户信息")
                        else:
                            print(f"⚠️  验证确认失败: {verify_result.get('error', '未知错误')}")
                    else:
                        print("⚠️  未找到ticket")
                else:
                    print("❌ 未完成验证，登录取消")
            elif login_result.get('status') == 'failed':
                # 登录失败
                error_info = login_result.get('error', {})
                error_code = error_info.get('code')
                error_reason = error_info.get('reason', '未知错误')
                
                print(f"❌ 登录失败")
                if error_code:
                    print(f"错误代码: {error_code}")
                print(f"错误原因: {error_reason}")
                
                # 如果是1311错误，提示用户
                if error_code == 1311:
                    print("\n提示: 错误代码 1311 表示用户登录已失效")
                    print("可能的原因:")
                    print("  1. 设备信息未正确上传")
                    print("  2. 设备密钥已过期")
                    print("  3. 网络连接问题")
                    print("  4. 账号密码错误")
                
            elif login_result.get('status') == 'error':
                # 登录异常
                error_msg = login_result.get('error', '未知错误')
                print(f"❌ 登录异常: {error_msg}")
                
            else:
                print("❌ 登录失败")
                error = login_result.get('error', '未知错误')
                print(f"错误信息: {error}")
        
        elif choice == '2':
            # 退出
            print("再见!")
            break
        
        else:
            print("无效选择，请输入1-2")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序已退出")
        sys.exit(0)
    except Exception as e:
        print(f"\n程序出错: {e}")
        sys.exit(1)
