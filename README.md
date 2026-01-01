# 网易邮箱登录工具

这是一个基于抓包数据分析实现的网易邮箱登录工具，支持邮箱登录、Cookie管理和邮箱信息获取。

## 功能特性

-  网易邮箱登录验证
-  设备信息模拟上传
-  Cookie自动拼接和管理
-  邮箱消息列表获取

## 文件说明

- `netease_email_auth.py` - 核心认证模块，实现邮箱登录逻辑
- `utils.py` - 工具类，包含加密、Cookie管理等辅助功能
- `main.py` - 主程序入口，提供交互式界面
- `sauth_data.json` - 认证相关配置数据
- `requirements.txt` - Python依赖包列表

## 使用方法

### 安装依赖

```
pip install -r requirements.txt
pip install pycryptodome

```

### 运行程序

```bash
python main.py
```

### 操作流程

**登录邮箱**: 输入邮箱和密码进行登录

## 注意事项

- 如遇安全验证，需要手动完成验证流程
- Cookie会自动保存到`cookies.json`文件中
- 生成完成后，请查看nemc开头的文件
- 一个手机号一天内只能验证2次安全验证

## 技术实现

- 基于Python requests库实现HTTP请求
- 模拟移动端设备信息和请求头
- 实现了网易邮箱登录的完整流程
- 支持Cookie的自动拼接

## 免责声明

本工具仅供学习和研究使用，请勿用于非法用途。使用者应当遵守相关法律法规和网站服务条款。
