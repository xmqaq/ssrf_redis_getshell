# ssrf_redis_getshell
通过ssrf漏洞对redis资产进行getshell的常见姿势

一、使用方法

1.需手动在代码中修改对应的ip和端口，以及三种方式所需的配置信息

2.所需环境: python2

example:
![image](https://user-images.githubusercontent.com/50257557/173984487-5a98d409-b68c-4c1f-be86-f0158aaae109.png)
输入想获取哪种类型的payload，curl即一次编码，burp对应的即为两次编码
![image](https://user-images.githubusercontent.com/50257557/173984651-b8ade100-4438-4d5f-af20-423d26ed049b.png)
