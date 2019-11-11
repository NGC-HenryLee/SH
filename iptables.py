#!/usr/bin/python
#-*- coding:utf-8 -*-
import os
import platform
import socket
import json
import operator
from sys import version_info
if version_info.major != 2 :
    import operator
    def cmp(parameta_a, parameta_b):
        if operator.eq(parameta_a,parameta_b):
            return 0
        return 1
Forward_dict={
        '网卡IP':{
            '转发端口':['落地IP','落地端口'],
        }
    }

def check_sys():
    sysinfo = platform.linux_distribution()[0] 
    if 'centos' in sysinfo.lower():
        return 'centos'
    return 'debian'
def check_iptables():
    iptables=0
    envpath = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    for cmdpath in envpath.split(':'):
        if os.path.isdir(cmdpath) and 'iptables' in os.listdir(cmdpath):
            iptables=1
    if not iptables:
        print("正在安装iptables")
        install_iptables()
        print("iptables安装完成")
    ip_forward_check = os.popen("/sbin/sysctl -p").read().replace("\n","").replace(" ","")
    if 'net.ipv4.ip_forward=1' not in ip_forward_check:
        print("add ip_forward")
        os.popen('echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf')
        os.popen('/sbin/sysctl -p')
    return 0
def install_iptables():
    if check_sys() == 'centos':
        os.popen("yum update")
        os.popen("yum install -y iptables")
    else:
        os.popen("apt-get update")
        os.popen("apt-get install -y iptables")
    if os.popen("/sbin/iptables -V")=='':
        try:
            sys.exit(0)
        except:
            print('安装iptables失败.')      
    else:
        if check_sys() == 'centos':
            os.popen('service iptables save')
            os.popen('chkconfig --level 2345 iptables on')
        else:
            os.popen('/sbin/iptables-save > /etc/iptables.up.rules')
            os.popen(r"echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables")  
            os.popen('chmod +x /etc/network/if-pre-up.d/iptables')          

def add_iptables(localip,localport,forwardip,forwardport):
    forwardip = socket.gethostbyname(forwardip)
    os.popen('/sbin/iptables -t nat -A PREROUTING -p tcp --dport %d -j DNAT --to-destination %s:%d'%(localport,forwardip,forwardport))
    os.popen('/sbin/iptables -t nat -A PREROUTING -p udp --dport %d -j DNAT --to-destination %s:%d'%(localport,forwardip,forwardport))
    os.popen("/sbin/iptables -t nat -A POSTROUTING -p tcp -d %s --dport %d -j SNAT --to-source %s"%(forwardip,forwardport,localip))
    os.popen("/sbin/iptables -t nat -A POSTROUTING -p udp -d %s --dport %d -j SNAT --to-source %s"%(forwardip,forwardport,localip))
    print("%s:%d转发至%s:%d完成"%(localip,localport,forwardip,forwardport))
    return 0
def iptables_save():
    if check_sys() == 'centos':
        os.popen("service iptables save")
        print("iptables储存完成*centos")
    else:
        os.system("/sbin/iptables-save > /etc/iptables.up.rules")
        if os.popen("cat /etc/iptables.up.rules").read().replace('\r','').replace('\n','').replace(' ','') == '':
            iptables_save()
        print("iptables储存完成*debian")

    return 0 

def Local_iptables_config():
    for localip in Forward_dict:
        localip = localip
    Forward_dict_Local = {
        localip:{
        }
    }
    config_raw = os.popen('/sbin/iptables -t nat -nL PREROUTING|tail -n +3').read()
    config_rules_list = config_raw.split('\n')
    if config_rules_list[-1] == '':
        del config_rules_list[-1]
    for config in config_rules_list:
        iptables_rules = config.split("dpt:")[1].split('to:')
        localport = iptables_rules[0].replace(' ','')
        forward = iptables_rules[1].split(':')
        forwardIP = forward[0]
        forwardPort = forward[1]
        forwardList = [forwardIP,forwardPort]
        Forward_dict_Local[localip][localport]  = forwardList
    return Forward_dict_Local
def data_add():
    print("正在添加转发")
    os.popen('/sbin/iptables -t nat -F')
    print(Forward_dict)
    for localip in Forward_dict:
        for localport in Forward_dict[localip]:
            forwardip = Forward_dict[localip][localport][0]
            forwardport = Forward_dict[localip][localport][1]
            add_iptables(localip,int(localport),forwardip,int(forwardport))
    iptables_save()
    return 0
check_iptables()
for key1 in Forward_dict:
    for key2 in Forward_dict[key1]:
        Forward_dict[key1][key2][0] = socket.gethostbyname(Forward_dict[key1][key2][0])
print(Local_iptables_config())
print(Forward_dict)
if cmp(Local_iptables_config(), Forward_dict)!= 0 :
    print("有变动")
    data_add()
else:
    print("无变动")

