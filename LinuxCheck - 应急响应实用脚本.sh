# LinuxCheck - 应急响应实用脚本

#!/usr/bin/env bash

# 设置保存文件

# interface=$(cat /etc/network/interfaces | ag '(?<=\biface\b).*(?=\binet\b)' | ag -v 'lo|docker' | awk '{print $2}' | head -n 1) 2>/dev/null

ipaddress=$(ip addr | ag -o '(?<=inet | inet addr:)\d+\.\d+\.\d+\.\d+' | ag -v '127.0.0.1' | head -n 1) 2>/dev/null
FileName=$ipaddress'_'$(hostname)'_'$(whoami)'_'$(date +%s)'.log' 2>/dev/null

echo -e "==================================================" | tee -a $FileName
echo -e "                Linux 应急响应 V3.3                " | tee -a $FileName
echo -e "==================================================" | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo -e "# 支持CentOS、Debian系统检测                        " | tee -a $FileName
echo -e "# 原author：al0ne                                  " | tee -a $FileName
echo -e "# 原项目：https://github.com/al0ne/LinuxCheck      " | tee -a $FileName
echo -e "# 更新项目：https://gitee.com/hulu20/LinuxCheck    " | tee -a $FileName
echo -e "# 对项目做了细微优化处理                            " | tee -a $FileName
echo -e "# 最新版本更新作者 author：利刃信安 - Mannix        " | tee -a $FileName
echo -e "# 最新版本更新日期：2021年4月29日                   " | tee -a $FileName
echo -e "\n" | tee -a $FileName

# WebPath

# 设置WebPath目录 默认的话是从/目录去搜索 性能较慢

WebPath='/'

# 环境检测开始 ……

echo -e "\e[00;31m[+] 环境检测开始……\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 系统信息

echo -e "\e[00;31m[+] 系统信息\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName

# CurrentUser 当前用户

echo -e "CurrentUser:\t\t" $(whoami) 2>/dev/null | tee -a $FileName

# OS Version 版本信息

echo -e "OS Version:\t" $(uname -r) 2>/dev/null | tee -a $FileName

# Hostname 主机名

echo -e "Hostname: \t" $(hostname -s) 2>/dev/null | tee -a $FileName

# Uptime

echo -e "Uptime: \t" $(uptime | awk -F ',' '{print $1}') 2>/dev/null | tee -a $FileName

# CPU info CPU信息

echo -e "CPU info:\t" $(cat /proc/cpuinfo | ag -o '(?<=model name\t: ).*' | head -n 1)  2>/dev/null | tee -a $FileName

# ipaddress

ipaddress=$(ifconfig | ag -o '(?<=inet | inet addr:)\d+\.\d+\.\d+\.\d+' | ag -v '127.0.0.1')  2>/dev/null
echo -e "IPADDR:\t\t${ipaddress}" | sed ":a;N;s/\n/ /g;ta" | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 验证是否为root权限

if [ $UID -ne 0 ]; then
    echo -e "\n\e[00;33m请使用root权限运行\e[00m" | tee -a $FileName
    exit 1
else
    echo -e "\e[00;32m当前为root权限\e[00m" | tee -a $FileName
fi

# 验证操作系统是debian系还是CentOS

OS='None'

if [ -e "/etc/os-release" ]; then
    source /etc/os-release
    case ${ID} in
    "debian" | "ubuntu" | "devuan")
        OS='Debian'
        ;;
    "CentOS" | "rhel fedora" | "rhel")
        OS='CentOS'
        ;;
    *) ;;
    esac
fi

if [ $OS = 'None' ]; then
    if command -v apt-get >/dev/null 2>&1; then
        OS='Debian'
    elif command -v yum >/dev/null 2>&1; then
        OS='CentOS'
    else
        echo -e "\n不支持这个系统\n" | tee -a $FileName
        echo -e "已退出" | tee -a $FileName
        exit 1
    fi
fi

# ifconfig

if ifconfig >/dev/null 2>&1; then
    echo -e "\e[00;32mifconfig已安装\e[00m" | tee -a $FileName
else
    if [ $OS = 'CentOS' ]; then
        yum -y install net-tools >/dev/null 2>&1
    else
        apt-get -y install net-tools >/dev/null 2>&1
    fi
fi

# CentOS安装lsof

if lsof -v >/dev/null 2>&1; then
    echo -e "\e[00;32mlsof已安装\e[00m" | tee -a $FileName
else
    if [ $OS = 'CentOS' ]; then
        yum -y install lsof >/dev/null 2>&1
    else
        apt-get -y install lsof >/dev/null 2>&1
    fi
fi

# 检测ag软件有没有安装

if ag -V >/dev/null 2>&1; then
    echo -e "\e[00;32msilversearcher-ag已安装\e[00m" | tee -a $FileName
else
    if [ $OS = 'CentOS' ]; then
        yum -y install the_silver_searcher >/dev/null 2>&1
    else
        apt-get -y install silversearcher-ag >/dev/null 2>&1
    fi
fi

# 检测rkhunter有没有安装

if rkhunter -V >/dev/null 2>&1; then
    echo -e "\e[00;32mrkhunter已安装\e[00m" | tee -a $FileName
else
    if [ $OS = 'CentOS' ]; then
        yum -y install rkhunter >/dev/null 2>&1
    else
        apt-get -y install rkhunter >/dev/null 2>&1
    fi
fi

echo -e "\n" | tee -a $FileName

# 系统改动

# 对比hash，看看有没有系统文件被替换掉

echo -e "\e[00;31m[+] 系统改动\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
if [ $OS = 'CentOS' ]; then
    rpm -Va | tee -a $FileName
else
    apt install -y debsums >/dev/null 2>&1
    debsums -e | ag -v 'OK' | tee -a $FileName
fi
echo -e "\n" | tee -a $FileName

# CPU使用率

echo -e "\e[00;31m[+] CPU使用率: \e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
    echo "$line" | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}' | tee -a $FileName
done
echo -e "\n" | tee -a $FileName

# 登录用户

echo -e "\e[00;31m[+] 登录用户\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
w | tee -a $FileName
echo -e "\n" | tee -a $FileName
who -H | tee -a $FileName
echo -e "\n" | tee -a $FileName

# CPU占用TOP15

cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
echo -e "\e[00;31m[+] CPU TOP15: \e[00m\n\n${cpu}\n" | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 内存占用

echo -e "\e[00;31m[+] 内存占用\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
free -mh | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 剩余空间

echo -e "\e[00;31m[+] 剩余空间\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
df -mh | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 硬盘挂载

echo -e "\e[00;31m[+] 硬盘挂载\e[00m" | tee -a $FileName
cat /etc/fstab | ag -v "#" | awk '{print $1,$2,$3}' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ifconfig

echo -e "\e[00;31m[+] ifconfig\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
/sbin/ifconfig -a | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ip address

echo -e "\e[00;31m[+] ip address\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ip add | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 网络流量

echo -e "\e[00;31m[+] 网络流量\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo "Interface    ByteRec   PackRec   ByteTran   PackTran" | tee -a $FileName
awk ' NR>2' /proc/net/dev | while read line; do
    echo "$line" | awk -F ':' '{print "  "$1"  " $2}' | 
        awk '{print $1"   "$2 "    "$3"   "$10"  "$11}' | tee -a $FileName
done
echo -e "\n" | tee -a $FileName

# 端口监听

echo -e "\e[00;31m[+] 端口监听\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
netstat -atunlpe | ag 'tcp|udp.*' --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 对外开放端口

echo -e "\e[00;31m[+] 对外开放端口\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
netstat -atunlpe | awk '{print $1,$4}' | ag -o '.*0.0.0.0:(\d+)|:::\d+' --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 网络连接

echo -e "\e[00;31m[+] 网络连接\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
netstat -atunlpe | ag ESTABLISHED --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# TCP连接状态

echo -e "\e[00;31m[+] TCP连接状态\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 路由表

echo -e "\e[00;31m[+] 路由表\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
/sbin/route -nee | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 路由转发

echo -e "\e[00;31m[+] 路由转发\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}') 2>/dev/null
if [ -n "$ip_forward" ]; then
    echo -e "/proc/sys/net/ipv4/ip_forward 已开启路由转发" | tee -a $FileName
else
    echo -e "该服务器未开启路由转发" | tee -a $FileName
fi
echo -e "\n" | tee -a $FileName

# DNS Server

echo -e "\e[00;31m[+] DNS Server\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat /etc/resolv.conf | ag -o '\d+\.\d+\.\d+\.\d+' --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ARP

echo -e "\e[00;31m[+] ARP\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
arp -n -a | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 网卡混杂模式

echo -e "\e[00;31m[+] 网卡混杂模式\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
if ip link | ag PROMISC >/dev/null 2>&1; then
    echo -e "网卡存在混杂模式！" | tee -a $FileName
else
    echo -e "网卡不存在混杂模式" | tee -a $FileName
fi
echo -e "\n" | tee -a $FileName

# 常用软件

echo -e "\e[00;31m[+] 常用软件\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cmdline=(
    "which perl"
    "which gcc"
    "which g++"
    "which python"
    "which php"
    "which cc"
    "which go"
    "which node"
    "which nodejs"
    "which bind"
    "which tomcat"
    "which clang"
    "which ruby"
    "which curl"
    "which wget"
    "which mysql"
    "which redis"
    "which ssserver"
    "which vsftpd"
    "which java"
    "which apache"
    "which nginx"
    "which git"
    "which mongodb"
    "which docker"
    "which tftp"
    "which psql"
)

for prog in "${cmdline[@]}"; do
    soft=$($prog)
    if [ "$soft" ] 2>/dev/null; then
        echo -e "$soft" | ag -o '\w+$' --nocolor | tee -a $FileName
    fi
done
echo -e "\n" | tee -a $FileName

# Crontab

echo -e "\e[00;31m[+] Crontab\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
crontab -u root -l | ag -v '#' --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName
crontab  -l | ag -v '#' --nocolor | tee -a $FileName
ls -alht /etc/cron.*/* | tee -a $FileName
echo -e "\n" | tee -a $FileName

# Crontab Backdoor Crontab可疑命令

echo -e "\e[00;31m[+] Crontab Backdoor\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ag '((?:useradd|groupadd|chattr)|(?:wget\s|curl\s|tftp\s\-i|scp\s|sftp\s)|(?:bash\s\-i|fsockopen|nc\s\-e|sh\s\-i|\"/bin/sh\"|\"/bin/bash\"))' /etc/cron* /var/spool/cron/* --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# env

echo -e "\e[00;31m[+] env\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
env | tee -a $FileName
echo -e "\n" | tee -a $FileName

# PATH

echo -e "\e[00;31m[+] PATH\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo $PATH | tee -a $FileName
echo -e "\n" | tee -a $FileName

# LD_PRELOAD

echo -e "\e[00;31m[+] LD_PRELOAD\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo ${LD_PRELOAD} | tee -a $FileName
echo -e "\n" | tee -a $FileName

# LD_ELF_PRELOAD

echo -e "\e[00;31m[+] LD_ELF_PRELOAD\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo ${LD_ELF_PRELOAD} | tee -a $FileName
echo -e "\n" | tee -a $FileName

# LD_LIBRARY_PATH

echo -e "\e[00;31m[+] LD_LIBRARY_PATH\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo ${LD_LIBRARY_PATH} | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ld.so.preload

echo -e "\e[00;31m[+] ld.so.preload\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
preload='/etc/ld.so.preload'
if [ -e "${preload}" ]; then
    cat ${preload} | tee -a $FileName
else
    echo -e "/etc/ld.so.preload 文件不存在" | tee -a $FileName
fi
echo -e "\n" | tee -a $FileName

# 可登录用户账号

echo -e "\e[00;31m[+] 可登录用户账号\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat /etc/passwd | ag -v 'nologin$|false$' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# passwd文件修改日期

echo -e "\e[00;31m[+] passwd文件修改日期:\e[00m\n\n" $(stat /etc/passwd | ag -o '(?<=Modify: ).*' --nocolor) 2>/dev/null | tee -a $FileName
echo -e "\n" | tee -a $FileName

# sudoers(请注意NOPASSWD)

echo -e "\e[00;31m[+] sudoers(请注意NOPASSWD)\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat /etc/sudoers | ag -v '#' | sed -e '/^$/d' | ag ALL --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# IPTABLES防火墙

echo -e "\e[00;31m[+] IPTABLES防火墙\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
iptables -L | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 登录用户信息

echo -e "\e[00;31m[+] 登录用户信息\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
w | tee -a $FileName
echo -e "\n" | tee -a $FileName
last -n 20 -a -i | tee -a $FileName
echo -e "\n" | tee -a $FileName
lastlog | ag -v 'Never' | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo "登录ip:" $(ag -a Accepted /var/log/secure /var/log/auth.* 2>/dev/null | ag -o '\d+\.\d+\.\d+\.\d+' | sort | uniq) 2>/dev/null | tee -a $FileName
echo -e "\n" | tee -a $FileName

# SSH暴破IP

echo -e "\e[00;31m[+] SSH暴破IP\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
if [ $OS = 'CentOS' ]; then
    ag -a 'authentication failure' /var/log/secure* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25 | tee -a $FileName
else
    ag -a 'authentication failure' /var/log/auth.* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25 | tee -a $FileName

fi
echo -e "\n" | tee -a $FileName

# 运行服务 Service

echo -e "\e[00;31m[+] Service\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
if [ $OS = 'CentOS' ]; then
    systemctl -l | grep running | awk '{print $1}' | tee -a $FileName
else
    service --status-all | ag -Q '+' --nocolor | tee -a $FileName
fi
echo -e "\n" | tee -a $FileName

# 查看History文件

echo -e "\e[00;31m[+] History\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ls -alht ~/.*_history | tee -a $FileName
ls -alht /root/.*_history | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat ~/.*history | ag '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b' --nocolor | ag -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# /etc/hosts

echo -e "\e[00;31m[+] /etc/hosts\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat /etc/hosts | ag -v "#" | tee -a $FileName
echo -e "\n" | tee -a $FileName

# /etc/profile

echo -e "\e[00;31m[+] /etc/profile\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat /etc/profile | ag -v '#' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# /etc/rc.local

echo -e "\e[00;31m[+] /etc/rc.local\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat /etc/rc.local | ag -v '#' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ~/.bash_profile

echo -e "\e[00;31m[+] ~/.bash_profile\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat ~/.bash_profile | ag -v '#' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ~/.bashrc

echo -e "\e[00;31m[+] ~/.bashrc\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
cat ~/.bashrc | ag -v '#' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# bash反弹shell

echo -e "\e[00;31m[+] bash反弹shell\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ps -ef | ag 'bash -i' | ag -v 'ag' | awk '{print $2}' | xargs -i{} lsof -p {} | ag 'ESTABLISHED' --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# SSHD

echo -e "\e[00;31m[+] SSHD\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
echo -e "/usr/sbin/sshd"
stat /usr/sbin/sshd | ag 'Access | Modify | Change' --nocolor | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ...隐藏文件

# Linux下常用的隐藏手法

echo -e "\e[00;31m[+] ...隐藏文件\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*." | tee -a $FileName
echo -e "\n" | tee -a $FileName

# /tmp目录

echo -e "\e[00;31m[+] /tmp\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ls -alht /tmp /var/tmp /dev/shm | tee -a $FileName
echo -e "\n" | tee -a $FileName

# alias 别名

echo -e "\e[00;31m[+] alias\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
alias | ag -v 'git' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# SUID

echo -e "\e[00;31m[+] SUID\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
find / ! -path "/proc/*" -perm -004000 -type f | ag -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# lsof +L1

#进程存在但文件已经没有了

echo -e "\e[00;31m[+] lsof +L1\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
lsof +L1 | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 近七天文件改动 mtime

echo -e "\e[00;31m[+] 近七天文件改动 mtime\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
find /etc /bin /lib /sbin /dev /root/ /home /tmp /opt /var ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {} | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 近七天文件改动 ctime

echo -e "\e[00;31m[+] 近七天文件改动 ctime\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
find /etc /bin /lib /sbin /dev /root/ /home /tmp /opt /var ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {} | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 大文件>200mb

# 有些黑客会将数据库、网站打包成一个文件然后下载

echo -e "\e[00;31m[+] 大文件>100mb\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +100M -print 2>/dev/null | xargs -i{} ls -alh {} | ag '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' --nocolor | ag -v 'ib_logfile|ibd｜mysql-bin｜mysql-slow｜ibdata1' | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 敏感文件

echo -e "\e[00;31m[+] 敏感文件\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*minerd|.*/ew$' -type f | ag -v '/lib/python' | xargs -i{} ls -alh {} | tee -a $FileName
echo -e "\n" | tee -a $FileName

# lsmod 可疑模块

echo -e "\e[00;31m[+] lsmod 可疑模块\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
lsmod | ag -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl" | tee -a $FileName
echo -e "\n" | tee -a $FileName

# Rootkit 内核模块

echo -e "\e[00;31m[+] Rootkit 内核模块\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
kernel=$(cat /proc/kallsyms | egrep 'hide_tcp4_port|hidden_files|hide_tcp6_port') 2>/dev/null
if [ -n "$kernel" ]; then
    echo -e "存在内核敏感函数！ 疑似Rootkit内核模块" | tee -a $FileName
else
    echo -e "未找到内核敏感函数" | tee -a $FileName
fi
echo -e "\n" | tee -a $FileName

# 检查SSH key

echo -e "\e[00;31m[+] SSH key\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
sshkey=${HOME}/.ssh/authorized_keys
if [ -e "${sshkey}" ]; then
    cat ${sshkey} | tee -a $FileName
else
    echo -e "SSH key文件不存在\n" | tee -a $FileName
fi
echo -e "\n" | tee -a $FileName

# PHP WebShell查杀

echo -e "\e[00;31m[+] PHP WebShell查杀\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ag --php -l -s -i 'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' $WebPath | tee -a $FileName
ag --php -l -s -i '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' $WebPath | tee -a $FileName
ag --php -l -s -i '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))' $WebPath | tee -a $FileName
ag --php -l -s -i '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' $WebPath | tee -a $FileName
ag --php -l -s -i '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' $WebPath | tee -a $FileName
ag --php -l -s -i "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" $WebPath | tee -a $FileName
echo -e "\n" | tee -a $FileName

# JSP WebShell查杀

echo -e "\e[00;31m[+] JSP WebShell查杀\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ag --jsp -l -s -i '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' $WebPath | tee -a $FileName
echo -e "\n" | tee -a $FileName

# ASP/ASPX WebShell查杀

echo -e "\e[00;31m[+] ASP/ASPX WebShell查杀\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ag -G ".+\.asp" -l -i -s '<%@codepage=65000[\s\S]*=936:|<%eval\srequest\(\"|<%@\sPage\sLanguage=\"Jscript\"[\s\S]*eval\(\w+\+|<%@.*eval\(Request\.Item' $WebPath | tee -a $FileName
echo -e "\n" | tee -a $FileName

# 挖矿木马检测

echo -e "\e[00;31m[+] 挖矿木马检测\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
ps aux | ag "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb" | ag -v "ag|$0" | tee -a $FileName
echo -e "\n" | tee -a $FileName

# Rkhunter查杀

echo -e "\e[00;31m[+] Rkhunter查杀\e[00m" | tee -a $FileName
echo -e "\n" | tee -a $FileName
if rkhunter >/dev/null 2>&1; then
    rkhunter --checkall --sk | ag -v 'OK | Not found | None found' | tee -a $FileName
else
    if [ -e "rkhunter.tar.gz" ]; then
        tar -zxvf rkhunter.tar.gz >/dev/null 2>&1
        cd rkhunter-1.4.6/
        ./installer.sh --install >/dev/null 2>&1
        rkhunter --checkall --sk | ag -v 'OK | Not found | None found' | tee -a $FileName
    else
        echo -e "找不到rkhunter.tar.gz尝试下载"
        wget https://github.com/al0ne/LinuxCheck/raw/master/rkhunter.tar.gz >/dev/null 2>&1
        tar -zxvf rkhunter.tar.gz >/dev/null 2>&1
        cd rkhunter-1.4.6/
        ./installer.sh --install >/dev/null 2>&1
        rkhunter --checkall --sk | ag -v 'OK | Not found | None found' | tee -a $FileName
    fi
fi