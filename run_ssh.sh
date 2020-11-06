#!/bin/bash
# Date  : 2020-10-12
# Author: czn92
# Email : czn_1992@163.com
# Func  : 批量ssh登陆串口服务器

console_path="/home/admin/workspace/console/console"
server_ip="172.28.145.44"
username="admin"
password="admin"

login() {
    sshpass -p "$password" ssh -t $username@$server_ip sudo $console_path $1
}

login $1
ls
exit