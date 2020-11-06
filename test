#!/bin/bash
# Date  : 2020-10-12
# Author: czn92
# Email : czn_1992@163.com
# Func  : 批量ssh登陆串口服务器

port_amount="2002"
username="admin"
password="admin"
PORT_TXT="port.txt"

init() {
    touch . port.txt

    j=$port_amount
    for ((i=2001; i<=j; i++))
    do
        echo "$i" >> port.txt
    done
}

test() 
{
    local action

    action=$1
    echo ""
    echo "-------------------------------------------------------- "
    echo "username: $username  password: $password" 
    echo "command: "
    echo "Remote exec command script"
    echo "--------------------------------------------------------"
    echo ""

    if [ -f "$PORT_TXT" ]; then
        rm $PORT_TXT
        rm nohup.out
    fi

    init

    for ((i=1; i<=1; i++))
    do
        echo "----------Start No.$i round!------------"
        for port in `cat port.txt`;
        do
            #nohup ./run_ssh.sh &
            if [ "${action}" == "start" ]; then
                screen -dmS test_${port}_${i}
                screen -S test_${port}_${i} -p 0 -X stuff "./run_ssh.sh $port"
                screen -S test_${port}_${i} -p 0 -X stuff $'\n'
                screen -ls
                sleep 1
            elif [ "${action}" == "clear" ]; then
                screen -S test_${port}_${i} -X quit
            fi
        done
        echo "----------End of No.$i round"
    done
}

test $1
ls
exit
