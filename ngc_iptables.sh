#!/bin/sh

local_ip="这里填中转鸡内网IP"
s_port="这里填中转鸡端口，如：1584"
d_port="这里填落地机端口，如：1584"
d_domain="这里填你落地机的DDNS"



get_ip=`ping -c 1 $d_domain | grep 'PING' | awk '{print $3}' | sed 's/[(,)]//g'`

cd `dirname $0`

if [ -e './ngc_iptables_DDNS_ip.txt' ]; then
	old_ip=`tail ./ngc_iptables_DDNS_ip.txt -n 1`
	if ! [ "$old_ip" = "$get_ip"  ]; then
	`/sbin/iptables -t nat -D PREROUTING -d $local_ip/32 -p tcp -m tcp --dport $s_port -j DNAT --to-destination $old_ip:$d_port`
	`/sbin/iptables -t nat -D POSTROUTING -d $old_ip/32 -p tcp -m tcp --dport $d_port -j SNAT --to-source $local_ip`
        `/sbin/iptables -t nat -D PREROUTING -d $local_ip/32 -p udp -m udp --dport $s_port -j DNAT --to-destination $old_ip:$d_port`
        `/sbin/iptables -t nat -D POSTROUTING -d $old_ip/32 -p udp -m udp --dport $d_port -j SNAT --to-source $local_ip`

	`/sbin/iptables -t nat -A PREROUTING -d $local_ip/32 -p tcp -m tcp --dport $s_port -j DNAT --to-destination $get_ip:$d_port`
	`/sbin/iptables -t nat -A POSTROUTING -d $get_ip/32 -p tcp -m tcp --dport $d_port -j SNAT --to-source $local_ip`
        `/sbin/iptables -t nat -A PREROUTING -d $local_ip/32 -p udp -m udp --dport $s_port -j DNAT --to-destination $get_ip:$d_port`
	`/sbin/iptables -t nat -A POSTROUTING -d $get_ip/32 -p udp -m udp --dport $d_port -j SNAT --to-source $local_ip`

	echo $get_ip >> ./ngc_iptables_DDNS_ip.txt
	fi
        else
	echo $get_ip >> ./ngc_iptables_DDNS_ip.txt
       `/sbin/iptables -t nat -A PREROUTING -d $local_ip/32 -p tcp -m tcp --dport $s_port -j DNAT --to-destination $get_ip:$d_port`
       `/sbin/iptables -t nat -A POSTROUTING -d $get_ip/32 -p tcp -m tcp --dport $d_port -j SNAT --to-source $local_ip`
       `/sbin/iptables -t nat -A PREROUTING -d $local_ip/32 -p udp -m udp --dport $s_port -j DNAT --to-destination $get_ip:$d_port`
       `/sbin/iptables -t nat -A POSTROUTING -d $get_ip/32 -p udp -m udp --dport $d_port -j SNAT --to-source $local_ip`	
       fi

