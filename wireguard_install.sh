#!/bin/bash

apt update && apt upgrade -y
apt install -y wireguard

sed -i "s/#Port 22/Port *ssh_port*/g" /etc/ssh/sshd_config

wg genkey | tee /etc/wireguard/privatekey | wg pubkey | tee /etc/wireguard/publickey
chmod 600 /etc/wireguard/privatekey
touch /etc/wireguard/wg0.conf

cat <<EOT > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $(cat /etc/wireguard/privatekey)
Address = $(curl http://169.254.169.254/latest/meta-data/local-ipv4)/24
ListenPort = *wg_port*
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOT

echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
systemctl enable wg-quick@wg0.service
systemctl start wg-quick@wg0.service
