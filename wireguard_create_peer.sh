mkdir /etc/wireguard/*peer_name*
wg genkey | tee /etc/wireguard/*peer_name*/*peer_name*_privatekey | wg pubkey > /etc/wireguard/*peer_name*/*peer_name*_publickey

cat <<EOT >> /etc/wireguard/wg0.conf

[Peer]
PublicKey = $(cat /etc/wireguard/*peer_name*/*peer_name*_publickey)
AllowedIPs = *peer_private_ips*
EOT

systemctl restart wg-quick@wg0

cat <<EOT > /etc/wireguard/*peer_name*/*peer_name*_client_file
[Interface]
PrivateKey = $(cat /etc/wireguard/*peer_name*/*peer_name*_privatekey)
Address = *peer_private_ips*
DNS = 8.8.8.8

[Peer]
PublicKey = $(cat /etc/wireguard/publickey)
Endpoint = $(curl http://169.254.169.254/latest/meta-data/public-ipv4):*wg_port*
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20
EOT

echo '================================================'

cat /etc/wireguard/*peer_name*/*peer_name*_client_file

echo '================================================'