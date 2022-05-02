export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT=$(date +%F-%T | tr ':' '_')

VPN_USER='*username*'
VPN_PASSWORD='*password*'

sed -i "/^\"$VPN_USER\" /d" /etc/ppp/chap-secrets
cat >> /etc/ppp/chap-secrets <<EOF
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
EOF

sed -i '/^'"$VPN_USER"':\$1\$/d' /etc/ipsec.d/passwd
VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
cat >> /etc/ipsec.d/passwd <<EOF
$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
EOF

chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
echo "If you forgot the PSK, check /etc/ipsec.secrets."
cat <<EOF

================================================

VPN user to add or update:

Server address: $(curl http://169.254.169.254/latest/meta-data/public-ipv4)
Username: $VPN_USER
Password: $VPN_PASSWORD

PSK: $(cat /etc/ipsec.secrets)

================================================

EOF
