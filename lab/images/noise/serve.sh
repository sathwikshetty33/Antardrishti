#!/bin/sh
# noise_b: dns (dnsmasq, a static lab zone), ntp (chrony server), http (python)
mkdir -p /srv/www
for i in $(seq 1 20); do head -c $((i * 7919)) /dev/urandom | base64 > /srv/www/p$i.txt; done
cat > /etc/dnsmasq.d/lab.conf <<EOD
no-resolv
no-hosts
listen-address=0.0.0.0,::
bind-interfaces
address=/lab.test/172.31.2.20
address=/lab.test/fd00:b::20
EOD
for i in $(seq 1 40); do echo "address=/h$i.lab.test/172.31.2.$((100 + i))" >> /etc/dnsmasq.d/lab.conf; done
dnsmasq --conf-dir=/etc/dnsmasq.d
printf 'local stratum 8\nallow all\nbindcmdaddress /var/run/chrony/chronyd.sock\n' > /etc/chrony/chrony.conf
chronyd -x -f /etc/chrony/chrony.conf
cd /srv/www && exec python3 -m http.server --bind :: 80
