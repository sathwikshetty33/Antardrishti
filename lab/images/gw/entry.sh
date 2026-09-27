#!/bin/sh
# gateway entry: config is mounted into /etc/swanctl and /etc/strongswan.conf
# by the orchestrator; charon runs in the foreground, logging to /var/log/charon.log
sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 2>/dev/null
exec sleep infinity
