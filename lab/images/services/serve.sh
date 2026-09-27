#!/bin/sh
# starts every lab service. config lives in /etc/lab/conf, media is mounted at /srv/media
c=/etc/lab/conf

# bulk files: incompressible, fixed set of sizes (MB)
mkdir -p /srv/bulk
for s in 10 25 50 100 200; do
  [ -s /srv/bulk/f$s.bin ] || head -c ${s}M /dev/urandom > /srv/bulk/f$s.bin
done

# web / hls / bulk over https (h2) and http
cp $c/nginx.conf /etc/nginx/nginx.conf
nginx

# voip: asterisk echo on ext 100 (g711 + opus)
cp $c/pjsip.conf $c/extensions.conf $c/rtp.conf $c/modules.conf /etc/asterisk/
asterisk -f -U asterisk -G asterisk > /var/log/asterisk.out 2>&1 &

# email: postfix smtp (25 + 587 starttls) delivering to ~lab/Maildir, dovecot imap (143 starttls)
cp $c/postfix-main.cf /etc/postfix/main.cf
cp $c/postfix-master.cf /etc/postfix/master.cf
cp /etc/resolv.conf /var/spool/postfix/etc/ 2>/dev/null
newaliases
postfix start
cp $c/dovecot-lab.conf /etc/dovecot/conf.d/99-lab.conf
dovecot

# xmpp: prosody with two bot accounts
cp $c/prosody.cfg.lua /etc/prosody/prosody.cfg.lua
mkdir -p /etc/prosody/certs /run/prosody && chown prosody /run/prosody
cp /etc/lab/tls/cert.pem /etc/prosody/certs/lab.test.crt
cp /etc/lab/tls/key.pem /etc/prosody/certs/lab.test.key
chown -R prosody /etc/prosody/certs
su prosody -s /bin/sh -c "prosody -D" 2>/dev/null || prosody -D
sleep 1
prosodyctl register bot1 lab.test bot-throwaway >/dev/null 2>&1
prosodyctl register bot2 lab.test bot-throwaway >/dev/null 2>&1

# bulk over ssh: scp / rsync as user lab, key pushed by lab/topo.py
mkdir -p /run/sshd ~lab/.ssh && chown lab ~lab/.ssh
ln -sf /srv/bulk ~lab/bulk
/usr/sbin/sshd

# ready only when every service listens (tcp 22 25 80 143 443 587 5222, udp 5060)
for i in $(seq 1 30); do
  miss=""
  for p in 22 25 80 143 443 587 5222; do ss -lnt | grep -q ":$p " || miss="$miss tcp/$p"; done
  ss -lnu | grep -q ":5060 " || miss="$miss udp/5060"
  [ -z "$miss" ] && break
  sleep 1
done
if [ -n "$miss" ]; then echo "not listening:$miss" > /tmp/failed; else echo ready > /tmp/ready; fi
exec sleep infinity
