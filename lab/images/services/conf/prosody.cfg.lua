admins = { }
modules_enabled = {
  "roster"; "saslauth"; "tls"; "disco"; "carbons"; "pep"; "private";
  "vcard4"; "vcard_legacy"; "ping"; "register"; "posix"; "smacks"; "csi_simple";
}
allow_registration = false
c2s_require_encryption = true
s2s_require_encryption = true
authentication = "internal_hashed"
pidfile = "/run/prosody/prosody.pid"
daemonize = true
interfaces = { "*", "::" }
log = { info = "/var/log/prosody/prosody.log"; error = "/var/log/prosody/prosody.err"; }
certificates = "certs"
VirtualHost "lab.test"
  ssl = { key = "/etc/prosody/certs/lab.test.key"; certificate = "/etc/prosody/certs/lab.test.crt"; }
