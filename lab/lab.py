"""shared helpers: shell, docker exec, template rendering"""
import subprocess
from pathlib import Path

import jinja2

root = Path(__file__).resolve().parent.parent
tpl = jinja2.Environment(loader=jinja2.FileSystemLoader(root / "lab" / "swanctl"),
                         trim_blocks=True, lstrip_blocks=True,
                         undefined=jinja2.StrictUndefined)


def sh(cmd, check=True, timeout=300, input=None):
    """run a shell command, return (rc, combined output)"""
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       timeout=timeout, input=input)
    out = (p.stdout + p.stderr).strip()
    if check and p.returncode:
        raise RuntimeError(f"{cmd}\n-> rc {p.returncode}: {out[-2000:]}")
    return p.returncode, out


def dx(name, cmd, check=True, timeout=300, detach=False):
    """docker exec a shell command inside a container"""
    flag = "-d" if detach else ""
    esc = cmd.replace("'", "'\\''")
    return sh(f"docker exec {flag} {name} sh -c '{esc}'", check, timeout)


def put(name, path, text):
    """write text to a file inside a container"""
    sh(f"docker exec -i {name} sh -c 'cat > {path}'", input=text)


def render(name, **ctx):
    return tpl.get_template(name).render(**ctx)


def bridge_off():
    """lab bridges must act as plain switches: docker's forward rules drop
    bridged frames between our subnets when br_netfilter hands them to iptables"""
    sh("sudo sysctl -qw net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0")
    return "bridge-nf-call-ip(6)tables=0"
