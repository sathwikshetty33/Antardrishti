"""email (module named mail so it does not shadow the stdlib): swaks smtp submission (587, starttls) and imaplib fetches (143, starttls).

attachments are random 0-5 MB. think times between actions are random.
"""
import imaplib
import os
import random
import ssl
import subprocess
import time

from common import args, emit, launch, left, nap

words = ("report meeting budget quarter review draft invoice schedule update project "
         "network travel photo minutes agenda feedback release notes contract").split()


def start(duration, seed, ctx):
    return launch(ctx, "email", duration, seed)


def send(a, rng):
    att = ""
    size = 0
    if rng.random() < 0.6:
        size = int(rng.uniform(0, 5) ** 2 / 5 * 1024 * 1024)  # skewed toward small
        with open("/tmp/att.bin", "wb") as f:
            f.write(os.urandom(size))
        att = "--attach-type application/octet-stream --attach @/tmp/att.bin"
    body = " ".join(rng.choice(words) for _ in range(rng.randint(10, 400)))
    subj = " ".join(rng.choice(words) for _ in range(rng.randint(2, 6)))
    six = "-6" if a.fam == "v6" else "-4"
    cmd = (f"swaks {six} --server {a.ip} --port 587 --tls --to lab@lab.test "
           f"--from user{rng.randint(1, 50)}@lab.test --h-Subject '{subj}' --body '{body}' {att}")
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=max(5, left(a)))
    return {"action": "send", "attach_bytes": size, "rc": p.returncode}


def fetch(a, rng):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    m = imaplib.IMAP4(a.ip, 143, timeout=max(5, left(a)))
    m.starttls(ssl_context=ctx)
    m.login("lab", "lab-throwaway")
    m.select("INBOX")
    _, ids = m.search(None, "ALL")
    ids = ids[0].split()
    k = rng.randint(1, 5)
    got = 0
    for i in ids[-k:]:
        _, d = m.fetch(i, "(RFC822)")
        got += sum(len(x[1]) for x in d if isinstance(x, tuple))
    if len(ids) > 30:
        for i in ids[:-10]:
            m.store(i, "+FLAGS", "\\Deleted")
        m.expunge()
    m.logout()
    return {"action": "fetch", "messages": min(k, len(ids)), "bytes": got}


def main():
    a = args()
    rng = random.Random(a.seed)
    first = True
    while left(a) > 3:
        t = time.time()
        try:
            d = send(a, rng) if first or rng.random() < 0.6 else fetch(a, rng)
        except Exception as e:
            d = {"action": "error", "error": str(e)[:200]}
        first = False
        emit("email", d.pop("action"), t, **d)
        nap(a, rng.uniform(2, 15))


if __name__ == "__main__":
    main()
