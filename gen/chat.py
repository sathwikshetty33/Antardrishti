"""chat (live): two xmpp bots on the client side talking through prosody.

conversation turns with typing indicators (xep-0085), reply delays and
message lengths drawn from skewed distributions, occasional bursts.
"""
import asyncio
import random
import ssl
import time

from common import args, emit, launch, left

words = ("ok yes no sure lol thanks see you soon where are you now coming later call me "
         "meeting done send the file tomorrow tonight lunch? good morning haha nice great "
         "on my way traffic is bad reached home check this photo when free").split()


def start(duration, seed, ctx):
    return launch(ctx, "chat", duration, seed)


def text(rng):
    n = max(1, int(rng.lognormvariate(1.4, 0.9)))
    return " ".join(rng.choice(words) for _ in range(min(n, 80)))


async def talk(a, rng):
    from slixmpp import ClientXMPP
    bots = {}
    for me in ("bot1", "bot2"):
        x = ClientXMPP(f"{me}@lab.test/lab", "bot-throwaway")
        x.register_plugin("xep_0085")
        x.register_plugin("xep_0199")
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        x.ssl_context = c
        x.enable_plaintext = False
        x.ready = asyncio.Event()

        async def on_start(ev, x=x):
            x.send_presence()
            await x.get_roster()
            x.ready.set()
        x.add_event_handler("session_start", on_start)
        x.connect(host=a.ip, port=5222)
        bots[me] = x
    await asyncio.wait_for(asyncio.gather(*(b.ready.wait() for b in bots.values())), 30)
    emit("chat", "connected", time.time())
    cur = rng.choice(["bot1", "bot2"])
    while left(a) > 2:
        peer = "bot2" if cur == "bot1" else "bot1"
        for _ in range(1 if rng.random() < 0.7 else rng.randint(2, 4)):
            msg = text(rng)
            typing = min(len(msg) * rng.uniform(0.05, 0.2), max(0.2, left(a) - 1))
            s = bots[cur].make_message(mto=f"{peer}@lab.test", mtype="chat")
            s["chat_state"] = "composing"
            s.send()
            await asyncio.sleep(typing)
            t = time.time()
            m = bots[cur].make_message(mto=f"{peer}@lab.test", mbody=msg, mtype="chat")
            m["chat_state"] = "active"
            m.send()
            emit("chat", "message", t, frm=cur, chars=len(msg))
            await asyncio.sleep(min(rng.uniform(0.3, 2), max(0, left(a))))
        await asyncio.sleep(min(rng.lognormvariate(1.5, 0.8), max(0, left(a) - 1)))
        cur = peer
    for b in bots.values():
        b.disconnect()
    await asyncio.sleep(0.5)


def main():
    a = args()
    asyncio.run(talk(a, random.Random(a.seed)))


if __name__ == "__main__":
    main()
