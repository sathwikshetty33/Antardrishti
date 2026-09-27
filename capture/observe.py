"""what actually happened in a run, from the wire (tshark) and charon logs.

outer.pcap is captured on the router with -i any, so every forwarded packet
appears twice (ingress + egress). counts use ingress copies only
(sll.pkttype != 4); duplicate checks work per interface.
"""
import re
import subprocess
from collections import Counter, defaultdict

v2x = {"34": "IKE_SA_INIT", "35": "IKE_AUTH", "36": "CREATE_CHILD_SA", "37": "INFORMATIONAL"}
v1x = {"2": "main", "4": "aggressive", "32": "quick", "5": "informational"}
# charon log abbreviations -> iana names
notify = {"NO_PROP": "NO_PROPOSAL_CHOSEN", "INVAL_KE": "INVALID_KE_PAYLOAD", "COOKIE": "COOKIE",
          "AUTH_FAILED": "AUTHENTICATION_FAILED", "TS_UNACCEPT": "TS_UNACCEPTABLE",
          "INVAL_SYN": "INVALID_SYNTAX", "NO_ADD_SAS": "NO_ADDITIONAL_SAS", "INT_ADDR_FAIL": "INTERNAL_ADDRESS_FAILURE"}
wire_notify = {"14": "NO_PROPOSAL_CHOSEN", "17": "INVALID_KE_PAYLOAD", "16390": "COOKIE",
               "24": "AUTHENTICATION_FAILED", "7": "INVALID_SYNTAX", "38": "TS_UNACCEPTABLE"}


def tshark(pcap, fields, flt=None, opts=""):
    f = " ".join(f"-e {x}" for x in fields)
    y = f"-Y '{flt}'" if flt else ""
    p = subprocess.run(f"tshark -n {opts} -r {pcap} {y} -T fields -E occurrence=a -E aggregator=, {f}",
                       shell=True, capture_output=True, text=True, timeout=900)
    rows = []
    for line in p.stdout.splitlines():
        v = line.split("\t")
        rows.append(dict(zip(fields, v + [""] * (len(fields) - len(v)))))
    return rows


def ike(pcap):
    fs = ["frame.time_epoch", "sll.pkttype", "sll.ifindex", "ip.src", "ipv6.src", "udp.srcport",
          "udp.dstport", "isakmp.ispi", "isakmp.rspi", "isakmp.exchangetype", "isakmp.flags",
          "isakmp.messageid", "isakmp.version", "isakmp.notify.msgtype", "isakmp.nextpayload",
          "frame.len", "isakmp.id.data.fqdn"]
    rows = [r for r in tshark(pcap, fs, "isakmp") if r["sll.pkttype"] != "4"]
    out = {"packets": len(rows), "exchanges": [], "v1_exchanges": Counter(), "notifies": set(),
           "init_requests": 0, "init_responses": 0, "auth_requests": 0, "ispis": set(),
           "retransmits": 0, "fragments": False, "responder_spi_zero": None,
           "nonesp_marker": False, "first": None, "src_ports": defaultdict(set), "cleartext_ids": set()}
    seen = Counter()
    for r in rows:
        ver = r["isakmp.version"]
        x = r["isakmp.exchangetype"].split(",")[0]
        flags = int(r["isakmp.flags"].split(",")[0] or "0", 16)
        resp = bool(flags & 0x20)
        src = r["ip.src"] or r["ipv6.src"]
        out["src_ports"][src].add(r["udp.srcport"])
        if r["udp.srcport"] == "4500" or r["udp.dstport"] == "4500":
            out["nonesp_marker"] = True
        if out["first"] is None:
            out["first"] = float(r["frame.time_epoch"])
        v1 = not (ver.startswith("0x2") or x in v2x)
        # ikev2: one message per (msg id, direction). ikev1 main/aggressive messages
        # all share msg id 0 and have no response flag, so length + first payload tell them apart
        key = (src, r["isakmp.ispi"], x, r["isakmp.messageid"], resp) if not v1 else \
            (src, r["isakmp.ispi"], r["isakmp.rspi"], x, r["isakmp.messageid"], r["frame.len"],
             r["isakmp.nextpayload"].split(",")[0], r["isakmp.flags"])
        seen[key] += 1
        if not v1:
            name = v2x.get(x, x)
            if name not in out["exchanges"]:
                out["exchanges"].append(name)
            if name == "IKE_SA_INIT" and not resp:
                out["init_requests"] += 1
                z = set(r["isakmp.rspi"].split(",")) <= {"0000000000000000"}
                out["responder_spi_zero"] = z if out["responder_spi_zero"] is None else out["responder_spi_zero"] and z
            if name == "IKE_SA_INIT" and resp:
                out["init_responses"] += 1
            if name == "IKE_AUTH" and not resp:
                out["auth_requests"] += 1
        else:
            if seen[key] == 1:
                out["v1_exchanges"][v1x.get(x, x)] += 1
        if r["isakmp.ispi"]:
            out["ispis"].add(r["isakmp.ispi"].split(",")[0])
        for n in r["isakmp.notify.msgtype"].split(","):
            if n in wire_notify:
                out["notifies"].add(wire_notify[n])
        for i in r["isakmp.id.data.fqdn"].split(","):
            if i:
                out["cleartext_ids"].add(i)
        if "53" in r["isakmp.nextpayload"].split(","):
            out["fragments"] = True
    out["retransmits"] = sum(v - 1 for v in seen.values() if v > 1)
    return out


def esp(pcap, null=False):
    fs = ["frame.time_epoch", "sll.pkttype", "sll.ifindex", "esp.spi", "esp.sequence", "ip.src",
          "ipv6.src", "udp.dstport", "ip.flags.mf", "ip.frag_offset", "ipv6.fraghdr.nxt", "ah.spi",
          "frame.len", "icmp.type", "icmpv6.type"]
    opts = "-o esp.enable_null_encryption_decode_heuristic:TRUE" if null else ""
    rows = tshark(pcap, fs, "esp || ah || ip.flags.mf==1 || ip.frag_offset>0 || ipv6.fraghdr", opts)
    per_if = defaultdict(Counter)
    out = {"packets": 0, "ah_packets": 0, "spis": Counter(), "first_seq": {}, "last_time": None, "times": [],
           "first_time": None, "udp4500": 0, "ip_fragments": 0, "duplicates": 0, "plaintext": 0,
           "outer_family": set()}
    for r in rows:
        if r["ip.flags.mf"] in ("1", "True") or (r["ip.frag_offset"] not in ("", "0")) or r["ipv6.fraghdr.nxt"]:
            out["ip_fragments"] += 1
        if r["ah.spi"]:
            if r["sll.pkttype"] != "4":
                out["ah_packets"] += 1
                out["times"].append(float(r["frame.time_epoch"]))
            if r["icmp.type"] or r["icmpv6.type"]:
                out["plaintext"] += 1
            continue
        if not r["esp.spi"]:
            continue
        spi = r["esp.spi"].split(",")[0]
        seq = r["esp.sequence"].split(",")[0]
        per_if[r["sll.ifindex"] + r["sll.pkttype"]][(spi, seq)] += 1
        if r["sll.pkttype"] == "4":
            continue
        t = float(r["frame.time_epoch"])
        out["packets"] += 1
        out["times"].append(t)
        out["spis"][spi] += 1
        out["first_seq"].setdefault(spi, int(seq or 0))
        out["first_time"] = out["first_time"] or t
        out["last_time"] = t
        out["outer_family"].add("v6" if r["ipv6.src"] else "v4")
        if r["udp.dstport"] == "4500":
            out["udp4500"] += 1
        if null and (r["icmp.type"] or r["icmpv6.type"]):
            out["plaintext"] += 1
    out["duplicates"] = sum(v - 1 for c in per_if.values() for v in c.values() if v > 1)
    return out


def null_plaintext(pcap):
    """esp packets (ingress copies) whose payload is readable plaintext: the bytes
    after the esp header form a valid inner ip header that fits the packet. works
    on truncated captures, unlike tshark's null heuristic (needs the esp trailer)"""
    import pcap as pc
    n = 0
    for ts, meta, l3 in pc.packets(pcap):
        if meta.get("pkttype") == 4:
            continue
        e = pc.esp_payload(l3)
        if not e:
            continue
        h = pc.ip(l3)
        room = meta["orig_len"] - 20 - h[4] - 8 if "pkttype" in meta else len(l3)
        if pc.plausible_inner(e[2], room):
            n += 1
    return n


def keepalives(pcap):
    rows = tshark(pcap, ["frame.time_epoch"], "udp.port==4500 && udp.length==9 && sll.pkttype!=4")
    return len(rows)


def inner_family(pcap):
    rows = tshark(pcap, ["ip.src", "ipv6.src"], "ip || ipv6")
    return {("v6" if r["ipv6.src"] and not r["ip.src"] else "v4") for r in rows[:500]}


def count(pcap):
    p = subprocess.run(f"capinfos -c -M {pcap}", shell=True, capture_output=True, text=True)
    m = re.search(r"Number of packets:\s+(\d+)", p.stdout)
    return int(m.group(1)) if m else 0


def charon(log):
    """established state, exchanges, notifies, rekeys, proposals from a charon log"""
    o = {"ike_established": 0, "child_established": 0, "exchanges": [], "notifies": set(),
         "child_rekeys": 0, "ike_rekeys": 0, "proposals": [], "deletes": 0, "errors": [],
         "nat_local": False, "nat_remote": False}
    rekeyed = set()
    for line in log.splitlines():
        m = re.search(r"(generating|parsed) (\S+) (request|response) \d+ \[ (.*) \]", line)
        if m:
            x = m.group(2)
            x = {"ID_PROT": "main", "AGGRESSIVE": "aggressive", "QUICK_MODE": "quick"}.get(x, x)
            if x not in o["exchanges"]:
                o["exchanges"].append(x)
            for n in re.findall(r"N\((\w+)\)", m.group(4)):
                if n in notify:
                    o["notifies"].add(notify[n])
            if re.search(r"(^| )D( |$)", m.group(4)):
                o["deletes"] += 1
        if re.search(r"IKE_SA \S+ established", line):
            o["ike_established"] += 1
        if re.search(r"[>\]] CHILD_SA \S+ established", line):
            o["child_established"] += 1
        m = re.search(r"outbound CHILD_SA \S+\{(\d+)\} established", line)
        if m:
            rekeyed.add(m.group(1))
        if re.search(r"IKE_SA \S+ rekeyed", line):
            o["ike_rekeys"] += 1
        m = re.search(r"selected proposal: (\S+)", line)
        if m:
            o["proposals"].append(m.group(1))
        if "local host is behind NAT" in line:
            o["nat_local"] = True
        if "remote host is behind NAT" in line:
            o["nat_remote"] = True
        if "received AUTHENTICATION_FAILED" in line:
            o["notifies"].add("AUTHENTICATION_FAILED")
        if re.search(r"\[(IKE|CFG|ENC)\] .*(failed|error|no matching)", line, re.I):
            o["errors"].append(line.strip()[-160:])
    o["errors"] = o["errors"][:10]
    o["child_rekeys"] = len(rekeyed)
    o["pfs_seen"] = any(p.startswith(("ESP:", "AH:")) and re.search(r"/(MODP|ECP|CURVE)_", p) for p in o["proposals"])
    return o


def xfrm_state(txt):
    """spis, replay windows, esn, replay counters from `ip -s xfrm state` dumps"""
    o = {"spis": set(), "replay_window": set(), "esn": False, "replay": 0, "sections": {}}
    for sec in re.split(r"^== ", txt, flags=re.M):
        if not sec.strip():
            continue
        name = sec.split("\n", 1)[0].strip()
        spis = re.findall(r"spi (0x[0-9a-f]+)", sec)
        rep = [int(x) for x in re.findall(r"replay-window \d+ replay (\d+) failed", sec)]
        o["sections"][name] = {"spis": spis, "replay": sum(rep)}
        o["spis"] |= set(spis)
        o["replay_window"] |= {int(x) for x in re.findall(r"replay-window (\d+)", sec) if x}
        if re.search(r"flag .*esn", sec):
            o["esn"] = True
    return o
