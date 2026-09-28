"""the checks, as data: one row per check, so thresholds are easy to audit and change.

row keys:
  id, title        check id and short name
  standard         what the check cites
  fact             the fact it reads (analyzer result, app/schema/v1.known_facts)
  when             optional: {fact: [values]} the check only applies when these hold
  match            "prefix" (value starts with a key), "exact", "range" (numeric (lo, hi) keys)
  outcomes         key -> (verdict, severity, text); "*" matches anything else
  missing          (verdict, severity, text) when the fact is absent
  threats          threat ids (threats below) a failing or warning finding feeds
  fix              the recommendation shown with a failing or warning finding
texts use {value}; the engine prefixes "likely " to the claim when confidence is below 0.8.
verdicts: pass, fail, warn, info, not determinable. severities: critical, high, medium, low,
info (a pass or info finding is always severity info).
"""

rfc8221 = "RFC 8221 (ESP and AH algorithm requirements)"
rfc8247 = "RFC 8247 (IKEv2 algorithm requirements)"
nist = "NIST SP 800-77r1 (Guide to IPsec VPNs)"
rfc4303 = "RFC 4303 section 2.7 (traffic flow confidentiality padding)"
rfc7296 = "RFC 7296 (IKEv2)"
nd = ("not determinable", "info")

checks = [
    {"id": "IKE-ENC", "title": "IKE encryption algorithm", "standard": [rfc8247, nist], "fact": "ike_encryption",
     "match": "prefix",
     "outcomes": {"null": ("fail", "critical", "IKE SA uses NULL encryption ({value})"),
                  "des": ("fail", "critical", "IKE SA uses single DES ({value}), which RFC 8247 says MUST NOT be used"),
                  "3des": ("fail", "high", "IKE SA uses 3DES ({value}); NIST has deprecated 3DES"),
                  "aes-gcm8": ("warn", "low", "IKE SA uses AES-GCM with an 8-byte ICV ({value})"),
                  "aes-gcm12": ("pass", "info", "IKE SA uses {value}"),
                  "aes-gcm16": ("pass", "info", "IKE SA uses {value}"),
                  "aes-cbc": ("pass", "info", "IKE SA uses {value}"),
                  "aes-ctr": ("pass", "info", "IKE SA uses {value}"),
                  "aes-ccm8": ("pass", "info", "IKE SA uses {value}"),
                  "chacha20-poly1305": ("pass", "info", "IKE SA uses {value}"),
                  "*": ("warn", "medium", "IKE SA uses an unrecognised encryption algorithm ({value})")},
     "missing": nd + ("the IKE_SA_INIT exchange is not in the capture",),
     "threats": ["T-CONF", "T-MITM"], "fix": "Use AES-GCM-16 or AES-CBC with a 128 or 256-bit key for the IKE SA."},
    {"id": "IKE-KEYLEN", "title": "IKE AES key size", "standard": [rfc8247, nist], "fact": "_ike_key_bits",
     "match": "range", "when": {"ike_encryption": ["aes"]},
     "outcomes": {(0, 128): ("fail", "high", "the IKE SA uses a {value}-bit key"),
                  (128, 1e9): ("pass", "info", "the IKE SA uses a {value}-bit AES key")},
     "missing": nd + ("no key length attribute was read from IKE_SA_INIT",), "threats": ["T-KEY"],
     "fix": "Use 128 or 256-bit AES keys."},
    {"id": "ESP-KEYLEN", "title": "ESP AES key size", "standard": [rfc8221], "fact": "_never",
     "outcomes": {}, "missing": nd + ("the AES key size never shows in ESP (same IV, ICV and block padding for 128 "
                                      "and 256-bit keys) and the child SA proposal is encrypted inside IKE_AUTH",),
     "threats": [], "fix": ""},
    {"id": "IKE-INTEG", "title": "IKE integrity algorithm", "standard": [rfc8247], "fact": "ike_integ", "match": "prefix",
     "outcomes": {"hmac-md5": ("fail", "high", "IKE SA integrity is {value}, which RFC 8247 says MUST NOT be used"),
                  "hmac-sha1": ("warn", "low", "IKE SA integrity is {value} (RFC 8247: MUST-, expected to be "
                                              "deprecated)"),
                  "hmac-sha256": ("pass", "info", "IKE SA integrity is {value}"),
                  "hmac-sha384": ("pass", "info", "IKE SA integrity is {value}"),
                  "hmac-sha512": ("pass", "info", "IKE SA integrity is {value}"),
                  "aes-xcbc": ("pass", "info", "IKE SA integrity is {value}"),
                  "*": ("warn", "medium", "IKE SA integrity algorithm unrecognised ({value})")},
     "missing": nd + ("no integrity transform was read (AEAD suite, or no IKE_SA_INIT in the capture)",),
     "threats": ["T-FORGE", "T-MITM"], "fix": "Use HMAC-SHA2-256-128 or stronger, or an AEAD cipher."},
    {"id": "IKE-PRF", "title": "IKE pseudo-random function", "standard": [rfc8247], "fact": "ike_prf", "match": "prefix",
     "outcomes": {"prf-hmac-md5": ("fail", "high", "IKE SA PRF is {value}, which RFC 8247 says MUST NOT be used"),
                  "prf-hmac-sha1": ("warn", "low", "IKE SA PRF is {value} (RFC 8247: MUST-)"),
                  "*": ("pass", "info", "IKE SA PRF is {value}")},
     "missing": nd + ("the IKE_SA_INIT exchange is not in the capture (or IKEv1)",),
     "threats": ["T-KEY"], "fix": "Use PRF_HMAC_SHA2_256 or stronger."},
    {"id": "IKE-DH", "title": "Diffie-Hellman group", "standard": [rfc8247, nist], "fact": "ike_dh", "match": "exact",
     "outcomes": {"modp768": ("fail", "critical", "the key exchange uses {value}, which RFC 8247 says MUST NOT be used"),
                  "modp1024": ("fail", "high", "the key exchange uses {value}; RFC 8247 says SHOULD NOT and NIST "
                                               "requires at least 2048-bit MODP"),
                  "modp1536": ("fail", "medium", "the key exchange uses {value} (RFC 8247: SHOULD NOT)"),
                  "modp1024s160": ("fail", "medium", "the key exchange uses {value} (RFC 8247: SHOULD NOT)"),
                  "modp2048s224": ("warn", "low", "the key exchange uses {value} (RFC 8247: SHOULD NOT)"),
                  "modp2048s256": ("warn", "low", "the key exchange uses {value} (RFC 8247: SHOULD NOT)"),
                  "*": ("pass", "info", "the key exchange uses {value}")},
     "missing": nd + ("the IKE_SA_INIT exchange is not in the capture",),
     "threats": ["T-KEY", "T-RETRO"], "fix": "Use group 19 (ECP-256), 20, 31 (Curve25519) or MODP 2048 and above."},
    {"id": "ESP-SUITE", "title": "ESP cipher and integrity", "standard": [rfc8221, nist], "fact": "esp_suite",
     "match": "prefix",
     "outcomes": {"AES-GCM-16": ("pass", "info", "ESP uses {value}"),
                  "AES-CBC + HMAC-SHA1-96": ("warn", "low", "ESP uses {value}; RFC 8221 rates HMAC-SHA1-96 MUST- "
                                                            "(expected to be deprecated)"),
                  "*": ("pass", "info", "ESP uses {value}")},
     "missing": nd + ("the tunnel carries no ESP",), "threats": ["T-FORGE"],
     "fix": "Prefer AES-GCM-16 or AES-CBC with HMAC-SHA2-256-128 for the child SA."},
    {"id": "ESP-NULL", "title": "NULL encryption", "standard": [rfc8221, nist], "fact": "esp_plaintext_share",
     "match": "range",
     "outcomes": {(0.5, 1.01): ("fail", "critical", "ESP payloads are readable: {value:.0%} start with a cleartext IP "
                                                    "header (NULL encryption)"),
                  (0.05, 0.5): ("warn", "medium", "{value:.0%} of ESP payloads start like a cleartext IP header"),
                  (0.0, 0.05): ("pass", "info", "ESP payloads look encrypted ({value:.1%} resemble cleartext by "
                                                "chance)")},
     "missing": nd + ("the tunnel carries no ESP",), "threats": ["T-CONF"],
     "fix": "Configure an encryption algorithm for the child SA; ENCR_NULL gives no confidentiality."},
    {"id": "AH-ONLY", "title": "AH with readable payload", "standard": [rfc8221, nist], "fact": "ah_packets",
     "match": "range",
     "outcomes": {(1, 1e18): ("fail", "high", "{value} AH packets: AH authenticates but does not encrypt, so their "
                                              "payload is readable on the wire"),
                  (0, 1): ("pass", "info", "no AH packets")},
     "missing": nd + ("",), "threats": ["T-CONF", "T-META"],
     "fix": "Use ESP with encryption instead of AH."},
    {"id": "PFS", "title": "Perfect forward secrecy", "standard": [nist, rfc7296], "fact": "pfs", "match": "exact",
     "outcomes": {True: ("pass", "info", "child SA rekeys use a fresh Diffie-Hellman exchange (PFS)"),
                  False: ("fail", "medium", "child SA rekeys reuse the IKE SA's keying material (no PFS)"),
                  "not determinable": nd + ("PFS only shows in a child SA rekey, and none is in the capture",)},
     "missing": nd + ("PFS only shows in a child SA rekey, and none is in the capture",),
     "threats": ["T-RETRO"], "fix": "Add a DH group to the child SA proposals (esp_proposals) to enable PFS."},
    {"id": "IKE-VERSION", "title": "IKE version", "standard": [nist, rfc8247], "fact": "ike_version", "match": "exact",
     "outcomes": {2: ("pass", "info", "the tunnel uses IKEv2"),
                  1: ("fail", "medium", "the tunnel uses IKEv1, which NIST SP 800-77r1 recommends against; use "
                                        "IKEv2")},
     "missing": nd + ("no IKE messages are in the capture",), "threats": ["T-MITM"],
     "fix": "Migrate the tunnel to IKEv2."},
    {"id": "IKEV1-AGGR", "title": "IKEv1 aggressive mode", "standard": [nist], "fact": "ikev1_mode", "match": "exact",
     "when": {"ike_version": [1]},
     "outcomes": {"aggressive": ("fail", "high", "IKEv1 aggressive mode sends the identity in the clear and, with a "
                                                 "pre-shared key, a hash an attacker can crack offline"),
                  "main": ("pass", "info", "IKEv1 main mode (identities protected)"),
                  "*": nd + ("the IKEv1 phase 1 mode was not seen",)},
     "missing": nd + ("the IKEv1 phase 1 exchange is not in the capture",), "threats": ["T-KEY", "T-META"],
     "fix": "Disable aggressive mode (or move to IKEv2)."},
    {"id": "AUTH", "title": "Peer authentication", "standard": [nist, rfc8247], "fact": "ikev1_auth", "match": "exact",
     "outcomes": {"psk": ("warn", "low", "IKEv1 authenticates with a pre-shared key; its strength cannot be seen"),
                  "*": ("pass", "info", "IKEv1 authenticates with {value}")},
     "missing": nd + ("IKEv2 authentication is inside the encrypted IKE_AUTH exchange",), "threats": ["T-KEY"],
     "fix": "Prefer certificate (RSA-PSS or ECDSA) authentication; if a PSK is used, make it long and random."},
    {"id": "MODE", "title": "Tunnel or transport mode", "standard": [nist], "fact": "mode", "match": "exact",
     "outcomes": {"tunnel": ("pass", "info", "the tunnel is in tunnel mode (inner addresses hidden)"),
                  "transport": ("warn", "low", "the tunnel is in transport mode: the protected hosts' addresses are "
                                               "the outer ones, visible to any observer")},
     "missing": nd + ("the tunnel carries no ESP",), "threats": ["T-META"],
     "fix": "Use tunnel mode where hiding the communicating hosts matters."},
    {"id": "LIFETIME-CHILD", "title": "Child SA lifetime (from SPI changes)", "standard": [nist],
     "fact": "_child_lifetime_s", "match": "range",
     "outcomes": {(0, 60): ("warn", "low", "child SAs are replaced every {value:.0f} s or less (rekey churn)"),
                  (60, 28800.01): ("pass", "info", "child SAs are replaced every {value:.0f} s at most"),
                  (28800.01, 1e18): ("warn", "low", "child SAs live longer than 8 h ({value:.0f} s)")},
     "missing": nd + ("fewer than two child SA rekeys in the capture, so the lifetime is not visible",),
     "threats": ["T-RETRO"], "fix": "Keep child SA lifetimes at 8 hours or less (and far below the key's data limits)."},
    {"id": "LIFETIME-IKE", "title": "IKE SA lifetime", "standard": [nist], "fact": "_ike_lifetime_s", "match": "range",
     "outcomes": {(0, 86400.01): ("pass", "info", "the IKE SA is replaced within {value:.0f} s"),
                  (86400.01, 1e18): ("warn", "low", "the IKE SA lifetime is {value:.0f} s, over 24 h")},
     "missing": nd + ("no IKE SA lifetime is visible (no lifetime attribute, fewer than two IKE SA rekeys)",),
     "threats": ["T-RETRO"], "fix": "Keep IKE SA lifetimes at 24 hours or less."},
    {"id": "REPLAY", "title": "Replayed ESP packets", "standard": ["RFC 4303 section 3.4.3 (sequence number "
                                                                   "verification)"], "fact": "esp_duplicate_seq",
     "match": "range",
     "outcomes": {(1, 1e18): ("fail", "medium", "{value} ESP packets repeat an earlier SPI and sequence number (a "
                                                "replay attempt)"),
                  (0, 1): ("info", "info", "no repeated ESP sequence numbers seen on the wire (an injected replay "
                                           "may not cross this vantage point)")},
     "missing": nd + ("the tunnel carries no ESP",), "threats": ["T-REPLAY"],
     "fix": "Keep anti-replay enabled (replay_window > 0) and investigate the source of the repeated packets."},
    {"id": "REPLAY-WINDOW", "title": "Anti-replay window and ESN", "standard": ["RFC 4303 section 3.4.3"],
     "fact": "_never", "outcomes": {},
     "missing": nd + ("the replay window and ESN are negotiated and enforced inside the gateways; the wire only "
                      "shows the low 32 sequence bits",), "threats": [], "fix": ""},
    {"id": "NEGOTIATION", "title": "Failed negotiation", "standard": [rfc7296], "fact": "handshake_status",
     "match": "exact",
     "outcomes": {"failed": ("fail", "medium", "an IKE negotiation started but no SA carried traffic{notes}"),
                  "*": ("pass", "info", "handshake status: {value}")},
     "missing": nd + ("",), "threats": ["T-DOS"],
     "fix": "Check that both peers share a proposal and credentials; failed negotiations can also be probes."},
    {"id": "NOTIFY", "title": "Error notifies", "standard": [rfc7296], "fact": "_error_notifies", "match": "exact",
     "outcomes": {"none": ("pass", "info", "no error notifies in the cleartext IKE messages"),
                  "*": ("warn", "low", "the peers exchanged error notifies: {value}")},
     "missing": nd + ("no cleartext IKE messages are in the capture",), "threats": ["T-DOS"],
     "fix": "Investigate the notified errors (proposal or authentication mismatch)."},
    {"id": "COOKIE", "title": "IKE cookie challenge (DoS protection)", "standard": [rfc7296], "fact": "_cookie",
     "match": "exact",
     "outcomes": {True: ("warn", "low", "the responder answered with a COOKIE challenge: it saw many half-open IKE "
                                        "SAs (a flood, or heavy load)"),
                  False: ("pass", "info", "no cookie challenge")},
     "missing": nd + ("no cleartext IKE messages are in the capture",), "threats": ["T-DOS"],
     "fix": "Investigate the source of half-open IKE_SA_INIT requests; rate-limit them at the edge."},
    {"id": "RETRANSMIT", "title": "IKE retransmissions", "standard": [rfc7296], "fact": "ike_retransmissions",
     "match": "range",
     "outcomes": {(3, 1e18): ("warn", "low", "{value} IKE messages were retransmitted (loss or an unresponsive "
                                             "peer)"),
                  (0, 3): ("pass", "info", "{value} IKE retransmissions")},
     "missing": nd + ("no IKE messages are in the capture",), "threats": ["T-DOS"],
     "fix": "Check reachability of UDP 500/4500 between the peers."},
    {"id": "METADATA", "title": "Traffic metadata exposure", "standard": [rfc4303, nist], "fact": "_identifiable",
     "match": "exact",
     "outcomes": {"none": ("pass", "info", "no traffic class is confidently identifiable from sizes and timing"),
                  "*": ("warn", "medium", "a passive observer can tell the traffic inside apart: {value}")},
     "missing": nd + ("the tunnel carries no analysable traffic",), "threats": ["T-META"],
     "fix": "Enable TFC padding (RFC 4303 section 2.7) or dummy traffic where hiding activity matters."},
]

# threat catalog: impact 1-5; likelihood comes from the linked findings (engine)
threats = {
    "T-CONF": {"threat": "Loss of confidentiality: traffic readable or decryptable", "impact": 5},
    "T-KEY": {"threat": "Offline recovery of keys or the pre-shared key", "impact": 4},
    "T-MITM": {"threat": "IKE downgrade or man-in-the-middle", "impact": 4},
    "T-RETRO": {"threat": "Retroactive decryption of recorded traffic", "impact": 4},
    "T-FORGE": {"threat": "Forgery of protected packets", "impact": 4},
    "T-META": {"threat": "Traffic analysis and metadata exposure", "impact": 2},
    "T-REPLAY": {"threat": "Replay of captured packets", "impact": 3},
    "T-DOS": {"threat": "Denial of service against the IKE responder", "impact": 3},
}

# risk weights per severity (a pass, info or not determinable finding weighs nothing)
weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
critical_floor = 90          # a confident critical finding sets the tunnel score to at least this
confident = 0.8              # below this confidence, wording says "likely"
likelihood = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# metadata exposure: an app counts as identifiable when it carries at least this byte share and
# its windows' mean calibrated presence probability reaches this level
identifiable = {"min_share_pct": 5.0, "min_probability": 0.8}

# error notify types (rfc 7296 section 3.10.1, rfc 2408 for ikev1) and the informational ones
notify_names = {1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
                7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN",
                17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
                35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED",
                38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND",
                16390: "COOKIE"}
benign_errors = {17}   # INVALID_KE_PAYLOAD: the initiator's DH guess is corrected, normal
cookie = 16390
