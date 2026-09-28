"""the analyzer result contract, version 1 (app/CLAUDE.md section 5).

matches what `python -m analyzer.cli analyze` writes. `config` maps a fact name to a fact
(value, confidence, source); the known names are listed in `known_facts`, and new observed
facts may be added without a version change (the map is open). anything else that changes
shape needs a new version (v2.py beside this file).
"""
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

schema_version = "antardrishti.result/1"
apps = ["voip", "video", "web", "email", "icmp", "bulk", "chat"]
share_names = apps + ["unknown"]
sources = ("read from IKE", "observed", "inferred")
known_facts = {
    "handshake_status": "full, rekey-only, esp-only, failed or ike-only (observed)",
    "outer_family": "ipv4 or ipv6 (observed)",
    "nat_t": "esp in udp 4500 (observed)",
    "ike_version": "1 or 2 (read from IKE)",
    "ike_exchanges": "exchange name -> message count (read from IKE)",
    "ike_retransmissions": "repeated ike messages (observed)",
    "ike_encryption": "the responder's chosen ike encryption, with key length (read from IKE)",
    "ike_integ": "ike integrity (read from IKE)",
    "ike_prf": "ike prf (read from IKE)",
    "ike_dh": "ike diffie-hellman group (read from IKE)",
    "ikev1_mode": "main or aggressive (read from IKE)",
    "ikev1_auth": "ikev1 phase 1 authentication method (read from IKE)",
    "ike_lifetime_s": "ikev1 phase 1 lifetime attribute (read from IKE)",
    "ike_init_payloads": "cleartext payload types of the IKE_SA_INIT response (read from IKE)",
    "ike_notifies": "cleartext notify types (read from IKE)",
    "rekeys": "child and ike sa rekey counts (observed)",
    "rekey_times_s": "rekey times, seconds from the capture start (observed)",
    "spi_first_seen_s": "first appearance of each esp spi (observed)",
    "capture_span_s": "seconds between the tunnel's first and last packet (observed)",
    "ah_packets": "ah packets (observed)",
    "esp_plaintext_share": "share of esp payloads starting like a cleartext ip header (observed)",
    "esp_duplicate_seq": "esp packets repeating an (spi, sequence) pair (observed)",
    "esp_suite": "esp wire shape (inferred by the suite model)",
    "mode": "tunnel or transport (inferred by the mode model)",
    "pfs": "true, false or 'not determinable' (inferred by the pfs model, needs a child rekey)",
}


class strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class fact_value(strict):
    value: Any
    confidence: Optional[float] = Field(None, ge=0, le=1)
    source: Literal["read from IKE", "observed", "inferred"]


class facts_map(BaseModel):
    """fact name -> fact; esp_suite_probabilities is the suite model's full distribution"""
    model_config = ConfigDict(extra="allow")
    esp_suite_probabilities: Optional[dict[str, float]] = None

    def facts(self):
        out = {}
        for k, v in (self.model_extra or {}).items():
            out[k] = v if isinstance(v, fact_value) else fact_value.model_validate(v)
        return out


class share_value(strict):
    share: float
    error_pp: Optional[float] = None


class window_row(strict):
    t: float
    pair: int
    esp_bytes: float
    packets: int
    present: list[Literal["voip", "video", "web", "email", "icmp", "bulk", "chat"]]
    presence_probability: dict[str, float]
    share: dict[str, float]


class tunnel_result(strict):
    tunnel: int
    initiator: Optional[str]
    responder: list[str]
    direction_from: str
    handshake_status: Literal["full", "rekey-only", "esp-only", "failed", "ike-only"]
    esp_packets: int
    start_s: Optional[float]
    end_s: Optional[float]
    config: facts_map
    byte_share: Optional[dict[str, share_value]] = None
    byte_share_rounded: Optional[dict[str, int]] = None
    active_time_share: Optional[dict[str, float]] = None
    active_time_share_rounded: Optional[dict[str, int]] = None
    windows: Optional[list[window_row]] = None


class timing_info(strict):
    seconds: float
    traffic_seconds: float
    seconds_per_minute: Optional[float]


class result(strict):
    schema_version: Literal["antardrishti.result/1"] = schema_version
    inputs: list[str]
    bundle: Optional[str]
    tunnels: list[tunnel_result]
    counts: dict[str, Any]
    timing: timing_info


def validate(d):
    """-> result, raising on a contract violation (also checks every fact and the share totals)"""
    r = result.model_validate(d)
    for t in r.tunnels:
        for name, f in t.config.facts().items():
            if f.source not in sources:
                raise ValueError(f"{name}: bad source {f.source}")
        if t.byte_share_rounded is not None and sum(t.byte_share_rounded.values()) not in (0, 100):
            raise ValueError(f"tunnel {t.tunnel}: rounded byte share sums to {sum(t.byte_share_rounded.values())}")
        if t.byte_share is not None and set(t.byte_share) != set(share_names):
            raise ValueError(f"tunnel {t.tunnel}: byte share names {sorted(t.byte_share)}")
    return r
