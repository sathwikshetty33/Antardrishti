"""tables (app/CLAUDE.md section 7). migrations: app/api/migrations (alembic), run by hand."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

jsonb = JSON().with_variant(JSONB(), "postgresql")


def now():
    return datetime.now(timezone.utc)


def new_id():
    return str(uuid.uuid4())


class base(DeclarativeBase):
    pass


class analysis(base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="queued")        # queued running done failed
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    stage: Mapped[str] = mapped_column(String(32), default="queued")
    error: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(16), default="upload")        # upload demo replay
    name: Mapped[str] = mapped_column(String(200), default="")
    urls: Mapped[list] = mapped_column(jsonb, default=list)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    bundle_version: Mapped[str] = mapped_column(String(64), default="")
    schema_version: Mapped[str] = mapped_column(String(64), default="")
    timings: Mapped[dict] = mapped_column(jsonb, default=dict)
    counts: Mapped[dict] = mapped_column(jsonb, default=dict)
    risk: Mapped[int | None] = mapped_column(Integer)
    risk_band: Mapped[str | None] = mapped_column(String(16))
    replay: Mapped[dict] = mapped_column(jsonb, default=dict)                # demo, step, steps, t
    result: Mapped[dict] = mapped_column(jsonb, default=dict)                # the analyzer result (contract v1)


class tunnel(base):
    __tablename__ = "tunnels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    idx: Mapped[int] = mapped_column(Integer)
    initiator: Mapped[str | None] = mapped_column(String(64))
    responder: Mapped[list] = mapped_column(jsonb, default=list)
    direction_from: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16))
    esp_packets: Mapped[int] = mapped_column(Integer, default=0)
    start_s: Mapped[float | None] = mapped_column(Float)
    end_s: Mapped[float | None] = mapped_column(Float)
    has_traffic: Mapped[bool] = mapped_column(Boolean, default=False)
    esp_suite_probabilities: Mapped[dict | None] = mapped_column(jsonb)


class config_fact(base):
    __tablename__ = "config_facts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tunnel_id: Mapped[int] = mapped_column(ForeignKey("tunnels.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    value: Mapped[object] = mapped_column(jsonb)
    confidence: Mapped[float | None] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(16))


class window(base):
    __tablename__ = "windows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tunnel_id: Mapped[int] = mapped_column(ForeignKey("tunnels.id", ondelete="CASCADE"), index=True)
    t: Mapped[float] = mapped_column(Float)
    pair: Mapped[int] = mapped_column(Integer)
    esp_bytes: Mapped[float] = mapped_column(Float)
    packets: Mapped[int] = mapped_column(Integer)
    present: Mapped[list] = mapped_column(jsonb, default=list)
    probabilities: Mapped[dict] = mapped_column(jsonb, default=dict)
    shares: Mapped[dict] = mapped_column(jsonb, default=dict)


class session_share(base):
    __tablename__ = "session_shares"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tunnel_id: Mapped[int] = mapped_column(ForeignKey("tunnels.id", ondelete="CASCADE"), index=True)
    app: Mapped[str] = mapped_column(String(16))
    byte_share: Mapped[float] = mapped_column(Float)
    byte_rounded: Mapped[int] = mapped_column(Integer)
    error_pp: Mapped[float | None] = mapped_column(Float)
    active_share: Mapped[float | None] = mapped_column(Float)
    active_rounded: Mapped[int | None] = mapped_column(Integer)


class finding(base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    tunnel_idx: Mapped[int | None] = mapped_column(Integer)
    check_id: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(120))
    verdict: Mapped[str] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(10))
    standard: Mapped[list] = mapped_column(jsonb, default=list)
    evidence: Mapped[list] = mapped_column(jsonb, default=list)
    confidence: Mapped[float | None] = mapped_column(Float)
    text: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    threats: Mapped[list] = mapped_column(jsonb, default=list)


class risk_score(base):
    __tablename__ = "risk_scores"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    tunnel_idx: Mapped[int | None] = mapped_column(Integer)                 # null: the overall score
    score: Mapped[int] = mapped_column(Integer)
    band: Mapped[str] = mapped_column(String(16))
    breakdown: Mapped[dict] = mapped_column(jsonb, default=dict)


class threat(base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    threat_id: Mapped[str] = mapped_column(String(16))
    threat: Mapped[str] = mapped_column(String(200))
    likelihood: Mapped[int] = mapped_column(Integer)
    impact: Mapped[int] = mapped_column(Integer)
    tunnels: Mapped[list] = mapped_column(jsonb, default=list)
    findings: Mapped[list] = mapped_column(jsonb, default=list)


class replay_chunk(base):
    __tablename__ = "replay_chunks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    idx: Mapped[int] = mapped_column(Integer)
    t_end: Mapped[float] = mapped_column(Float)
    packets: Mapped[int] = mapped_column(Integer)
    data: Mapped[bytes] = mapped_column(LargeBinary)


class live_session(base):
    """a live capture session: one analyses row (source="live") plus this sensor-facing state.
    no workspaces or read access control (app/CLAUDE.md live-mode brief): every session is
    readable by anyone, only feeding it needs the sensor key."""
    __tablename__ = "live_sessions"
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    key_hash: Mapped[str] = mapped_column(String(64))                    # sha256 of the sensor key; never the key
    status: Mapped[str] = mapped_column(String(16), default="waiting")   # waiting live stopped expired
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_chunk_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    chunks: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    last_seq: Mapped[int] = mapped_column(Integer, default=-1)
    creator_ip: Mapped[str] = mapped_column(String(64), default="")
    esp_header: Mapped[bytes | None] = mapped_column(LargeBinary)        # the first chunk's 24-byte pcap header
    ike_header: Mapped[bytes | None] = mapped_column(LargeBinary)


class live_chunk(base):
    __tablename__ = "live_chunks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    esp_data: Mapped[bytes] = mapped_column(LargeBinary)                 # zstd-compressed pcap records (no header)
    ike_data: Mapped[bytes | None] = mapped_column(LargeBinary)
    packets: Mapped[int] = mapped_column(Integer, default=0)
