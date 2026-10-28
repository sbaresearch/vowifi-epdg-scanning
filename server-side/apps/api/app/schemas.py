from datetime import datetime
from enum import StrEnum
from uuid import UUID
from typing import Dict, List

from pydantic import BaseModel, Field, IPvAnyAddress


class IKEResult(StrEnum):
    SUCCESS = "SUCCESS"
    NO_RESPONSE = "NO_RESPONSE"
    NO_PROPOSAL_CHOSEN = "NO_PROPOSAL_CHOSEN"
    NO_SUCCESS = "NO_SUCCESS"
    UNDEFINED = "UNDEFINED"


class AggregatedState(StrEnum):
    SUPPORTED = "SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NO_SUCCESS = "NO_SUCCESS"
    NO_RESPONSE = "NO_RESPONSE"
    UNKNOWN = "UNKNOWN"


class ServerOut(BaseModel):
    id: UUID
    inserted_at: datetime
    epdg_domain: str
    target_ip: IPvAnyAddress
    mcc: str | None = None
    mnc: str | None = None
    country: str | None = None
    iso3: str | None = None
    network: str | None = None
    operator: str | None = None
    itu_region: str | None = None


class VantagePointOut(BaseModel):
    """Logical vantage point (host or VPN exit): newest exit's fields, counts over all exits."""

    id: UUID
    label: str
    provider: str
    vpn_type: str | None = None
    requested_country: str | None = None
    iso3: str | None = None
    server_location: bool
    # newest exit, and the Cloudflare hop in front of it (WARP modes).
    exit_ip: IPvAnyAddress | None = None
    exit_country: str | None = None
    warp_ip: IPvAnyAddress | None = None
    warp_country: str | None = None
    first_seen: datetime
    last_seen: datetime
    scan_count: int = 0
    # distinct exits used.
    exit_count: int = 1
    # scan modes it has run.
    modes: List[str] = Field(default_factory=list)


class VantageExitOut(BaseModel):
    """One exit of a vantage point, with its own id."""

    id: UUID
    label: str
    exit_ip: IPvAnyAddress | None = None
    exit_country: str | None = None
    warp_ip: IPvAnyAddress | None = None
    warp_country: str | None = None
    first_seen: datetime
    last_seen: datetime
    scan_count: int = 0


class ScanOut(BaseModel):
    id: UUID
    inserted_at: datetime
    dh_variant: str
    header_text: str | None = None
    source_file: str | None = None
    vantage_id: UUID
    vantage_label: str
    # full / full_warp / dh2048_warp / local.
    mode: str = "full"
    # exit address (VPN exit, or host if local) and WARP hop, null without one.
    exit_ip: IPvAnyAddress | None = None
    exit_country: str | None = None
    warp_ip: IPvAnyAddress | None = None
    warp_country: str | None = None


class ResultOut(BaseModel):
    id: UUID
    inserted_at: datetime
    scan_id: UUID
    server_id: UUID
    observed_at: datetime | None = None
    raw_state: str | None = None
    result: IKEResult
    dh_group: int | None = None
    encr_id: int | None = None
    encr_key_len: int | None = None
    integ_id: int | None = None
    prf_id: int | None = None
    key_hex: str | None = None
    nonce_hex: str | None = None


class LatestResultOut(BaseModel):
    server_id: UUID
    vantage_id: UUID
    vantage_label: str
    mode: str = "full"
    country: str | None = None
    iso3: str | None = None
    mcc: str | None = None
    mnc: str | None = None
    operator: str | None = None
    network: str | None = None
    target_ip: IPvAnyAddress
    dh_variant: str
    scan_id: UUID
    observed_at: datetime | None = None
    inserted_at: datetime
    result: IKEResult
    raw_state: str | None = None
    dh_group: int | None = None
    encr_id: int | None = None
    encr_key_len: int | None = None
    integ_id: int | None = None
    prf_id: int | None = None
    key_hex: str | None = None
    nonce_hex: str | None = None


class AllResultOut(BaseModel):
    id: UUID
    inserted_at: datetime
    scan_id: UUID
    server_id: UUID
    vantage_id: UUID
    vantage_label: str
    mode: str = "full"
    observed_at: datetime | None = None
    raw_state: str | None = None
    result: IKEResult
    dh_group: int | None = None
    encr_id: int | None = None
    encr_key_len: int | None = None
    integ_id: int | None = None
    prf_id: int | None = None
    key_hex: str | None = None
    nonce_hex: str | None = None
    dh_variant: str
    epdg_domain: str
    target_ip: IPvAnyAddress
    mcc: str | None = None
    mnc: str | None = None
    country: str | None = None
    iso3: str | None = None
    network: str | None = None
    operator: str | None = None
    itu_region: str | None = None


class OperatorSnapshotOut(BaseModel):
    operator: str | None = None
    mcc: str | None = None
    mnc: str | None = None
    network: str | None = None

    supported: List[str]
    not_supported: List[str]
    no_success: List[str] = Field(default_factory=list)
    no_response: List[str]
    unknown: List[str]

    variants: Dict[str, AggregatedState]  # dh_variant -> aggregated state


class CountrySnapshotOut(BaseModel):
    country: str
    iso3: str | None = None
    # where and how it was measured; no vantage_id, a label spans several exits.
    vantage_label: str
    mode: str
    operators: List[OperatorSnapshotOut]


# what the operator does towards one vantage country.
class ReachState(StrEnum):
    ANSWERS = "answers"
    BLOCKS = "blocks"
    NO_ANSWERS = "no_answers"


class GeoblockingState(StrEnum):
    GEOBLOCKING = "geoblocking"
    OPEN = "open"
    # answers at home, not yet scanned from abroad.
    HOME_ONLY = "home_only"
    NO_ANSWERS = "no_answers"


class GeoblockingOperatorOut(BaseModel):
    operator: str
    state: GeoblockingState
    blocks: List[str]  # ISO3 of the vantage countries this operator blocks
    answers: int  # vantage countries it answers in
    # never answered through a VPN or WARP exit: may block those addresses, not countries.
    vpn_silent: bool


class GeoblockingCountryOut(BaseModel):
    country: str
    iso3: str | None = None
    operators: List[GeoblockingOperatorOut]


class ReachOut(BaseModel):
    """One vantage country for one operator: its latest probes (label and mode)."""
    seen_from: str
    probes: int
    answered: int
    state: ReachState


class OperatorListItemOut(BaseModel):
    mcc: str | None = None
    mnc: str | None = None
    operator: str | None = None
    network: str | None = None
    country: str | None = None
    iso3: str | None = None
    server_count: int


class HistoryServerOut(BaseModel):
    server_id: UUID
    target_ip: IPvAnyAddress
    epdg_domain: str


class TimelinePointOut(BaseModel):
    ts: datetime
    state: AggregatedState


class DhGroupSeriesOut(BaseModel):
    dh_variant: str
    points: List[TimelinePointOut]


class DhTimelineOut(BaseModel):
    operator: str | None = None
    mcc: str | None = None
    mnc: str | None = None
    network: str | None = None
    country: str | None = None
    server_ids: List[UUID]
    groups: List[DhGroupSeriesOut]


class CollisionServerOut(BaseModel):
    server_id: UUID
    target_ip: IPvAnyAddress
    operator: str | None = None
    country: str | None = None
    dh_variant: str


class CollisionOut(BaseModel):
    key_hex: str
    server_count: int
    ip_count: int
    servers: List[CollisionServerOut]


class CollisionKeyOut(BaseModel):
    key: str
    usage_count: int
    dh_variant: str | None = None
    operators: List[str] = Field(default_factory=list)
    server_ids: List[UUID] = Field(default_factory=list)
    inserted_at: datetime
    updated_at: datetime
