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


class ScanOut(BaseModel):
    id: UUID
    inserted_at: datetime
    dh_variant: str
    header_text: str | None = None
    source_file: str | None = None


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
    country: str | None = None
    iso3: str | None = None
    mcc: str | None = None
    mnc: str | None = None
    operator: str | None = None
    network: str | None = None
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
    operators: List[OperatorSnapshotOut]


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
