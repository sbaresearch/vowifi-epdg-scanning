# -*- coding: utf-8 -*-
"""
some codeparts from https://github.com/Spinlogic/epdg_discoverer
"""

import secrets
import binascii, hashlib, socket
import logging
import datetime
import pathlib
import scanner.ikev2.ikev2_crypto as ikev2_crypto
from scanner.ikev2.ikev2_crypto import create_key
from functools import lru_cache
from ipaddress import ip_address
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scapy.all import IP, IPv6, UDP, sr1, sr, load_contrib

# fromt scapy.all import get_if_addr
# from scapy.config import conf
load_contrib("ikev2")


from binascii import hexlify


logger = logging.getLogger(__name__)


def toHex(value):  # bytes hex string
    return hexlify(value).decode("utf-8")


def get_default_source_address(af_inet, interface=None):
    target_ip = "2001:4860:4860::8888" if af_inet == socket.AF_INET6 else "8.8.8.8"
    sock = socket.socket(af_inet, socket.SOCK_DGRAM)
    if interface:
        sock.setsockopt(socket.SOL_SOCKET, 25, f"{interface}\0".encode("utf-8"))
    return [
        (s.connect((target_ip, 53)), s.getsockname()[0], s.close()) for s in [sock]
    ][0][1]


def get_ip_version(addr):
    if ip_address(addr).version == 6:
        return socket.AF_INET6
    return socket.AF_INET


@lru_cache(maxsize=None)
def usable_ip_versions(interface=None):
    """Address families ("v4", "v6") this host has a route and source address for.

    Routability only, not reachability: UDP connect() sends nothing. Cached per process.
    """
    available = []
    for version, af_inet in (("v4", socket.AF_INET), ("v6", socket.AF_INET6)):
        try:
            get_default_source_address(af_inet, interface)
            available.append(version)
        except OSError as exc:
            logger.info("no %s route from here (%s)", version, exc)
    return tuple(available)


# --- 3GPP identity helpers (3GPP TS 23.003, RFC 4187/5448) -------------------

# Leading NAI digit that tags how the peer interprets the username that follows,
# per RFC 4187 §4.1.1.7 (EAP-AKA/EAP-SIM) and RFC 5448 §4.1.1 (EAP-AKA').
EAP_IDENTITY_PREFIX = {
    "aka_permanent": "0",
    "sim_permanent": "1",
    "aka_pseudonym": "2",
    "sim_pseudonym": "3",
    "aka_reauth": "4",
    "sim_reauth": "5",
    "aka_prime_permanent": "6",
    "aka_prime_pseudonym": "7",
    "aka_prime_reauth": "8",
}


def generate_probe_imsi(mcc, mnc):
    """15-digit IMSI: MCC+MNC+zero MSIN (TS 23.003). Unprovisioned, 2/3-digit MNC."""
    mcc = str(mcc).strip()
    mnc = str(mnc).strip()
    if not (mcc.isdigit() and mnc.isdigit()):
        raise ValueError(f"mcc/mnc must be numeric, got mcc={mcc!r} mnc={mnc!r}")
    if len(mcc) != 3 or len(mnc) not in (2, 3):
        raise ValueError(
            f"mcc must be 3 digits and mnc 2 or 3, got mcc={mcc!r} mnc={mnc!r}"
        )
    return (mcc + mnc).ljust(15, "0")


def build_epc_nai(mcc, mnc, imsi=None, username=None, identity_type="aka_permanent"):
    """EPC NAI for the IKE_AUTH IDi (TS 23.003). Realm MNC/MCC zero-padded to 3."""
    try:
        prefix = EAP_IDENTITY_PREFIX[identity_type]
    except KeyError:
        raise ValueError(
            f"unknown identity_type {identity_type!r}; "
            f"expected one of {sorted(EAP_IDENTITY_PREFIX)}"
        )
    if username is None:
        username = imsi
    if username is None:
        raise ValueError("build_epc_nai needs either imsi or username")
    realm = f"nai.epc.mnc{str(mnc).zfill(3)}.mcc{str(mcc).zfill(3)}.3gppnetwork.org"
    return f"{prefix}{username}@{realm}"


# --- cert helpers ---


def _load_certificate(data):
    """Load a cert from DER or PEM bytes."""
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return x509.load_pem_x509_certificate(data)


def certreq_authority_from_cas(cert_paths):
    """CERTREQ authority: concat of SHA-1(DER SPKI) per CA (RFC 7296). Empty = any CA."""
    authority = b""
    for path in cert_paths:
        cert = _load_certificate(pathlib.Path(path).read_bytes())
        spki = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        authority += hashlib.sha1(spki).digest()
    return authority


def _iso_utc(dt):
    """ISO-8601 UTC; tolerate naive datetimes from older cryptography."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.isoformat()


def parse_certificate(cert_encoding, cert_data):
    """Summarise a CERT payload -> dict, never raises. X.509 only, else raw hex."""
    info = {
        "cert_encoding": int(cert_encoding) if cert_encoding is not None else None,
        "length": len(cert_data) if cert_data else 0,
    }
    if cert_encoding == 4 and cert_data:
        try:
            cert = x509.load_der_x509_certificate(bytes(cert_data))
            not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            info.update(
                {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial_number": format(cert.serial_number, "x"),
                    "not_valid_before": _iso_utc(not_before),
                    "not_valid_after": _iso_utc(not_after),
                    "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
                    "pem": cert.public_bytes(Encoding.PEM).decode("ascii"),
                }
            )
        except Exception as exc:  # bad cert mustn't kill the scan
            info["parse_error"] = f"{type(exc).__name__}: {exc}"
    else:
        info["raw_hex"] = toHex(bytes(cert_data)) if cert_data else ""
    return info


class EpdgIKEv2(object):
    # ENCRYPTION
    ENC_NULL = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_NULL,
        length=8,
    )
    ENC_DES = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_DES,
        length=8,
    )
    ENC_3DES = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_3DES,
        length=8,
    )
    ENC_AES_128 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_CBC,
        length=12,
        key_length=128,
    )
    ENC_AES_192 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_CBC,
        length=12,
        key_length=192,
    )
    ENC_AES_256 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_CBC,
        length=12,
        key_length=256,
    )
    ENC_AES_CTR_128 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_CTR,
        length=12,
        key_length=128,
    )
    ENC_AES_CTR_192 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_CTR,
        length=12,
        key_length=192,
    )
    ENC_AES_CTR_256 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_CTR,
        length=12,
        key_length=256,
    )
    AES_GCM_8_128 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_8,
        length=12,
        key_length=128,
    )
    AES_GCM_8_192 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_8,
        length=12,
        key_length=192,
    )
    AES_GCM_8_256 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_8,
        length=12,
        key_length=256,
    )
    AES_GCM_12_128 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_12,
        length=12,
        key_length=128,
    )
    AES_GCM_12_192 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_12,
        length=12,
        key_length=192,
    )
    AES_GCM_12_256 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_12,
        length=12,
        key_length=256,
    )
    AES_GCM_16_128 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_16,
        length=12,
        key_length=128,
    )
    AES_GCM_16_192 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_16,
        length=12,
        key_length=192,
    )
    AES_GCM_16_256 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Encryption",
        transform_id=ikev2_crypto.EncrId.ENCR_AES_GCM_16,
        length=12,
        key_length=256,
    )

    # PRF
    PRF_MD5 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="PRF",
        transform_id=ikev2_crypto.PrfId.PRF_HMAC_MD5,
    )
    PRF_SHA1 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="PRF",
        transform_id=ikev2_crypto.PrfId.PRF_HMAC_SHA1,
    )
    PRF_AES128_CBC = IKEv2_Transform(
        next_payload="Transform",
        transform_type="PRF",
        transform_id=ikev2_crypto.PrfId.PRF_AES128_XCBC,
    )
    PRF_SHA2_256 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="PRF",
        transform_id=ikev2_crypto.PrfId.PRF_HMAC_SHA2_256,
    )
    PRF_SHA2_384 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="PRF",
        transform_id=ikev2_crypto.PrfId.PRF_HMAC_SHA2_384,
    )
    PRF_SHA2_512 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="PRF",
        transform_id=ikev2_crypto.PrfId.PRF_HMAC_SHA2_512,
    )

    # INTEGRITY
    INT_NULL = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Integrity",
        transform_id=ikev2_crypto.IntegId.AUTH_NONE,
    )
    INT_MD5_96 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Integrity",
        transform_id=ikev2_crypto.IntegId.AUTH_HMAC_MD5_96,
    )
    INT_SHA1_96 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Integrity",
        transform_id=ikev2_crypto.IntegId.AUTH_HMAC_SHA1_96,
    )
    INT_AES_XCBC_96 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Integrity",
        transform_id=ikev2_crypto.IntegId.AUTH_AES_XCBC_96,
    )
    INT_SHA2_256_128 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Integrity",
        transform_id=ikev2_crypto.IntegId.AUTH_HMAC_SHA2_256_128,
    )
    INT_SHA2_384_192 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Integrity",
        transform_id=ikev2_crypto.IntegId.AUTH_HMAC_SHA2_384_192,
    )
    INT_SHA2_512_256 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Integrity",
        transform_id=ikev2_crypto.IntegId.AUTH_HMAC_SHA2_512_256,
    )

    # DH
    DH_768MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_1,
    )
    DH_1024MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_2,
    )
    DH_1536MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_5,
    )
    DH_2048MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_14,
    )
    DH_3072MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_15,
    )
    DH_4096MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_16,
    )
    DH_6144MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_17,
    )
    DH_8192MODP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_18,
    )
    DH_256ECP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_19,
    )
    DH_384ECP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_20,
    )
    DH_512ECP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_21,
    )
    DH_1024MODP_160POS = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_22,
    )
    DH_2048MODP_224POS = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_23,
    )
    DH_2048MODP_256POS = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_24,
    )
    DH_192ECP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_25,
    )
    DH_224ECP = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_26,
    )
    DH_224ECP_B = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_27,
    )
    DH_256ECP_B = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_28,
    )
    DH_384ECP_B = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_29,
    )
    DH_512ECP_B = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_30,
    )
    DH_X25519 = IKEv2_Transform(
        next_payload="Transform",
        transform_type="GroupDesc",
        transform_id=ikev2_crypto.DhId.DH_31,
    )

    # KE
    KE_DH_768MODP = ikev2_crypto.DhId.DH_1
    KE_DH_1024MODP = ikev2_crypto.DhId.DH_2
    KE_DH_1536MODP = ikev2_crypto.DhId.DH_5
    KE_DH_2048MODP = ikev2_crypto.DhId.DH_14
    KE_DH_3072MODP = ikev2_crypto.DhId.DH_15
    KE_DH_4096MODP = ikev2_crypto.DhId.DH_16
    KE_DH_6144MODP = ikev2_crypto.DhId.DH_17
    KE_DH_8192MODP = ikev2_crypto.DhId.DH_18
    KE_DH_256ECP = ikev2_crypto.DhId.DH_19
    KE_DH_384ECP = ikev2_crypto.DhId.DH_20
    KE_DH_512ECP = ikev2_crypto.DhId.DH_21
    KE_DH_1024MODP_160POS = ikev2_crypto.DhId.DH_22
    KE_DH_2048MODP_224POS = ikev2_crypto.DhId.DH_23
    KE_DH_2048MODP_256POS = ikev2_crypto.DhId.DH_24
    KE_DH_192ECP = ikev2_crypto.DhId.DH_25
    KE_DH_224ECP = ikev2_crypto.DhId.DH_26
    KE_DH_224ECP_B = ikev2_crypto.DhId.DH_27
    KE_DH_256ECP_B = ikev2_crypto.DhId.DH_28
    KE_DH_384ECP_B = ikev2_crypto.DhId.DH_29
    KE_DH_512ECP_B = ikev2_crypto.DhId.DH_30
    KE_DH_X25519 = ikev2_crypto.DhId.DH_31

    # IPSec (phase 2)
    ESN = IKEv2_Transform(
        next_payload="Transform",
        transform_type="Extended Sequence Number",
        transform_id=0,
    )

    @staticmethod
    def extract_matching_payloads(packet, payload_class, remove_references=True):
        ret = []
        while payload_class in packet:
            current = packet[payload_class]
            clone = current.copy()
            if remove_references:
                clone.payload = None
            ret.append(clone)
            packet = current.payload
        return ret

    @staticmethod
    def get_notify_payloads(packet):
        ret = []
        if not packet or not (IKEv2 in packet and IKEv2_Notify in packet):
            return ret
        current = packet[IKEv2]
        while IKEv2_Notify in current:
            packet_notify = current[IKEv2_Notify]
            ret.append((packet_notify.type, packet_notify.notify))
            current = packet_notify.payload
        return ret

    @staticmethod
    def contains_auth_lifetime(packet):
        notify_packets = EpdgIKEv2.get_notify_payloads(packet)
        return any([n for n in notify_packets if n[0] == 16403])

    @staticmethod
    def contains_no_proposal_chosen(packet):
        notify_packets = EpdgIKEv2.get_notify_payloads(packet)
        logger.debug("notify payloads: %s", notify_packets)
        return any([n for n in notify_packets if n[0] == 14])

    @staticmethod
    def contains_invalid_ke(packet):
        notify_packets = EpdgIKEv2.get_notify_payloads(packet)
        logger.debug("notify payloads: %s", notify_packets)
        return any([n for n in notify_packets if n[0] == 17])

    @staticmethod
    def contains_invalid_user(packet):
        notify_packets = EpdgIKEv2.get_notify_payloads(packet)
        logger.debug("notify payloads: %s", notify_packets)
        return any([n for n in notify_packets if n[0] == 9001])

    @staticmethod
    def contains_auth_failed(packet):
        notify_packets = EpdgIKEv2.get_notify_payloads(packet)
        logger.debug("notify payloads: %s", notify_packets)
        return any([n for n in notify_packets if n[0] == 24])

    @staticmethod
    def validate_key_exchange(request, answer, dh_group):
        ke_request = EpdgIKEv2.extract_matching_payloads(request, IKEv2_KE)
        ke_answer = EpdgIKEv2.extract_matching_payloads(answer, IKEv2_KE)
        assert len(ke_request) == 1
        assert len(ke_answer) == 1
        assert (
            ke_request[0].group == ke_answer[0].group and ke_answer[0].group == dh_group
        )

    @staticmethod
    def validate_security_assotiations(request, answer):
        # TODO extract IKE proposals, extrac
        # proposals_request = extract_matching_payloads(request, IKEv2_Proposal)
        # proposals_answer = extract_matching_payloads(answer, IKEv2_Proposal)
        transforms_request = EpdgIKEv2.extract_matching_payloads(
            request, IKEv2_Transform
        )
        transforms_answer = EpdgIKEv2.extract_matching_payloads(answer, IKEv2_Transform)

        encr_ans = [
            (x.transform_id, x.key_length)
            for x in transforms_answer
            if x.transform_type == 1
        ]
        prf_ans = [x.transform_id for x in transforms_answer if x.transform_type == 2]
        integ_ans = [x.transform_id for x in transforms_answer if x.transform_type == 3]
        dh_ans = [x.transform_id for x in transforms_answer if x.transform_type == 4]
        assert (
            len(encr_ans) == 1
            and len(prf_ans) == 1
            and len(integ_ans) == 1
            and len(dh_ans) == 1
        )

        assert encr_ans[0] in [
            (x.transform_id, x.key_length)
            for x in transforms_request
            if x.transform_type == 1
        ]
        assert prf_ans[0] in [
            x.transform_id for x in transforms_request if x.transform_type == 2
        ]
        assert integ_ans[0] in [
            x.transform_id for x in transforms_request if x.transform_type == 3
        ]
        assert dh_ans[0] in [
            x.transform_id for x in transforms_request if x.transform_type == 4
        ]

        return (
            ikev2_crypto.EncrId(encr_ans[0][0]),
            encr_ans[0][1],
            ikev2_crypto.PrfId(prf_ans[0]),
            ikev2_crypto.IntegId(integ_ans[0]),
            ikev2_crypto.DhId(dh_ans[0]),
        )

    @staticmethod
    def get_cookie(packet):
        if not packet or not (IKEv2 in packet and IKEv2_Notify in packet):
            return None
        current = packet[IKEv2]
        while IKEv2_Notify in current:
            packet_notify = current[IKEv2_Notify]
            if packet_notify.type == 16390:
                # print("return cookie")
                return packet_notify.notify
            current = packet_notify.payload
        # print("no cookie found")
        return None

    @staticmethod
    def append_cookie(packet, cookie):
        packet_ikev2 = packet[IKEv2]
        notify_cookie = IKEv2_Notify(
            next_payload=packet_ikev2.next_payload, type=16390, notify=cookie
        )  # 16390 -> COOKIE
        notify_cookie = notify_cookie / packet_ikev2.payload
        packet_ikev2.next_payload = 41  # 41 -> COOKIE
        packet_ikev2.payload = notify_cookie

    def encrypt_ikev2_packet(packet_ike, encr_id, sk_e, integ_id, sk_a):
        assert IKEv2 in packet_ike
        first_payload_type = packet_ike.next_payload
        plaintext_content = packet_ike.payload
        packet_ike.next_payload = "Encrypted"

        encrypted_payload = ikev2_crypto.encrypt(
            bytes(plaintext_content), sk_e, encr_id, integ_id
        )
        packet_ike.payload = IKEv2_Encrypted(
            next_payload=first_payload_type,
            length=len(encrypted_payload) + 4,
            load=encrypted_payload,
        )
        packet_ike[IKEv2].length = len(packet_ike.payload) + 28
        # ICV length varies by integ algo (SHA1-96=12, SHA2-256-128=16)
        icv_len = ikev2_crypto.Integrity(integ_id).hash_size
        checksum = ikev2_crypto.calculate_checksum(
            bytes(packet_ike)[:-icv_len], sk_a, integ_id
        )

        # fix checksum in payload
        packet_ike[IKEv2_Encrypted].load = (
            packet_ike[IKEv2_Encrypted].load[:-icv_len] + checksum
        )

        return packet_ike

    def decrypt_ikev2_packet(packet_ike, encr_id, sk_e, integ_id):
        assert IKEv2 in packet_ike

        encrypted_payload = packet_ike[IKEv2_Encrypted].load
        first_payload_type = packet_ike[IKEv2_Encrypted].next_payload
        plaintext = ikev2_crypto.decrypt(encrypted_payload, sk_e, encr_id, integ_id)

        hdr = bytes.fromhex(f"{first_payload_type:02x}000004")
        # wrap it into generic payload object
        dummy_payload = IKEv2_Payload(hdr + plaintext)

        packet_ike[IKEv2].next_payload = dummy_payload.next_payload
        packet_ike[IKEv2].payload = dummy_payload.payload
        # del packet_ike[IKEv2].length
        packet_ike[IKEv2].length = len(packet_ike[IKEv2].payload) + 28

        return packet_ike

    # ID = '0232050000000000@nai.epc.mnc005.mcc232.3gppnetwork.org'
    def __init__(
        self,
        ip_dst,
        dport,
        interface=None,
        mcc="001",
        mnc="01",
        imsi="generate",
        sport=0,
        identity_type="aka_permanent",
        identity_username=None,
        idi_type="Email_addr",
        idi_mcc=None,
        idi_mnc=None,
    ):
        self.spi_i = secrets.token_bytes(8)
        self.spi_r = bytes(8)
        self.dst_addr = ip_dst
        self.dst_port = dport
        self.interface = interface
        self.mcc = mcc
        self.mnc = mnc
        self.imsi = imsi
        # permanent -> username from IMSI; pseudonym/reauth -> identity_username
        self.identity_type = identity_type
        self.identity_username = identity_username
        self.idi_type = idi_type
        # IDi realm/IMSI override (identity-axis probing); defaults to target
        self.idi_mcc = idi_mcc or mcc
        self.idi_mnc = idi_mnc or mnc
        self.af_inet = get_ip_version(self.dst_addr)
        self.src_addr = get_default_source_address(self.af_inet, self.interface)
        self.src_port = sport
        self.nonce_i = secrets.token_bytes(16)
        self.encr_id = None
        self.encr_key_len = None
        self.integ_id = None
        self.prf_id = None
        self.dh_id = None
        self.sock = socket.socket(self.af_inet, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if self.interface:
            self.sock.setsockopt(
                socket.SOL_SOCKET, 25, f"{self.interface}\0".encode("utf-8")
            )
        self.sock.bind((self.src_addr, self.src_port))
        self.src_port = self.sock.getsockname()[1]
        logger.debug("binding to %s", self.sock.getsockname())

        if self.imsi == "generate":
            self.imsi = generate_probe_imsi(self.idi_mcc, self.idi_mnc)  # 3GPP TS 23.003

    def ike_generate_keys(self):
        (
            self.sk_d,
            self.sk_ai,
            self.sk_ar,
            self.sk_ei,
            self.sk_er,
            self.sk_pi,
            self.sk_pr,
        ) = create_key(
            self.prf_id,
            self.integ_id,
            self.encr_id,
            self.encr_key_len,
            self.dh_shared_key,
            self.nonce_i,
            self.nonce_r,
            self.spi_i,
            self.spi_r,
        )
        logger.debug(
            "generated ike keys: %s",
            [
                self.sk_d,
                self.sk_ai,
                self.sk_ar,
                self.sk_ei,
                self.sk_er,
                self.sk_pi,
                self.sk_pr,
            ],
        )

    @staticmethod
    def print_ikev2_decryption_table(spi_i, spi_r, sk_ei, sk_er, sk_ai, sk_ar):
        logger.debug("IKEv2 DECRYPTION TABLE INFO (Wireshark):")
        text = toHex(spi_i) + "," + toHex(spi_r) + ","
        text += toHex(sk_ei) + "," + toHex(sk_er) + ',"AES-CBC-128 [RFC3602]",'
        text += toHex(sk_ai) + "," + toHex(sk_ar) + ',"HMAC_SHA1_96 [RFC2404]"\n'
        text += toHex(spi_r) + "," + toHex(spi_i) + ","
        text += toHex(sk_er) + "," + toHex(sk_ei) + ',"AES-CBC-128 [RFC3602]",'
        text += toHex(sk_ar) + "," + toHex(sk_ai) + ',"HMAC_SHA1_96 [RFC2404]"\n'
        logger.debug(text)
        return text

    @staticmethod
    def create_sa_transform_list(transform_list):
        head = None
        for t in reversed(transform_list):
            if not head:
                head = t.copy()
                head.next_payload = 0
            else:
                head = t.copy() / head
        return head

    @staticmethod
    def create_sa_proposal_list(sa_list, proto="IKE"):
        head = None
        for transform_list in reversed(sa_list):
            transforms = EpdgIKEv2.create_sa_transform_list(transform_list)
            if not head:
                head = IKEv2_Proposal(
                    next_payload="None",
                    proto=proto,
                    trans_nb=len(transform_list),
                    trans=transforms,
                )
            else:
                head = (
                    IKEv2_Proposal(
                        next_payload="Proposal",
                        proto=proto,
                        trans_nb=len(transform_list),
                        trans=transforms,
                    )
                    / head
                )
        return head

    @staticmethod
    def IPv4v6(dst):
        if ip_address(dst).version == 6:
            return IPv6(dst=dst)
        return IP(dst=dst)

    def ike_sa_init_create_packet(
        self, sa_list, key_exchange, cookie=None, fragmentation_supported=False
    ):
        self.dh_private_key, self.dh_public_key_bytes, self.dh_key_size = (
            ikev2_crypto.dh_generate_key(key_exchange)
        )
        ip_src = socket.inet_pton(self.af_inet, self.src_addr)
        ip_dst = socket.inet_pton(self.af_inet, self.dst_addr)
        src_port = binascii.unhexlify(format(self.src_port, "04x"))
        dst_port = binascii.unhexlify(format(self.dst_port, "04x"))
        nat_det_src = binascii.unhexlify(
            hashlib.sha1(self.spi_i + self.spi_r + ip_src + src_port).hexdigest()
        )
        nat_det_dst = binascii.unhexlify(
            hashlib.sha1(self.spi_i + self.spi_r + ip_dst + dst_port).hexdigest()
        )

        sa_proposal = EpdgIKEv2.create_sa_proposal_list(sa_list, "IKE")

        packet_sa_init = (
            EpdgIKEv2.IPv4v6(dst=self.dst_addr)
            / UDP(sport=self.src_port, dport=self.dst_port)
            / IKEv2(
                init_SPI=self.spi_i,
                next_payload="SA",
                exch_type="IKE_SA_INIT",
                flags="Initiator",
            )
            / IKEv2_SA(next_payload="KE", prop=sa_proposal)
            / IKEv2_KE(
                next_payload="Nonce", group=key_exchange, ke=self.dh_public_key_bytes
            )
            / IKEv2_Nonce(next_payload="Notify", nonce=self.nonce_i)
            / IKEv2_Notify(
                next_payload="Notify",
                type="NAT_DETECTION_SOURCE_IP",
                notify=nat_det_src,
            )
            / IKEv2_Notify(
                next_payload="Notify" if fragmentation_supported else "None",
                type="NAT_DETECTION_DESTINATION_IP",
                notify=nat_det_dst,
            )
        )
        # RFC 7383: responder fragments only if we advertise support
        if fragmentation_supported:
            packet_sa_init = packet_sa_init / IKEv2_Notify(
                next_payload="None", type="IKEV2_FRAGMENTATION_SUPPORTED"
            )
        if cookie:
            logger.debug("append cookie")
            EpdgIKEv2.append_cookie(packet_sa_init, cookie)
        return packet_sa_init

    def ike_sa_init(self, sa_list, key_exchange, cookie=None, fragmentation_supported=False):
        ## calculate nat_detection_source_ip and nat_detection_destination_ip
        packet_sa_init = self.ike_sa_init_create_packet(
            sa_list, key_exchange, cookie, fragmentation_supported
        )
        response = sr1(packet_sa_init, iface=self.interface, timeout=3, verbose=0)
        if not cookie and EpdgIKEv2.get_cookie(response):
            cookie = EpdgIKEv2.get_cookie(response)
            logger.debug("retry with cookie %s", cookie)
            return self.ike_sa_init(
                sa_list=sa_list,
                key_exchange=key_exchange,
                cookie=cookie,
                fragmentation_supported=fragmentation_supported,
            )
        if response and IKEv2 in response and response[IKEv2].flags == "Response":
            return self.ike_sa_init_analyze_response(
                packet_sa_init[IKEv2], response[IKEv2]
            )
        else:
            return {"state": "no ikev2 resp"}

    def ike_sa_init_analyze_response(self, request, answer):
        logger.debug("spi init %s %s", answer.init_SPI, self.spi_i)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("IKE_SA_INIT response:\n%s", answer.show(dump=True))
        assert answer.init_SPI == self.spi_i
        self.spi_r = answer.resp_SPI
        try:
            if IKEv2_KE in answer and IKEv2_Nonce in answer:
                (
                    self.encr_id,
                    self.encr_key_len,
                    self.prf_id,
                    self.integ_id,
                    self.dh_id,
                ) = self.validate_security_assotiations(request, answer)
                EpdgIKEv2.validate_key_exchange(request, answer, self.dh_id)
                self.dh_shared_key = ikev2_crypto.dh_calculate_shared_key(
                    answer[IKEv2_KE].group,
                    answer[IKEv2_KE].ke,
                    self.dh_key_size,
                    self.dh_private_key,
                )
                self.nonce_r = answer[IKEv2_Nonce].nonce

                if self.encr_id != ikev2_crypto.EncrId.ENCR_NULL:
                    self.ike_generate_keys()
                    EpdgIKEv2.print_ikev2_decryption_table(
                        self.spi_i,
                        self.spi_r,
                        self.sk_ei,
                        self.sk_er,
                        self.sk_ai,
                        self.sk_ar,
                    )

                # print('received nonce: {}'.format(self.nonce_r))
                # return f"successfull key exchange, group: {answer[IKEv2_KE].group}, ke: {toHex(answer[IKEv2_KE].ke)}, nonce: {toHex(answer[IKEv2_Nonce].nonce)}, encr_id: {self.encr_id}, encr_key_len: {self.encr_key_len}, integ_id: {self.integ_id}, prf_id: {self.prf_id}"
                return {
                    "state": "successful key exchange",
                    "group": answer[IKEv2_KE].group,
                    "ke": toHex(answer[IKEv2_KE].ke),
                    "nonce": toHex(answer[IKEv2_Nonce].nonce),
                    "encr_id": self.encr_id,
                    "encr_key_len": self.encr_key_len,
                    "integ_id": self.integ_id,
                    "prf_id": self.prf_id,
                }
            elif EpdgIKEv2.contains_invalid_ke(answer):
                notify_packets = EpdgIKEv2.get_notify_payloads(answer)
                preferred_ke = [n for n in notify_packets if n[0] == 17]
                return {"state": "unknown payload {notify_packets}"}
            elif EpdgIKEv2.contains_no_proposal_chosen(answer):
                return {"state": "no proposal chosen"}
            elif any(EpdgIKEv2.get_notify_payloads(answer)):
                notify_packets = EpdgIKEv2.get_notify_payloads(answer)
                return {"state": "unknown payload {notify_packets}"}
        except:
            return "exception occured"

    @staticmethod
    def _as_transform_list(transforms):
        if transforms is None:
            return []
        if isinstance(transforms, (list, tuple)):
            return list(transforms)
        return [transforms]

    def create_packet_ike_auth(
        self, trans_encr, trans_integ, cert_authority=None
    ):
        self.ike_auth_spi = secrets.token_bytes(4)
        # ESP proposal. encr/integ may be a transform or a list (offer several,
        # responder picks). Empty integ = AEAD (GCM). No DH group: child-SA PFS
        # isn't used by the SWu profile (TS 33.402/33.234).
        encr_list = EpdgIKEv2._as_transform_list(trans_encr)
        integ_list = EpdgIKEv2._as_transform_list(trans_integ)
        esp_transforms = encr_list + integ_list + [EpdgIKEv2.ESN]
        sa_proposal = IKEv2_Proposal(
            proto="ESP",
            SPI=self.ike_auth_spi,
            trans_nb=len(esp_transforms),
            trans=EpdgIKEv2.create_sa_transform_list(esp_transforms),
        )
        logger.debug("SPI: %s", toHex(self.ike_auth_spi))

        cp_attrs = [
            ConfigurationAttribute(type="INTERNAL_IP4_ADDRESS"),
            ConfigurationAttribute(type="INTERNAL_IP4_DNS"),
            ConfigurationAttribute(type="INTERNAL_IP6_ADDRESS"),
            ConfigurationAttribute(type="INTERNAL_IP6_DNS"),
            ConfigurationAttribute(type="P_CSCF_IP4_ADDRESS"),
            ConfigurationAttribute(type="P_CSCF_IP6_ADDRESS"),
        ]

        traffic_selectors_initiator = [
            IPv4TrafficSelector(
                IP_protocol_ID="All protocols",
                starting_address_v4="0.0.0.0",
                ending_address_v4="255.255.255.255",
            ),
            IPv6TrafficSelector(
                IP_protocol_ID="All protocols",
                length=40,
                starting_address_v6="::",
                ending_address_v6="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ),
        ]

        traffic_selectors_responder = [
            IPv4TrafficSelector(
                IP_protocol_ID="All protocols",
                starting_address_v4="0.0.0.0",
                ending_address_v4="255.255.255.255",
            ),
            IPv6TrafficSelector(
                IP_protocol_ID="All protocols",
                length=40,
                starting_address_v6="::",
                ending_address_v6="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ),
        ]

        # A CERTREQ asks the ePDG to present its certificate (RFC 7296 §3.7). It
        # sits right after IDi; cert_authority is a concatenation of SHA-1
        # hashes of trusted CA public keys, or b"" to accept any CA.
        want_certreq = cert_authority is not None
        idi = IKEv2_IDi(
            next_payload="CERTREQ" if want_certreq else "IDr",
            IDtype=self.idi_type,
            ID=build_epc_nai(
                self.idi_mcc,
                self.idi_mnc,
                imsi=self.imsi,
                username=self.identity_username,
                identity_type=self.identity_type,
            ),
        )
        if want_certreq:
            idi = idi / IKEv2_CERTREQ(
                next_payload="IDr",
                cert_encoding=4,  # X.509 Certificate - Signature
                cert_authority=cert_authority,
            )

        packet_ike_auth = (
            IKEv2(
                init_SPI=self.spi_i,
                resp_SPI=self.spi_r,
                next_payload="IDi",
                exch_type="IKE_AUTH",
                flags="Initiator",
                id=1,
            )
            / idi
            / IKEv2_IDr(next_payload="CP", IDtype="FQDN", ID="ims")
            / IKEv2_CP(next_payload="SA", CFGType="CFG_REQUEST", attributes=cp_attrs)
            / IKEv2_SA(next_payload="TSi", prop=sa_proposal)
            / IKEv2_TSi(
                next_payload="TSr",
                number_of_TSs=2,
                traffic_selector=traffic_selectors_initiator,
            )
            / IKEv2_TSr(
                next_payload="Notify",
                number_of_TSs=2,
                traffic_selector=traffic_selectors_responder,
            )
            / IKEv2_Notify(next_payload="None", type="EAP_ONLY_AUTHENTICATION")
        )  # 16417 -> EAP_ONLY_AUTHENTICATION

        if self.encr_id != ikev2_crypto.EncrId.ENCR_NULL:
            packet_ike_auth = EpdgIKEv2.encrypt_ikev2_packet(
                packet_ike_auth, self.encr_id, self.sk_ei, self.integ_id, self.sk_ai
            )

        packet_ip = (
            EpdgIKEv2.IPv4v6(dst=self.dst_addr)
            / UDP(sport=self.src_port, dport=4500)
            / NON_ESP()
            / packet_ike_auth
        )

        return packet_ip

    def ike_auth_analyze_response(self, response):
        # IP / UDP 213.94.78.29:ipsec_nat_t > 192.168.52.71:52707 / NON_ESP / IKEv2 / IKEv2_Encrypted

        # wrap it into generic payload object
        decrypted = EpdgIKEv2.decrypt_ikev2_packet(
            response, self.encr_id, self.sk_er, self.integ_id
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("IKE_AUTH decrypted response:\n%s", decrypted.show(dump=True))

        if EpdgIKEv2.contains_invalid_user(decrypted):
            return "invalid user"
        elif EpdgIKEv2.contains_auth_failed(decrypted):
            return "auth failed"
        elif IKEv2_EAP in decrypted:
            eap = decrypted[IKEv2_EAP]
            return f"received eap challenge {eap.load}"

    def ike_auth(self, trans_encr, trans_integ):
        packet_ike_auth = self.create_packet_ike_auth(trans_encr, trans_integ)
        response = sr1(packet_ike_auth, iface=self.interface, timeout=3, verbose=0)

        logger.debug("IKE_AUTH response: %s", response)
        if response and IKEv2 in response and response[IKEv2].flags == "Response":
            return self.ike_auth_analyze_response(response[IKEv2])
        else:
            logger.debug("no auth resp")
            return "no auth response"

    @staticmethod
    def reassemble_encrypted_response(responses, encr_id, sk_er, integ_id):
        """Decrypt a (possibly RFC 7383 fragmented) IKE response.

        Returns (payload_chain, n_fragments), or (None, n) if nothing decrypted.
        Fragments are de-padded then concatenated.
        """
        fragments = {}
        first_next_payload = None
        single_plain = None
        single_next = None

        for resp in responses:
            if resp is None or IKEv2 not in resp:
                continue
            ike = resp[IKEv2]
            if IKEv2_Encrypted_Fragment in ike:
                skf = ike[IKEv2_Encrypted_Fragment]
                try:
                    plain = ikev2_crypto.decrypt(
                        bytes(skf.load), sk_er, encr_id, integ_id
                    )
                except Exception as exc:
                    logger.warning(
                        "fragment %s decrypt failed: %s", skf.frag_number, exc
                    )
                    continue
                fragments[int(skf.frag_number)] = plain
                if int(skf.frag_number) == 1:
                    first_next_payload = skf.next_payload
            elif IKEv2_Encrypted in ike:
                enc = ike[IKEv2_Encrypted]
                try:
                    single_plain = ikev2_crypto.decrypt(
                        bytes(enc.load), sk_er, encr_id, integ_id
                    )
                    single_next = enc.next_payload
                except Exception as exc:
                    logger.warning("encrypted payload decrypt failed: %s", exc)

        if fragments:
            if 1 not in fragments:
                logger.warning(
                    "missing first IKE fragment; got %s", sorted(fragments)
                )
                return None, len(fragments)
            ordered = b"".join(fragments[i] for i in sorted(fragments))
            hdr = bytes.fromhex(f"{int(first_next_payload):02x}000004")
            return IKEv2_Payload(hdr + ordered), len(fragments)

        if single_plain is not None:
            hdr = bytes.fromhex(f"{int(single_next):02x}000004")
            return IKEv2_Payload(hdr + single_plain), 1

        return None, 0

    @staticmethod
    def classify_cert_response(chain, n_fragments):
        """IKE_AUTH chain -> cert_present / vulnerable_no_cert_eap / inconclusive"""
        result = {
            "state": "ike_auth cert probe",
            "n_fragments": n_fragments,
            "cert_present": False,
            "eap_started": False,
            "certs": [],
            "notify_types": [],
        }
        if chain is None:
            result["finding"] = "no_decryptable_response"
            return result

        certs = EpdgIKEv2.extract_matching_payloads(chain, IKEv2_CERT)
        result["cert_present"] = bool(certs)
        result["certs"] = [
            parse_certificate(c.cert_encoding, c.cert_data) for c in certs
        ]
        result["eap_started"] = IKEv2_EAP in chain
        # get_notify_payloads() expects a full IKEv2 packet; the reassembled
        # response is a bare payload chain, so walk it for IKEv2_Notify directly.
        notifies = EpdgIKEv2.extract_matching_payloads(chain, IKEv2_Notify)
        result["notify_types"] = [int(n.type) for n in notifies]

        if result["cert_present"]:
            # Finer secure/partial split (ID/CN mismatch, expiry) is left to
            # post-analysis against the configured IDr/CA.
            result["finding"] = "cert_present"
        elif result["eap_started"]:
            result["finding"] = "vulnerable_no_cert_eap"
        else:
            result["finding"] = "inconclusive"
        return result

    def _ike_auth_exchange(
        self, trans_encr, trans_integ, cert_authority=None, timeout=5
    ):
        # needs a completed encrypted IKE_SA_INIT. sr(multi=True) matches every
        # datagram on our init_SPI, so all fragments are collected.
        """Send one IKE_AUTH, collect+decrypt the reply -> (chain, n, error)."""
        if self.encr_id is None or self.encr_id == ikev2_crypto.EncrId.ENCR_NULL:
            return None, 0, "ike_auth needs an encrypted IKE SA"

        packet = self.create_packet_ike_auth(
            trans_encr, trans_integ, cert_authority=cert_authority
        )
        answered, _ = sr(
            packet, iface=self.interface, timeout=timeout, multi=True, verbose=0
        )
        responses = [rcv for _sent, rcv in answered]
        logger.debug("IKE_AUTH: %d response datagram(s)", len(responses))
        if not responses:
            return None, 0, "no auth response"

        chain, n_fragments = EpdgIKEv2.reassemble_encrypted_response(
            responses, self.encr_id, self.sk_er, self.integ_id
        )
        if logger.isEnabledFor(logging.DEBUG) and chain is not None:
            logger.debug("reassembled IKE_AUTH response:\n%s", chain.show(dump=True))
        return chain, n_fragments, None

    def ike_auth_probe_cert(
        self, trans_encr, trans_integ, cert_authority=b"", timeout=5
    ):
        """Send an IKE_AUTH with a CERTREQ and report whether a cert comes back."""
        chain, n_fragments, error = self._ike_auth_exchange(
            trans_encr, trans_integ, cert_authority=cert_authority, timeout=timeout
        )
        if error:
            return {"state": error}
        return EpdgIKEv2.classify_cert_response(chain, n_fragments)

    def ike_auth_probe_ipsec(self, trans_encr, trans_integ, timeout=5):
        """Offer one child-SA (ESP) proposal and report whether it was accepted.

        No CERTREQ -- this isolates the crypto accept/reject signal.
        """
        chain, n_fragments, error = self._ike_auth_exchange(
            trans_encr, trans_integ, cert_authority=None, timeout=timeout
        )
        if error:
            return {"state": error}
        return EpdgIKEv2.classify_ipsec_proposal_response(chain, n_fragments)

    @staticmethod
    def classify_ipsec_proposal_response(chain, n_fragments):
        # NO_PROPOSAL_CHOSEN -> rejected; any other decryptable reply -> accepted
        # (SA checked before subscriber). Raw notify_types kept for analysis.
        """Did the ePDG accept the offered ESP proposal? -> result dict."""
        result = {
            "state": "ike_auth ipsec probe",
            "n_fragments": n_fragments,
            "proposal_rejected": False,
            "cert_present": False,
            "eap_started": False,
            "notify_types": [],
        }
        if chain is None:
            result["result"] = "inconclusive"
            return result

        notifies = EpdgIKEv2.extract_matching_payloads(chain, IKEv2_Notify)
        result["notify_types"] = [int(n.type) for n in notifies]
        result["proposal_rejected"] = 14 in result["notify_types"]  # NO_PROPOSAL_CHOSEN
        result["cert_present"] = bool(
            EpdgIKEv2.extract_matching_payloads(chain, IKEv2_CERT)
        )
        result["eap_started"] = IKEv2_EAP in chain
        result["result"] = (
            "not_supported" if result["proposal_rejected"] else "supported"
        )
        return result
