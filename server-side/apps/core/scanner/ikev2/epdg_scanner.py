#!/usr/bin/env python3

import os
import re
import pathlib
import argparse
import subprocess
import dns.resolver
from scanner.common.logging_config import configure_logging
from scanner.ikev2.ikev2_class import (
    EpdgIKEv2,
    certreq_authority_from_cas,
    usable_ip_versions,
)
import logging
import datetime
import json


logger = logging.getLogger(__name__)

TEST_CONFIG = {
    "SUPPORT_ENC_NULL_DH_768MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_768MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_768MODP,
    },
    "SUPPORT_ENC_NULL_DH_1024MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_ENC_NULL_DH_2048MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
    },
    "SUPPORT_DH_768MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_768MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_768MODP,
    },
    "SUPPORT_DH_1024MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_DH_1536MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1536MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1536MODP,
    },
    "SUPPORT_DH_2048MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
    },
    "SUPPORT_DH_3072MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_3072MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_3072MODP,
    },
    "SUPPORT_DH_4096MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_4096MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_4096MODP,
    },
    "SUPPORT_DH_6144MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_6144MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_6144MODP,
    },
    "SUPPORT_DH_8192MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_8192MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_8192MODP,
    },
    "SUPPORT_DH_256ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_256ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_256ECP,
    },
    "SUPPORT_DH_384ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_384ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_384ECP,
    },
    "SUPPORT_DH_512ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_512ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_512ECP,
    },
    "SUPPORT_DH_192ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_192ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_192ECP,
    },
    "SUPPORT_DH_224ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_224ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_224ECP,
    },
    "SUPPORT_DH_X25519": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_X25519,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_X25519,
    },
    "TOLERATE_DH1024": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
                EpdgIKEv2.DH_768MODP,
                EpdgIKEv2.DH_1536MODP,
                EpdgIKEv2.DH_2048MODP,
                EpdgIKEv2.DH_3072MODP,
                EpdgIKEv2.DH_4096MODP,
                EpdgIKEv2.DH_6144MODP,
                EpdgIKEv2.DH_8192MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "DOWNGRADE_DH2048": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
                EpdgIKEv2.DH_768MODP,
                EpdgIKEv2.DH_1024MODP,
                EpdgIKEv2.DH_1536MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
    },
    "CHECK_AUTOCONF_DOMAINS": {},
    # encr scan:
    "SUPPORT_IKE_ENCR_NULL": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_IKE_ENCR_DES": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    # IKE_AUTH w/ CERTREQ
    "PROBE_EPDG_CERT": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
        # broad ESP offer so one is accepted (narrow -> 14, e.g. Telstra)
        "ipsec_encr": [
            EpdgIKEv2.ENC_AES_256,
            EpdgIKEv2.ENC_AES_192,
            EpdgIKEv2.ENC_AES_128,
            EpdgIKEv2.ENC_3DES,
        ],
        "ipsec_integ": [
            EpdgIKEv2.INT_SHA2_256_128,
            EpdgIKEv2.INT_SHA2_384_192,
            EpdgIKEv2.INT_SHA2_512_256,
            EpdgIKEv2.INT_SHA1_96,
            EpdgIKEv2.INT_AES_XCBC_96,
            EpdgIKEv2.INT_MD5_96,
        ],
        "cert_probe": True,
        "identity_type": "aka_pseudonym",
        "identity_username": "fakeuser",
    },
}


# child-SA (ESP) crypto probing
_IPSEC_BASELINE_ENCR = [
    EpdgIKEv2.ENC_AES_256,
    EpdgIKEv2.ENC_AES_192,
    EpdgIKEv2.ENC_AES_128,
    EpdgIKEv2.ENC_3DES,
]
_IPSEC_BASELINE_INTEG = [
    EpdgIKEv2.INT_SHA2_256_128,
    EpdgIKEv2.INT_SHA2_384_192,
    EpdgIKEv2.INT_SHA2_512_256,
    EpdgIKEv2.INT_SHA1_96,
    EpdgIKEv2.INT_AES_XCBC_96,
    EpdgIKEv2.INT_MD5_96,
]
# IKE SA to bring the tunnel up before the ESP probe (broad, DH-2048)
_IKE_SA_FOR_IPSEC_PROBE = [
    [
        EpdgIKEv2.ENC_AES_128,
        EpdgIKEv2.ENC_AES_256,
        EpdgIKEv2.ENC_3DES,
        EpdgIKEv2.PRF_SHA1,
        EpdgIKEv2.PRF_SHA2_256,
        EpdgIKEv2.PRF_MD5,
        EpdgIKEv2.INT_SHA1_96,
        EpdgIKEv2.INT_SHA2_256_128,
        EpdgIKEv2.INT_MD5_96,
        EpdgIKEv2.DH_2048MODP,
    ]
]

# CBC/CTR ciphers (broad integ baseline)
_IPSEC_ENCR_CANDIDATES = {
    "AES_CBC_256": EpdgIKEv2.ENC_AES_256,
    "AES_CBC_192": EpdgIKEv2.ENC_AES_192,
    "AES_CBC_128": EpdgIKEv2.ENC_AES_128,
    "AES_CTR_128": EpdgIKEv2.ENC_AES_CTR_128,
    "3DES": EpdgIKEv2.ENC_3DES,
    "DES": EpdgIKEv2.ENC_DES,
    "NULL": EpdgIKEv2.ENC_NULL,
}
# AEAD: no separate integ transform
_IPSEC_ENCR_AEAD_CANDIDATES = {
    "AES_GCM_16_256": EpdgIKEv2.AES_GCM_16_256,
    "AES_GCM_16_128": EpdgIKEv2.AES_GCM_16_128,
    "AES_GCM_8_128": EpdgIKEv2.AES_GCM_8_128,
}
# integ algos (broad CBC baseline)
_IPSEC_INTEG_CANDIDATES = {
    "SHA1_96": EpdgIKEv2.INT_SHA1_96,
    "SHA2_256_128": EpdgIKEv2.INT_SHA2_256_128,
    "SHA2_384_192": EpdgIKEv2.INT_SHA2_384_192,
    "SHA2_512_256": EpdgIKEv2.INT_SHA2_512_256,
    "AES_XCBC_96": EpdgIKEv2.INT_AES_XCBC_96,
    "MD5_96": EpdgIKEv2.INT_MD5_96,
}


def _ipsec_probe_entry(encr, integ):
    return {
        "sa_list": _IKE_SA_FOR_IPSEC_PROBE,
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
        "ipsec_encr": encr,
        "ipsec_integ": integ,
        "ipsec_probe": True,
        "identity_type": "aka_pseudonym",
        "identity_username": "fakeuser",
    }


for _name, _t in _IPSEC_ENCR_CANDIDATES.items():
    TEST_CONFIG[f"PROBE_IPSEC_ENCR_{_name}"] = _ipsec_probe_entry(
        [_t], _IPSEC_BASELINE_INTEG
    )
for _name, _t in _IPSEC_ENCR_AEAD_CANDIDATES.items():
    TEST_CONFIG[f"PROBE_IPSEC_ENCR_{_name}"] = _ipsec_probe_entry([_t], [])
for _name, _t in _IPSEC_INTEG_CANDIDATES.items():
    TEST_CONFIG[f"PROBE_IPSEC_INTEG_{_name}"] = _ipsec_probe_entry(
        _IPSEC_BASELINE_ENCR, [_t]
    )

# identity-axis control: same crypto, IDi from the 001/01 test PLMN (foreign
# realm). served-vs-wrong response shows whether the subscriber check is reached.
def _wrongrealm(base_name):
    import copy
    e = copy.deepcopy(TEST_CONFIG[base_name])
    e["idi_realm_mcc"] = "001"
    e["idi_realm_mnc"] = "01"
    return e

TEST_CONFIG["PROBE_IPSEC_ENCR_NULL_WRONGREALM"] = _wrongrealm("PROBE_IPSEC_ENCR_NULL")
TEST_CONFIG["PROBE_IPSEC_ENCR_AES_GCM_16_128_WRONGREALM"] = _wrongrealm(
    "PROBE_IPSEC_ENCR_AES_GCM_16_128"
)


REGEX_VOWIFI = r"^epdg.epc.mnc(\d{2,3}).mcc(\d{3}).pub.3gppnetwork.org\.?$"

BASE_DIR = pathlib.Path(__file__).resolve().parent
DATA_DIR = pathlib.Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
RESULTS_DIR = DATA_DIR / "results"
EPDGS_DIR = DATA_DIR


def get_ids_from_domain(domain):
    m = re.search(REGEX_VOWIFI, domain)
    mnc = m[1]
    mcc = m[2]
    return mcc, mnc


def get_epdg_domains(filename="epdg_domains.txt"):
    """Target list for this run; EPDG_DOMAINS_FILE overrides the shared list."""
    override = os.getenv("EPDG_DOMAINS_FILE", "").strip()
    edpg_input_file = pathlib.Path(override) if override else EPDGS_DIR / filename
    with open(edpg_input_file) as file:
        return [line.rstrip() for line in file]


# Missing records are normal; resolver failures (timeout, no nameserver) are not.
NO_SUCH_RECORD = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)

# resolver failures since the last reset: tells "no ePDG answered" from "DNS down".
resolver_failures = {"count": 0}


def _resolve(dnsres, name, rdtype):
    """One lookup: [] for a missing record, [] plus a counted failure for a broken resolver."""
    try:
        return list(dnsres.resolve(name, rdtype))
    except NO_SUCH_RECORD:
        return []
    except Exception as exc:
        resolver_failures["count"] += 1
        logger.debug(f"resolving {name} {rdtype} failed: {type(exc).__name__}: {exc}")
        return []


def resolve_domain(operator_url, ip_version="v4v6"):
    dnsres = dns.resolver.Resolver()
    records = []
    if "v4" in ip_version:
        records.extend(r.address for r in _resolve(dnsres, operator_url, "A"))
    if "v6" in ip_version:
        records.extend(r.address for r in _resolve(dnsres, operator_url, "AAAA"))
    for record in _resolve(dnsres, operator_url, "CNAME"):
        records.extend(resolve_domain(record.target, ip_version))
    return list(dict.fromkeys(records))  # order


def load_cert_authority():
    """CERTREQ authority bytes. EPDG_CA_CERTS_DIR -> hash those CAs; else empty (any CA)."""
    ca_dir = os.getenv("EPDG_CA_CERTS_DIR", "").strip()
    if not ca_dir:
        return b""
    paths = sorted(
        p
        for ext in ("*.crt", "*.pem", "*.der", "*.cer")
        for p in pathlib.Path(ca_dir).glob(ext)
    )
    if not paths:
        logger.warning("EPDG_CA_CERTS_DIR=%s has no cert files; using empty CERTREQ", ca_dir)
        return b""
    logger.info("CERTREQ built from %d CA cert(s) in %s", len(paths), ca_dir)
    return certreq_authority_from_cas(paths)


def cert_probe_target(interface, ip, mcc, mnc, cfg, cert_authority):
    """Cert probe on one IP: IKE_SA_INIT (frag) then IKE_AUTH w/ CERTREQ.
    Returns the SA_INIT result if the SA never comes up."""
    ike = EpdgIKEv2(
        ip,
        500,
        interface=None if interface == "any" else interface,
        mcc=mcc,
        mnc=mnc,
        identity_type=cfg.get("identity_type", "aka_pseudonym"),
        identity_username=cfg.get("identity_username"),
        idi_mcc=cfg.get("idi_realm_mcc"),
        idi_mnc=cfg.get("idi_realm_mnc"),
    )
    sa_resp = ike.ike_sa_init(
        cfg["sa_list"], key_exchange=cfg["key_echange"], fragmentation_supported=True
    )
    if not (
        isinstance(sa_resp, dict)
        and sa_resp.get("state") == "successful key exchange"
    ):
        return sa_resp
    return ike.ike_auth_probe_cert(
        cfg["ipsec_encr"], cfg["ipsec_integ"], cert_authority=cert_authority
    )


def ipsec_probe_target(interface, ip, mcc, mnc, cfg):
    """ESP crypto probe on one IP: IKE_SA_INIT then IKE_AUTH w/ cfg's ESP
    proposal. Returns the SA_INIT result if the tunnel never came up."""
    ike = EpdgIKEv2(
        ip,
        500,
        interface=None if interface == "any" else interface,
        mcc=mcc,
        mnc=mnc,
        identity_type=cfg.get("identity_type", "aka_pseudonym"),
        identity_username=cfg.get("identity_username"),
        idi_mcc=cfg.get("idi_realm_mcc"),
        idi_mnc=cfg.get("idi_realm_mnc"),
    )
    sa_resp = ike.ike_sa_init(
        cfg["sa_list"], key_exchange=cfg["key_echange"], fragmentation_supported=True
    )
    if not (
        isinstance(sa_resp, dict)
        and sa_resp.get("state") == "successful key exchange"
    ):
        return sa_resp
    return ike.ike_auth_probe_ipsec(cfg["ipsec_encr"], cfg["ipsec_integ"])


def epdg_scanner(
    interface="any",
    ip_version="ipv4",
    testcase="SUPPORT_DH_1024MODP",
    results_dir=None,
):
    """Run one IKEv2 testcase; returns the results file.

    Vantage point runs pass their own results_dir so parallel runs don't mix output.
    """

    # sanatizing input arguments.
    if testcase not in TEST_CONFIG.keys() or ip_version not in [
        "ipv4",
        "ipv6",
        "ipv4v6",
    ]:
        logger.info(
            f"provided arguments ip version: {ip_version} or testcase: {testcase} not allowed."
        )
        exit(0)

    # Only routable address families: a tunnel without IPv6 fails every AAAA target
    # (ENETUNREACH). resolve_domain() reads this too, so AAAA lookups stop as well.
    reachable = usable_ip_versions(None if interface == "any" else interface)
    effective_ip_version = "".join(v for v in ("v4", "v6") if v in reachable and v in ip_version)
    if not effective_ip_version:
        raise RuntimeError(
            f"none of the requested address families ({ip_version}) are reachable "
            f"from here; this host can originate {reachable or 'nothing'}"
        )
    effective_ip_version = f"ip{effective_ip_version}"
    if effective_ip_version != ip_version:
        logger.info(
            f"no {'/'.join(v for v in ('v4', 'v6') if v not in reachable)} route here, "
            f"scanning {effective_ip_version} only (requested {ip_version})"
        )
    ip_version = effective_ip_version

    logger.info(f"starting scan for {testcase}...")

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    name = f"{testcase}_{timestamp}"

    output_dir = pathlib.Path(results_dir) if results_dir else RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    epdg_domains = get_epdg_domains("epdg_domains.txt")
    # epdg_domains = get_epdg_domains("ike_encr_null_domains.txt")

    results_output_file = output_dir / f"{name}.json"
    traffic_output_file = output_dir / f"{name}.pcap"

    if testcase == "CHECK_AUTOCONF_DOMAINS":
        with open(results_output_file, "a") as results_file:
            for domain in epdg_domains:
                domain = domain.replace("epdg.epc", "aes")
                ips = resolve_domain(domain, ip_version)
                for ip in ips:
                    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    data = {
                        "timestamp": timestamp,
                        "domain": domain,
                        "ip": ip,
                    }
                    json_data = json.dumps(data, default=str)
                    logger.debug(json_data)
                    results_file.write(json_data + "\n")
            exit(0)

    sa_list = TEST_CONFIG[testcase]["sa_list"]
    ke = TEST_CONFIG[testcase]["key_echange"]
    ipsec_encr = TEST_CONFIG[testcase].get("ipsec_encr")
    ipsec_integ = TEST_CONFIG[testcase].get("ipsec_integ")
    cert_probe = TEST_CONFIG[testcase].get("cert_probe", False)
    cert_authority = load_cert_authority() if cert_probe else b""
    ipsec_probe = TEST_CONFIG[testcase].get("ipsec_probe", False)

    # start TCP dump to *.pcap file.
    p = subprocess.Popen(
        [
            "tcpdump",
            "-p",
            "-i",
            interface,
            "-w",
            str(traffic_output_file),
            "port",
            "500 or 4500",
        ],
        stdout=subprocess.PIPE,
    )

    # try/finally: always stop tcpdump, even if the scan raises.
    resolver_failures["count"] = 0
    resolved_domains = 0

    try:
        with open(results_output_file, "a") as results_file:
            results_file.write(f"# key exchange: {ke}, sa_list: {sa_list}\n")
            for domain in epdg_domains:
                ips = resolve_domain(domain, ip_version)
                resolved_domains += 1 if ips else 0
                for ip in ips:
                    # an unreachable target skips only itself, not the rest.
                    try:
                        mcc, mnc = get_ids_from_domain(domain)

                        # cert probe: own flow
                        if cert_probe:
                            resp = cert_probe_target(
                                interface,
                                ip,
                                mcc,
                                mnc,
                                TEST_CONFIG[testcase],
                                cert_authority,
                            )
                            timestamp = datetime.datetime.now(
                                datetime.timezone.utc
                            ).strftime("%Y-%m-%dT%H:%M:%SZ")
                            data = {
                                "timestamp": timestamp,
                                "domain": domain,
                                "ip": ip,
                                "response": resp,
                            }
                            json_data = json.dumps(data, default=str)
                            logger.debug(json_data)
                            results_file.write(json_data + "\n")
                            continue

                        # ESP probe: own flow
                        if ipsec_probe:
                            resp = ipsec_probe_target(
                                interface, ip, mcc, mnc, TEST_CONFIG[testcase]
                            )
                            timestamp = datetime.datetime.now(
                                datetime.timezone.utc
                            ).strftime("%Y-%m-%dT%H:%M:%SZ")
                            data = {
                                "timestamp": timestamp,
                                "domain": domain,
                                "ip": ip,
                                "testcase": testcase,
                                "response": resp,
                            }
                            json_data = json.dumps(data, default=str)
                            logger.debug(json_data)
                            results_file.write(json_data + "\n")
                            continue

                        # crafting package.
                        ike = EpdgIKEv2(
                            ip,
                            500,
                            interface=None if interface == "any" else interface,
                            mcc=mcc,
                            mnc=mnc,
                        )
                        # trying to make connection with encryption proposal.
                        resp = ike.ike_sa_init(sa_list, key_exchange=ke)
                        timestamp = datetime.datetime.now(
                            datetime.timezone.utc
                        ).strftime("%Y-%m-%dT%H:%M:%SZ")
                        if not ipsec_encr:
                            data = {
                                "timestamp": timestamp,
                                "domain": domain,
                                "ip": ip,
                                "response": resp,
                            }
                            json_data = json.dumps(data, default=str)
                            logger.debug(json_data)
                            results_file.write(json_data + "\n")
                    except OSError as exc:
                        logger.warning(f"{domain} [{ip}] unreachable: {exc}")
    finally:
        logger.info("terminating tcpdump...")
        p.terminate()
        try:
            # just to be safe.
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            # a stuck capture must not fail the testcase.
            logger.warning("tcpdump did not exit on SIGTERM, killing it")
            p.kill()
        logger.info("done...")

    # Nothing resolved means broken DNS: raise rather than ingest an empty scan,
    # which would read as "no operator supports this DH group".
    if epdg_domains and not resolved_domains:
        raise RuntimeError(
            f"resolved 0 of {len(epdg_domains)} domains "
            f"({resolver_failures['count']} resolver failures) -- DNS is broken "
            f"here, refusing to record an empty scan for {testcase}"
        )
    if resolver_failures["count"]:
        logger.warning(
            f"{resolved_domains}/{len(epdg_domains)} domains resolved, "
            f"{resolver_failures['count']} resolver failures -- results for "
            f"{testcase} are incomplete"
        )

    return results_output_file


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")
    parser = argparse.ArgumentParser(description="ePDG IKE scanner for VoWiFi")
    parser.add_argument("--interface", help="Target Network Interface", default="any")
    parser.add_argument(
        "--ip", help="IP Version", choices=["ipv4", "ipv6", "ipv4v6"], default="ipv4"
    )
    parser.add_argument("--testcase", help="Test Case", choices=TEST_CONFIG.keys())
    args = vars(parser.parse_args())

    interface = args["interface"]
    ip_version = args["ip"]
    testcase = args["testcase"]
    epdg_scanner(interface, ip_version, testcase)
