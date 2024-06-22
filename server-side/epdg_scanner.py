#!/usr/bin/env python3

import re
import time
import pathlib
import argparse
import subprocess
import dns.resolver
from ikev2_class import EpdgIKEv2

TEST_CONFIG={
    "SUPPORT_ENC_NULL_DH_768MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_768MODP
    },
    "SUPPORT_ENC_NULL_DH_1024MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_1024MODP
    },
    "SUPPORT_ENC_NULL_DH_2048MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_2048MODP
    },
    "SUPPORT_DH_768MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_768MODP
    },
    "SUPPORT_DH_1024MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_1024MODP
    },
    "SUPPORT_DH_1536MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_1536MODP
    },
    "SUPPORT_DH_2048MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_2048MODP
    },
    "SUPPORT_DH_3072MODP" : {
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
    "SUPPORT_DH_4096MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_4096MODP
    },
    "SUPPORT_DH_6144MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_6144MODP
    },
    "SUPPORT_DH_8192MODP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_8192MODP
    },

    "SUPPORT_DH_256ECP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_256ECP
    },
    "SUPPORT_DH_384ECP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_384ECP
    },
    "SUPPORT_DH_512ECP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_512ECP
    },
    "SUPPORT_DH_192ECP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_192ECP
    },
    "SUPPORT_DH_224ECP" : {
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
        "key_echange": EpdgIKEv2.KE_DH_224ECP
    },
    
    "SUPPORT_DH_X25519" : {
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
        "key_echange": EpdgIKEv2.KE_DH_X25519
    },

    "TOLERATE_DH1024" : {
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
        "key_echange": EpdgIKEv2.KE_DH_1024MODP
    },

    "DOWNGRADE_DH2048" : {
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
        "key_echange": EpdgIKEv2.KE_DH_2048MODP
    },
    "CHECK_AUTOCONF_DOMAINS":{

    },
    # encr scan:
    "SUPPORT_IKE_ENCR_NULL":{
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
    "SUPPORT_IKE_ENCR_DES":{
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
    "SUPPORT_IPSEC_ENCR_NULL":{
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
        "ipsec_encr": EpdgIKEv2.ENC_NULL,
        "ipsec_integ": EpdgIKEv2.INT_MD5_96
    },
    "SUPPORT_IPSEC_ENCR_DES":{
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
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
        "ipsec_encr": EpdgIKEv2.ENC_DES,
        "ipsec_integ": EpdgIKEv2.INT_MD5_96
    }
}


REGEX_VOWIFI = "^epdg.epc.mnc(\d{2,3}).mcc(\d{3}).pub.3gppnetwork.org\.?$"
def get_ids_from_domain(domain):
    m = re.search(REGEX_VOWIFI, domain)
    mnc = m[1]
    mcc = m[2]
    return mcc, mnc

def get_epdg_domains(filename="epdg_domains.txt"):
    with open(filename) as file:
        return [line.rstrip() for line in file]
    return []

def resolve_domain(operator_url, ip_version="v4v6"):
    dnsres = dns.resolver.Resolver()
    records = []
    try:
        if "v4" in ip_version:
            ans = dnsres.resolve(operator_url, "A")
            for record in ans:
                records.append(record.address)
    except:
        pass
    try:
        if "v6" in ip_version:
            ans = dnsres.resolve(operator_url, "AAAA")
            for record in ans:
                records.append(record.address)
    except:
        pass
    try:
        ans = dnsres.resolve(operator_url, "CNAME")
        for record in ans:
            #print(f"CNAME {ans}")
            records.extend(resolve_domain(record.target, ip_version))
    except:
        pass
    return list(dict.fromkeys(records)) # order

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ePDG IKE scanner for VoWiFi')
    parser.add_argument('--interface', help='Target Network Interface', default="any")
    parser.add_argument('--ip', help='IP Version', choices=["ipv4", "ipv6", "ipv4v6"], default="ipv4")
    parser.add_argument('--testcase', help='Test Case', choices=TEST_CONFIG.keys())
    args = vars(parser.parse_args())

    print("starting")
    interface = args['interface']
    ip_version = args['ip']

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"{args['testcase']}_{timestamp}"
    pathlib.Path("results").mkdir(parents=True, exist_ok=True)

    epdg_domains = get_epdg_domains("epdg_domains.txt")
    #epdg_domains = get_epdg_domains("ike_encr_null_domains.txt")

    if args['testcase'] == 'CHECK_AUTOCONF_DOMAINS':
        with open(f'results/{name}.txt', 'a') as results_file:
            for domain in epdg_domains:
                domain = domain.replace("epdg.epc", "aes")
                ips = resolve_domain(domain, ip_version)
                for ip in ips:
                    timestamp = time.strftime("%Y%m%d-%H%M%S")
                    print(f"[{timestamp}] {domain} -> {ip}")
                    results_file.write(f'[{timestamp}] {domain} -> {ip}\n')
            exit(0)
    
    sa_list = TEST_CONFIG[args['testcase']]['sa_list']
    ke = TEST_CONFIG[args['testcase']]['key_echange']
    ipsec_encr = TEST_CONFIG[args['testcase']].get('ipsec_encr')
    ipsec_integ = TEST_CONFIG[args['testcase']].get('ipsec_integ')
    p = subprocess.Popen(['tcpdump', '-i', interface, '-w', f'results/{name}.pcap', 'port', '500 or 4500'], stdout=subprocess.PIPE)
    with open(f'results/{name}.txt', 'a') as results_file:
        results_file.write(f'# key exchange: {ke}, sa_list: {sa_list}\n')
        for domain in epdg_domains:
            ips = resolve_domain(domain, ip_version)
            for ip in ips:
                mcc, mnc = get_ids_from_domain(domain)
                ike = EpdgIKEv2(ip, 500, interface=None if interface == "any" else interface, mcc=mcc, mnc=mnc)
                resp = ike.ike_sa_init(sa_list, key_exchange=ke)
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                if not ipsec_encr:
                    print(f"[{timestamp}] {domain} -> {ip}: {resp}")
                    results_file.write(f'[{timestamp}] {domain} -> {ip}: {resp}\n')
                elif "successfull" in resp:
                    resp = ike.ike_auth(ipsec_encr, ipsec_integ)
                    print(f"[{timestamp}] {domain} -> {ip}: {resp}")
                    results_file.write(f'[{timestamp}] {domain} -> {ip}: {resp}\n')

    print("terminating tcpdump")
    p.terminate()
    print("done")
            



    
    
