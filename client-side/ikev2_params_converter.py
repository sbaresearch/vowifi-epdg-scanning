# ikev2_params_converter.py

def get_ikev2_encryption_algorithm_name(encr_id, key_size=""):
    """
    Convert IKEv2 encryption algorithm ID and key size to the algorithm name based on IANA assignments.
    """
    encr_algorithms = {
        "1": "DES-IV64",
        "2": "DES",
        "3": "3DES",
        "4": "RC5",
        "5": "IDEA",
        "6": "CAST",
        "7": "BLOWFISH",
        "8": "3IDEA",
        "9": "DES-IV32",
        "12": "AES-CBC",
        "13": "AES-CTR",
        "14": "AES-CCM-8",
        "15": "AES-CCM-12",
        "16": "AES-CCM-16",
        "18": "AES-GCM-8",
        "19": "AES-GCM-12",
        "20": "AES-GCM-16",
        "21": "NULL",
    }
    name = encr_algorithms.get(encr_id, "Unknown")
    if key_size:
        name += f"({','.join(key_size)}) bits"
    return name


def get_ikev2_prf_algorithm_name(prf_id):
    """
    Convert IKEv2 PRF algorithm ID to the algorithm name.
    """
    prf_algorithms = {
        "1": "HMAC-MD5",
        "2": "HMAC-SHA1",
        "3": "HMAC-TIGER",
        "4": "AES128-XCBC",
        "5": "HMAC-SHA2-256",
        "6": "HMAC-SHA2-384",
        "7": "HMAC-SHA2-512",
		"8": "AES128-CMAC",
        # Add more mappings as required
    }
    return prf_algorithms.get(prf_id, "Unknown")

def get_ikev2_hash_algorithm_name(hash_id):
    """
    Convert IKEv2 integrity (hash) algorithm ID to the algorithm name based on IANA assignments.
    """
    hash_algorithms = {
        "0": "NONE",
        "1": "AUTH_HMAC_MD5_96 (DEPRECATED)",
        "2": "AUTH_HMAC_SHA1_96",
        "3": "AUTH_DES_MAC (DEPRECATED)",
        "4": "AUTH_KPDK_MD5 (DEPRECATED)",
        "5": "AUTH_AES_XCBC_96",
        "6": "AUTH_HMAC_MD5_128 (DEPRECATED)",
        "7": "AUTH_HMAC_SHA1_160 (DEPRECATED)",
        "8": "AUTH_AES_CMAC_96",
        "9": "AUTH_AES_128_GMAC",
        "10": "AUTH_AES_192_GMAC",
        "11": "AUTH_AES_256_GMAC",
        "12": "AUTH_HMAC_SHA2_256_128",
        "13": "AUTH_HMAC_SHA2_384_192",
        "14": "AUTH_HMAC_SHA2_512_256",
    }
    return hash_algorithms.get(str(hash_id), "Unknown")

def get_ikev2_dh_group_name(dh_id):
    """
    Convert IKEv2 DH group ID to the group name.
    """
    dh_groups = {
        "1": "MODP 768",
        "2": "MODP 1024",
        "5": "MODP 1536",
        "14": "MODP 2048",
        "15": "MODP 3072",
        "16": "MODP 4096",
        "17": "MODP 6144",
        "18": "MODP 8192",
        "19": "ECP 256",
        "20": "ECP 384",
        "21": "ECP 521",
        "22": "MODP 1024s160",
        "23": "MODP 2048s224",
        "24": "MODP 2048s256",
        # Add more mappings as required
    }
    return dh_groups.get(dh_id, "Unknown")


def get_ikev2_dh_group_id(dh_name):
	dh_group_list= {
        "MODP_1024": "2",
        "MODP_2048": "14",
        "ANY": "-1",
        "MODP_1536": "5",
        "MODP_3072": "15",
        "MODP_4096": "16",
        "MODP_6144": "17",
        "MODP_8192": "18",
        "ECP_256": "19",
        "MODP_768": "1",
        " MODP_1024": "2",
        " MODP_1536": "5",
        " MODP_2048": "14",
        " MODP_3072": "15",
        " MODP_4096": "16",
        " MODP_6144": "17",
        " MODP_8192": "18",
	}
	return dh_group_list.get(dh_name, "-1")




def convert_ikev2_params(ikev2_params):
    """
    Convert all IKEv2 parameters from their IDs to algorithm names.
    """
    conversion_results = {
        "ikev2_encr_algo_list": [get_ikev2_encryption_algorithm_name(algo["id"], algo.get("key_size", [])) for algo in ikev2_params["ikev2_encr_algo_list"]],
        "ikev2_prf_algo_list": [get_ikev2_prf_algorithm_name(algo["id"]) for algo in ikev2_params["ikev2_prf_algo_list"]],
        "ikev2_hash_algo_list": [get_ikev2_hash_algorithm_name(algo["id"]) for algo in ikev2_params["ikev2_hash_algo_list"]],
        "ikev2_dh_group_list": [get_ikev2_dh_group_name(algo["id"]) for algo in ikev2_params["ikev2_dh_group_list"]]
    }
    return conversion_results
