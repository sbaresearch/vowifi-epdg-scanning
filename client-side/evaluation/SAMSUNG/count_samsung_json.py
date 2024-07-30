#!/usr/bin/env python3

# General Imports
import argparse
import json 
from ast import literal_eval
import pprint


def count_ike_parameters(data):
	
	statistics={}
	
	parameter_set_dict={
			"ikev2_dh_group_list":0,
			"ikev2_encr_algo_list":0,		
			"ikev2_prf_algo_list":0,
			"ikev2_hash_algo_list":0,
			"ikev2_lifetime":0,
	}
	
	deprecated = {
		"ikev2_prf_algo_list":{"algorithms":{1:0,3:0},"count":0},
		"ikev2_hash_algo_list":{"algorithms":{1:0,3:0,4:0,6:0,7:0},"count":0},
		"ikev2_encr_algo_list":{"algorithms":{1:0, 2:0, 4:0, 5:0, 6:0, 7:0, 8:0, 9:0},"count":0},		
		"ikev2_dh_group_list":{"algorithms":{1:0,2:0,5:0,22:0},"count":0} #https://www.etsi.org/deliver/etsi_ts/133200_133299/133210/17.01.00_60/ts_133210v170100p.pdf (shall not be supported)
	}
	
	translate_apple_terminology={
		"ikev2_encr_algo_list": {
			"BASIC": -1,
			"ANY":-1,
			"AES_CBC_128": 12,
			"AES_CBC_256": 12,
			"3DES_CBC":3,
			"AES_CBC_192":12,
			"AES_CTR_128":13,
			"AES_CTR_192":13,
			"AES_CTR_256":13,
		},
		
		"ikev2_hash_algo_list": {
			"HMAC_SHA1_96": 2,
			"HMAC_SHA_256_128": 12,
			"HMAC_SHA_512_256": 14,
			"ANY": -1,
			"HMAC_SHA_384_192": 13,
			"HMAC_MD5_96": 1,
			"AES_XCBC_MAC_96": 5,
			"BASIC": -1,
		},
	}	
	res_counts={}
	for provider in data:
		large_dh_group_supp=False
		for key in data[provider]:
			if key.startswith("ikev2"):
				if key not in res_counts:
					res_counts[key]={}
				# If not empty
				if len(data[provider][key])>0:
					parameter_set_dict[key]+=1
					# Flag to decide if we have to increase deprecated count
					deprecated_flag=False
					if key in deprecated:
						#Iterate over the algorithms					
						for algo in data[provider][key]:
							if key in translate_apple_terminology:
								algo=translate_apple_terminology[key][algo]
							else:
								algo=int(algo)
							# Check if the algorithm is deprecated
							if algo in deprecated[key]["algorithms"]:
								# Increment the count of deprecated algorithm
								deprecated[key]["algorithms"][algo]+=1
								deprecated_flag=True
						if deprecated_flag==True:
							deprecated[key]["count"]+=1


				for parsed_element in data[provider][key]:
					if parsed_element not in res_counts[key]:
						res_counts[key][parsed_element]=1
					else:
						res_counts[key][parsed_element]+=1

					if key=="ikev2_dh_group_list":
						if len(parsed_element)>0:
							if int(parsed_element) >= 15:
								large_dh_group_supp=True
		if large_dh_group_supp==True:
			if ">15" not in res_counts["ikev2_dh_group_list"]:
				res_counts["ikev2_dh_group_list"][">15"]=1
			else:
				res_counts["ikev2_dh_group_list"][">15"]+=1
				
	return res_counts,parameter_set_dict,deprecated

def count_samsung_apn_file(jsonfile):
	# Read the json file
	jsonfile = jsonfile
	with open(jsonfile) as json_file:
		data = json.load(json_file)

	res_counts,parameter_set_dict,deprecated=count_ike_parameters(data)
	statistics={}
	statistics["total_providers"]=len(data)	
	statistics["deprecated"]=deprecated
	statistics["parsed_ikev2_params"]=res_counts
	statistics["ikev2_params"]=parameter_set_dict

	for key in parameter_set_dict:
		if key in deprecated:
			deprecated[key]["set"]=parameter_set_dict[key]

	pprint.pprint(statistics)
	return statistics

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-j", "--jsonfile", required=True, type=str, help="Json file with data of parsed MBN Files")
	args=parser.parse_args()
	
	count_samsung_apn_file(args.jsonfile)

if __name__ == "__main__":
	main()
