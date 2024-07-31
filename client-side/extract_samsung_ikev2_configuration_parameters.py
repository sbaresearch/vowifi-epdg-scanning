#!/usr/bin/env python3

# General Imports
import logging
import xmltodict 
import argparse
import ikev2_params_converter
import pprint
import json

statistics={
		"total_configs":0,
		"ikev2_no_enc_algo":0,
		"ikev2_no_dh_algo":0
	}


def evaluate_samsung_apn_file(samsungxml,outfile):
	# Read the xml file
	with open(samsungxml) as fd:
		doc = xmltodict.parse(fd.read())

	# Extract the ikev2 configurations
	config_dict={}
	doc=doc['iwlanapns']["iwlansettings"]
	for apn in doc["apn"]:
		
		# Check if the APN is default
		provider=apn["@mnoname"]
		if provider == "default":
			continue
			
		# Check if the APN is of type ims
		#apnname="ims"
		if apn["@apnname"]!="ims":
			continue

		# Provider ready for evaluation
		print("Provider: ",provider)
		
		if provider not in config_dict:
			config_dict[provider]={
			"mcc":[],
			"mnc":[], 		
			"ikev2_encr_algo_list":[],
			"ikev2_prf_algo_list":[],
			"ikev2_hash_algo_list":[],
			"ikev2_dh_group_list":[],
			"ikev2_lifetime":[]}
		epdg_domain=apn["@ownidentity"]
		
		# Extract the mcc and mnc
		domain_part=epdg_domain.split("@")[1].split(".")
		mcc=domain_part[3].replace("mcc","")
		if mcc not in config_dict[provider]["mcc"]:
			config_dict[provider]["mcc"].append(mcc)
		mnc=domain_part[2].replace("mnc","")
		if mnc not in config_dict[provider]["mnc"]:
			config_dict[provider]["mnc"].append(mnc)
		
		# Extract the ikev2 configurations
		# Extract the ikev2 DH Group
		try:
			dh_group=[x.replace("IKE_GROUP_","") for x in apn["@ikegroup"].split(",")]
			for group in dh_group:
				group_id=ikev2_params_converter.get_ikev2_dh_group_id(group)
				if group_id not in config_dict[provider]["ikev2_dh_group_list"]:
					config_dict[provider]["ikev2_dh_group_list"].append(group_id)
		except:
			pass

		# Extract the ikev2 encryption algorithm
		try:
			encryption=[x.replace("IKE_ENCRYPTION_","") for x in apn["@ikeencryption"].split(",")]
			for algo in encryption:
				if algo not in config_dict[provider]["ikev2_encr_algo_list"]:
					config_dict[provider]["ikev2_encr_algo_list"].append(algo)
		except:
			pass

		# Extract the ikev2 hash algorithm
		try:
			hash_algo=[x.replace("IKE_INTEGRITY_","") for x in apn["@ikeintegrity"].split(",")]
			if hash_algo not in config_dict[provider]["ikev2_hash_algo_list"]:
				for algo in hash_algo:
					config_dict[provider]["ikev2_hash_algo_list"].append(algo)
		except:
			pass

		# Extract the ikev2 lifetime parameter
		try:
			lifetime=apn["@ikelife"]
			if lifetime not in config_dict[provider]["ikev2_lifetime"]:
				config_dict[provider]["ikev2_lifetime"].append(lifetime)
		except:
			pass
	# Dump the result as json
	with open(outfile, "w") as outfile:
		json.dump(config_dict, outfile, indent=4)


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--samsungfile", required=True, type=str, default="dumps/Samsung_Clientside/epdg_apns_conf.xml", help="File including samsung ikve2 configuration as xml")
	parser.add_argument("-o", "--outfile", required=True, type=str, default="dumps/Samsung_Clientside/epdg_apns_conf.xml", help="File including samsung ikve2 configuration as xml")

	args=parser.parse_args()

	evaluate_samsung_apn_file(args.samsungfile,args.outfile)

if __name__ == "__main__":
    main()