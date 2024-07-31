#!/usr/bin/env python3

# General Imports
import argparse
import json 
from ast import literal_eval
import pprint
 

translate_apple_terminology={
	"ikev2_encr_algo_list": {
		"'3DES'": 3,
		"'AES-128'": 12,
		"'AES-256'": 12,
	},
	"ikev2_prf_algo_list": {
		"'MD5-128'": 1,
		"'SHA1-160'": 2,
        "'SHA2-256'": 5,
        "'SHA2-512'": 7},
	"ikev2_hash_algo_list": {
		"'MD5-96'": 1,
        "'SHA1-96'": 2,
        "'SHA2-256'": 12,
        "'SHA2-384'": 13,
        "'SHA2-512'": 14},
}
def count_apple_ike_parameters(statistics,data):
	"""
	
	"""

	deprecated = {
		"ikev2_prf_algo_list":{"algorithms":{1:0,3:0},"count":0},
		"ikev2_hash_algo_list":{"algorithms":{1:0,3:0,4:0,6:0,7:0},"count":0},
		"ikev2_encr_algo_list":{"algorithms":{1:0, 2:0, 4:0, 5:0, 6:0, 7:0, 8:0, 9:0},"count":0},
		"ikev2_dh_group_list":{"algorithms":{1:0,2:0,5:0,22:0},"count":0} #https://www.etsi.org/deliver/etsi_ts/133200_133299/133210/17.01.00_60/ts_133210v170100p.pdf (shall not be supported)
	}

	parameter_set_dict={
		"ikev2_dh_group_list":0,
		"ikev2_encr_algo_list":0,		
		"ikev2_prf_algo_list":0,
		"ikev2_hash_algo_list":0,
		"ikev2_lifetime":0,
	}	
	res_counts={}
	for provider in data:
		non_empty=False
		large_dh_group_supp=False

		for key in data[provider]:
			
			
			if key.startswith("ikev2"):
				if key not in res_counts:
					res_counts[key]={}
				#print("Key: ",key)
				#print("Data: ",data[provider][key])				
				if data[provider][key].startswith('[') and data[provider][key].endswith(']'):
					data[provider][key]=[s.strip() for s in data[provider][key][1:-1].split(',')] #literal_eval(element)
				
				if len(data[provider][key][0])>0:
				


					parameter_set_dict[key]+=1
					operator=provider.split("_")[0]
					statistics["none_empty_providers"][operator]=1
				for parsed_element in data[provider][key]:
					if parsed_element not in res_counts[key]:
						res_counts[key][parsed_element]=1
					else:
						res_counts[key][parsed_element]+=1

					value=parsed_element
					if value:
						if key in translate_apple_terminology:
							value=translate_apple_terminology[key][value]
						else:
							value=int(value)
						
						# Deprecation check
						if key in deprecated: 
							if value in deprecated[key]["algorithms"]:
								deprecated[key]["algorithms"][value]+=1
								deprecated[key]["count"]+=1	

					if key=="ikev2_dh_group_list":
						if len(parsed_element)>0:
							#print(parsed_element)
							if int(parsed_element) >= 15:
								large_dh_group_supp=True

								
		if large_dh_group_supp==True:
			if ">15" not in res_counts["ikev2_dh_group_list"]:
				res_counts["ikev2_dh_group_list"][">15"]=1
			else:
				res_counts["ikev2_dh_group_list"][">15"]+=1

						
		if non_empty==True:
			statistics["non_empty_configs"]+=1
	return statistics,res_counts,parameter_set_dict,deprecated

def count_apple(jsonfile):
	with open(jsonfile) as json_file:
		data = json.load(json_file)

	# Read the json file
	statistics={
		"total_providers":0,
		"total_configs":0,
		"non_empty_configs":0,
		"none_empty_providers":{},
		"parsed_ikev2_params":{},
		"ikev2_params":{},
		"deprecated":{}
	}

	statistics["total_configs"]=len(data)
	statistics["total_providers"]=len(set([x.split("_")[0] for x in data.keys()]))
	statistics,res_counts,parameter_set_dict,deprecated=count_apple_ike_parameters(statistics,data)

	
	# Print the result
	statistics["parsed_ikev2_params"]=res_counts
	statistics["ikev2_params"]=parameter_set_dict
	statistics["deprecated"]=deprecated
	for key in statistics["ikev2_params"]:
		if key in statistics["deprecated"]:
			statistics["deprecated"][key]["set"]=statistics["ikev2_params"][key]

	output_res=json.dumps(res_counts, indent=4)


	statistics["none_empty_providers"]=len(statistics["none_empty_providers"])
	pprint.pprint(statistics)
	return statistics

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-j", "--jsonfile", required=False, default="apple_ike_configuration_parameters.json",type=str, help="Json file with data of parsed MBN Files")
	args=parser.parse_args()
	count_apple(args.jsonfile)

if __name__ == "__main__":
	main()
