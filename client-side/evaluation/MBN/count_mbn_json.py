#!/usr/bin/env python3

# General Imports
import argparse
import json 
from ast import literal_eval
import pprint



def count_data(statistics,data):
	"""
	Count the data
	"""
	# https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
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
			"ikev2_sa_rekey_timer":0,
	}

	res_counts={}
	for config in data:
		ikev2_params = config["ikev2_params"]
		large_dh_group_supp=False

		for key in ikev2_params:
			if key not in res_counts:
				if key=="ikev2_sa_rekey_timer":
					res_counts[key+"_soft_sec"]={}
					res_counts[key+"_hard_sec"]={}
				res_counts[key]={}
			# Flag to evaluate if the parameter is deprecated
			deprecated_flag=False
			# Only consider the ikev2 parameters
			if key.startswith("ikev2"):
				# Check if the parameter is empty
				if len(ikev2_params[key])>0:
					parameter_set_dict[key]+=1
					statistics["non_empty_configs"]+=1
					
					# If not empty
					# Decide if we want to perform deprecated check
					if key in deprecated:
						#Iterate over the algorithms
						
						for algo in ikev2_params[key]:
							algo=int(algo["id"])
							# Check if the algorithm is deprecated
							if algo in deprecated[key]["algorithms"]:
								# Increment the count of deprecated algorithm
								deprecated[key]["algorithms"][algo]+=1
								deprecated_flag=True
						if deprecated_flag==True:
							deprecated[key]["count"]+=1

				for parsed_element in ikev2_params[key]:
					
					if key == "ikev2_sa_rekey_timer":
						if "soft_sec" in parsed_element:
							tmpkey=key+"_soft_sec"
							parsed_element=parsed_element["soft_sec"]
						elif "hard_sec" in parsed_element:
							tmpkey=key+"_hard_sec"
							parsed_element=parsed_element["hard_sec"]
						else:
							tmpkey=key
					else:
						tmpkey=key
						parsed_element=str(parsed_element["id"])

					if parsed_element not in res_counts[tmpkey]:
						res_counts[tmpkey][parsed_element]=1
					else:
						res_counts[tmpkey][parsed_element]+=1

					if key=="ikev2_dh_group_list":
						if parsed_element!="0":
							
							if int(parsed_element) >= 15:
								large_dh_group_supp=True
		
		if large_dh_group_supp==True:
			if ">15" not in res_counts["ikev2_dh_group_list"]:
				res_counts["ikev2_dh_group_list"][">15"]=1
			else:
				res_counts["ikev2_dh_group_list"][">15"]+=1
				#if ikev2_params[key].startswith('[') and ikev2_params[key].endswith(']'):
				#	ikev2_params[key]=[s.strip() for s in ikev2_params[key][1:-1].split(',')]

	return statistics,res_counts,parameter_set_dict,deprecated

def count_mbn_results(mbnjson):
	jsonfile = mbnjson
	with open(jsonfile) as json_file:
		data = json.load(json_file)

	data=data["configuration_files"]

	statistics={
		"total_providers":0,
		"total_configs":0,
		"non_empty_configs":0,
		"none_empty_providers":{},
		"ikev2_params":{}
	}
	
	# Read the json file
	statistics["total_configs"]=len(data)


	statistics,parsed_ikev2_params,parameter_set_dict,deprecated = count_data(statistics,data)
	statistics["parsed_ikev2_params"]=parsed_ikev2_params
	statistics["ikev2_params"]=parameter_set_dict
	statistics["deprecated"]=deprecated
	for key in statistics["ikev2_params"]:
		if key in statistics["deprecated"]:
			statistics["deprecated"][key]["set"]=statistics["ikev2_params"][key]
	#Print Statistical results of the parsed MBN File
	pprint.pprint(statistics)

	return statistics

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-j", "--jsonfile", default="../dumps/20230822_Xiaomi_13_Pro_0A_SM8550-AB/ikev2_configuration_parameters.json", required=False, type=str, help="Json file with data of parsed MBN Files")
	args=parser.parse_args()

	count_mbn_results(args.jsonfile)
	

if __name__ == "__main__":
    main()
