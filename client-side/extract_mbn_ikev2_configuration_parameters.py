#!/usr/bin/env python3

# General Imports
import json
import logging
import os
import sys
import re
import argparse

from pathlib import Path
from typing import List, Optional

# Project Imports
import xmltodict 
import pandas as pd

from mobile_codes import MobileCodeSearcher

import ikev2_params_converter

import pycountry_convert as pc

import pprint

mobiledb = MobileCodeSearcher('metadata/mccmnc.csv')

logger = logging.getLogger(__name__)
valid_meta=0
total_meta=0

statistics={
		"total_configs":0,
		"ikev2_no_enc_algo":0,
		"ikev2_no_dh_algo":0,
		"ikev2_parameter_no_dict":0
	}

def country_to_continent(country_name):
    country_alpha2 = pc.country_name_to_country_alpha2(country_name)
    country_continent_code = pc.country_alpha2_to_continent_code(country_alpha2)
    country_continent_name = pc.convert_continent_code_to_continent_name(country_continent_code)
    return country_continent_name

def listdir_fullpath(d):
	"""
		List all files in a directory and return their full path.
	"""
	return [os.path.join(d, f) for f in os.listdir(d)]

def extract_encr_algo(key,encr_algo,enc_algo_out):	
		"""
		 	Returns either a dict or a list of dicts with the encryption algorithms.
		"""
		# CASE 1'encr_algo':[{'@value': '12', 'key_size': ['256', '128']}, {'@value': '3'}, {'@value': '2'}]		
		# or CASE 2
		# @value 12
		# key_size [128,256]
		if isinstance(encr_algo,list):
				#CASE 1
				if "key_size" not in key and "@value" not in key:					
					for elem in encr_algo:
						res=[]
						enc_algo_out={"id":None,"key_size":None}
						if "@value" in elem:
							enc_algo_out["id"]=elem["@value"]
						if "key_size" in elem:
							enc_algo_out["key_size"]=elem["key_size"]
						res.append(enc_algo_out)
					return res
				#CASE 2
				else:
					for val in encr_algo:
						if "@value" in key:
							if enc_algo_out["id"] == None:
								enc_algo_out["id"]=[]
							else:
								enc_algo_out["id"].append(val)
						if "key_size" in key:
							if enc_algo_out["key_size"] == None:
								enc_algo_out["key_size"]=[]
							else:
								enc_algo_out["key_size"].append(val)
		# E.g. 
		# @value 12
		# key_size 128		
		else:
			if "@value" in key:					
				enc_algo_out["id"]=encr_algo
			if "key_size" in key:
				enc_algo_out["key_size"]=encr_algo
	
		return enc_algo_out

def extract_dh_group(key,dh_group,dh_group_out):
	#print(key)
	#print(dh_group)
	#[{'@value': '14'}, {'@value': '5'}, {'@value': '2'}]
	#2
	if isinstance(dh_group,list):
		res=[]
		for elem in dh_group:
			uniqe_ids={}
			if "@value" in elem:
				if elem["@value"] not in uniqe_ids:
					uniqe_ids[elem["@value"]]=1
					res.append({"id":elem["@value"]})
		return res
	else:
		dh_group_out["id"]=dh_group
	return dh_group_out

def get_all_keys(d):
    for key, value in d.items():
        yield key
        if isinstance(value, dict):
            yield from get_all_keys(value)

def find_ikev2_params(nested_dict, ikev2_params):
    # Function to recursively search for keys in a nested dictionary
    def search_dict(d, results):
        for key, value in d.items():
            if key in ikev2_params:
                # If the key matches, add the current sub-dictionary to the results
                results[key] = value
            elif isinstance(value, dict):
                # If the value is another dictionary, search recursively
                search_dict(value, results)
            elif isinstance(value, list):
                # If the value is a list, iterate through it
                # This is useful if the dictionary contains lists of dictionaries
                for item in value:
                    if isinstance(item, dict):
                        search_dict(item, results)

    results = {}
    search_dict(nested_dict, results)
    return results


def normalize_results(results,ikev2_params):
	"""
		Put results in a standardized format
		# {'ikev2_encr_algo_list': {'encr_algo': {'@value': '12', 'key_size': '128'}}, 'ikev2_prf_algo_list': {'prf_algo': {'@value': '2'}}, 'ikev2_hash_algo_list': {'algo': {'@value': '2'}}, 'ikev2_dh_group_list': {'dh_group': {'@value': '2'}}}
		# should be
		# {'ikev2_encr_algo_list': [{'id': '12', 'key_size': '128'}], 'ikev2_prf_algo_list': [{'id': '2'}], 'ikev2_hash_algo_list': [{'id': '2'}], 'ikev2_dh_group_list': [{'id': '2'}]}
	"""
	#print(results)
	
	for param in results.keys():
		if isinstance(results[param],dict):
			for key in results[param].keys():
				if isinstance(results[param][key],list):
					for elem in results[param][key]:
						if isinstance(elem,dict):
							if "@value" in elem:
								ikev2_params[param].append({"id":elem["@value"]})
							if "key_size" in elem:
								ikev2_params[param][-1]["key_size"]=elem["key_size"]
				else:
					if "@value" in results[param][key]:
						ikev2_params[param].append({"id":results[param][key]["@value"]})
					elif "key_size" in results[param][key]:
						ikev2_params[param][-1]["key_size"]=results[param][key]["key_size"]
					else:
						ikev2_params[param].append({key:results[param][key]})
		else:
			statistics["ikev2_parameter_no_dict"]+=1
			#ikev2_params[param].append(results[param][key])
			#if "hard_sec" in key:
			#	ikev2_params[param]["hard_sec"]=results[param]["hard_sec"]
			#if "soft_sec" in key:
				#	ikev2_params[param]["soft_sec"]=results[param]["soft_sec"]
	#print(ikev2_params)
	return ikev2_params

def parse_parameters_from_nested_dict(iwlan_dict):
	"""
		Extract the parameters from the nested dictionary.
	"""
	ikev2_params={
		"ikev2_encr_algo_list":[],
		"ikev2_prf_algo_list":[],
		"ikev2_hash_algo_list":[],
		"ikev2_dh_group_list":[],
		"ikev2_sa_rekey_timer":[]
	}

	# Iterate over nested dict and see if the key is included in ikev2_params
	results=find_ikev2_params(iwlan_dict, ikev2_params)
	
	# Put results in a standardized format
	ikev2_params=normalize_results(results,ikev2_params)

	return ikev2_params


def parse_custom_xml(config_file):
	"""
		Parse the custom xml file and return the parameters.
		<ikev2_encr_algo_list>\n
			<encr_algo value=\"12\">\n
				<key_size> 128 </key_size>\n
            </encr_algo>\n
		</ikev2_encr_algo_list>\n
		<ikev2_prf_algo_list>\n
			<prf_algo value=\"2\"/>\n
		</ikev2_prf_algo_list>\n
		<ikev2_hash_algo_list>\n
			<algo value=\"2\"/>\n
		</ikev2_hash_algo_list>\n
		<ikev2_dh_group_list>\n
		<dh_group value=\"2\"/>\n
		</ikev2_dh_group_list>\n
		<esp_encr_algo_list>\n 
			<encr_algo value=\"12\">\n
				<key_size>128</key_size>\n
			</encr_algo>\n
		</esp_encr_algo_list>\n
		<esp_auth_algo_list>\n
			<algo value=\"2\"/>\n
		</esp_auth_algo_list>\n 
	"""
	
	#Strip the first byte from the file and parse the xml
	with open(config_file, "rb") as f:	
		data = f.read()
		if int(data[0]) == 7:
			data = data[1:]
		else:
			# reconstructing the data as a dictionary 
			js = json.loads(data) 
			data=js["unparsed"]["ascii"]

	# Use xmltodict to parse and convert  
	# the XML documen 
	try:
		iwlan_dict = xmltodict.parse(data) 
		#print(iwlan_dict)
	except Exception as e:
		logger.warning("Exception occurred trying to parse xml file.", e)
		return None
	
	return iwlan_dict


def reduce_ikev2_results(ikev2_results):
	"""
		Count the occurence of each list element for each parameter and reduce the list to unique values.
	"""
	for param in ikev2_results.keys():
		out_res={}
		for res in ikev2_results[param]:
			
			for elem in res:
				
				if "hard_sec" in elem:
					continue
				if "key_size" in elem:
					elem=str(elem["id"])+"|"+str(elem["key_size"])
				else:
					for key in elem:
						elem=str(elem[key])
				if elem not in out_res:
					out_res[elem]=1
				else:
					out_res[elem]+=1
		ikev2_results[param]=out_res
	return ikev2_results		


def parse_metafile(meta_path):
	"""
	"operator": {
      "hex": "56 6f 6c 74 65 5f 4f 70 65 6e 4d 6b 74 2d 43 6f 6d 6d 65 72 63 69 61 6c 2d 43 4d 48 4b",
      "ascii": "Volte_OpenMkt-Commercial-CMHK",
      "__type__": "bytes"
    },
    "iccids": {
      "ids": [
        8985212,
        8985230
      ],
      "unknown_field": 0
    },
    "version2": {
      "hex": "01 22 01 0a",
      "ascii": "\u0001\"\u0001\n",
      "__type__": "bytes"
    },
    "mnoid": {
      "ids": [
        {
          "mcc": 454,
          "mnc": 12,
          "__type__": "MnoId"
        },
        {
          "mcc": 454,
          "mnc": 13,
          "__type__": "MnoId"
        },
        {
          "mcc": 454,
          "mnc": 30,
          "__type__": "MnoId"
	"""
	global total_meta
	global valid_meta
	total_meta+=1
	with open(meta_path, "rb") as f:
		data = f.read()
		js = json.loads(data) 
		
		if "trailer" in js:
			
			valid_meta+=1
			data=js["trailer"]
			operator=data["operator"]["ascii"]
			countries={"mccs":{}}
			ids=data["mnoid"]["ids"]
			for id in ids:
				if id["mcc"] not in countries["mccs"]:
					countries["mccs"][id["mcc"]]={}
					try:
						country = mobiledb.search_by_mcc(str(id["mcc"]))[0]
					except:
						country="Unknown"
					try:
						continent=country_to_continent(country)
					except:
						continent="Unknown"
					try:
						mnc_network = mobiledb.search_by_mcc_mnc(str(id["mcc"]),str(id["mnc"]))[0]["Network"]
					except:
						mnc_network="Unknown"
					countries["mccs"][id["mcc"]]["country"]=country
					countries["mccs"][id["mcc"]]["continent"]=continent		
					countries["mccs"][id["mcc"]]["mncs"]=[{id["mnc"]:mnc_network}]
				else:
					try:
						mnc_network = mobiledb.search_by_mcc_mnc(str(id["mcc"]),str(id["mnc"]))[0]["Network"]
					except:
						mnc_network="Unknown"
					countries["mccs"][id["mcc"]]["mncs"].append({id["mnc"]:mnc_network})
			return {"operator":operator,"countries":countries}
		
		return {"operator":None,"countries":None}
	
def extract_iwlan_xml_files(folder,file_list):
	"""
		Iteratively extract all iwlan xml files from a folder and return their full path.
	"""
	for folder_content in listdir_fullpath(folder):
		# If it is a file check if we got a correct file else repeat this function for the subfolder
		if os.path.isfile(folder_content):
			
			if str(folder_content).endswith("iwlan_s2b_config.xml"):
				file_list.append(folder_content)
		else:
			file_list=extract_iwlan_xml_files(folder_content,file_list)
	return file_list



def evaluate_mbn_files(folder,outputfile):
	# Iterate folder and list xml files (endswith("iwlan_s2b_config.xml"):)
	iwlan_s2b_list=extract_iwlan_xml_files(folder,[])
	# Remove parsed_nv_files
	iwlan_s2b_list=[x for x in iwlan_s2b_list if "parsed_nv_files" not in x]
	
	ikev2_results={
		"ikev2_encr_algo_list":[],
		"ikev2_prf_algo_list":[],
		"ikev2_hash_algo_list":[],
		"ikev2_dh_group_list":[],
		"ikev2_sa_rekey_timer":[]
	}

	out_dict={"configuration_files":[]}

	# Iterate over all iwlan_s2b_config.xml files
	for config_file in iwlan_s2b_list:
		config_res={"filename":config_file}

		# Retrieve meta file
		meta_path=re.sub("/files/data/.*","/meta",config_file)
		#meta_path=re.sub("/parsed_nv_files/data/.*","/meta",meta_path)
		metadata=parse_metafile(meta_path)
		config_res.update(metadata)

		# Parse file	
		# Parse the custom xml file and and return a dict from the xml 
		iwlan_dict=parse_custom_xml(config_file)
		# Parse the parameters
		ikev2_params=parse_parameters_from_nested_dict(iwlan_dict)
		# Add the parameters to the result dict	
		for key in ikev2_results.keys():
			if len(ikev2_params[key]) > 0:
				ikev2_results[key].append(ikev2_params[key])
			else:
				ikev2_results[key].append([{"id":None}])
		config_res["ikev2_params"]=ikev2_params
		statistics["total_configs"]+=1
		
		#Add output to dict
		out_dict["configuration_files"].append(config_res)

	# Save out_dict to json file
	with open(outputfile, "w") as outfile: 
		json.dump(out_dict, outfile,indent=4)

def main():
	# Parse	arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--folder", required=True, type=str, help="Folder with parsed MBN Files")
	parser.add_argument("-o", "--outputfile", required=True, default="ikev2_configuration_parameters.json", type=str, help="Folder with parsed MBN Files")

	args=parser.parse_args()
	
	evaluate_mbn_files(args.folder,args.outputfile)
	

if __name__ == "__main__":
    main()
