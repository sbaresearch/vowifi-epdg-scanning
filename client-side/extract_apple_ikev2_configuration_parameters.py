#!/usr/bin/env python3

# General Imports
import json
import logging
import os
import sys
import re
import argparse
import pprint 
import glob
from pathlib import Path
from typing import List, Optional

# Project Imports
import xmltodict 
import xml.etree.ElementTree as ET
import pandas as pd

from datetime import datetime

from mobile_codes import MobileCodeSearcher

import ikev2_params_converter

import pycountry_convert as pc

mobiledb = MobileCodeSearcher('metadata/mccmnc.csv')

logger = logging.getLogger(__name__)
valid_meta=0
total_meta=0

statistics={
		"total_configs":0,
		"ikev2_no_enc_algo":0,
		"ikev2_no_dh_algo":0
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

def extract_xml_files(folder,file_list):
	"""
		Iteratively extract all iwlan xml files from a folder and return their full path.
	"""
	for folder_content in listdir_fullpath(folder):
		# If it is a file check if we got a correct file else repeat this function for the subfolder
		if os.path.isfile(folder_content):
			
			if str(folder_content).endswith(".plist.xml"):
				file_list.append(folder_content)
		else:
			if "signatures" not in folder_content:
				file_list=extract_xml_files(folder_content,file_list)
	return file_list
	
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
	print(key)
	print(dh_group)
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
	for param in results.keys():
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
				if "key_size" in results[param][key]:
					ikev2_params[param][-1]["key_size"]=results[param][key]["key_size"]
	return ikev2_params



# Function to handle parsing of different element types
def parse_element(element):
    if element.tag == 'dict':
        return {element[i].text: parse_element(element[i+1]) for i in range(0, len(element), 2)}
    elif element.tag == 'array':
        return [parse_element(el) for el in element]
    elif element.tag == 'true':
        return True
    elif element.tag == 'false':
        return False
    elif element.tag in ['string', 'integer']:
        return element.text if element.tag == 'string' else int(element.text)
    else:
        return None

# Load and parse the XML
def parse_apple_xml(xml_data):
    root = ET.fromstring(xml_data)
    # Assuming the first child of the root <plist> is the main <dict>
    main_dict = root.find('dict')
    return parse_element(main_dict)


def parse_xml(config_file):
	"""
		Parse APPLE IPCC PLIST FILES.
	"""
	
	#Strip the first byte from the file and parse the xml
	with open(config_file, "rb") as f:	
		data = f.read()
	
	# Use xmltodict to parse and convert  
	try:
		plist_dict = parse_apple_xml(data) 

	except Exception as e:
		logger.warning("Exception occurred trying to parse xml file.", e)
		return None

	return plist_dict


def parse_parameters_from_apple_plist(plist_dict):
	"""
		Extract the parameters from the apple plist dictionary.
		'TechSettings': {'5wiServiceMask': 3,
                  'AllowRoamingHandover': False,
                  'ChildSAs': {'FirstChild': {'ChildProposals': [{'DHGroup': 14,
                                                                  'EncryptionAlgorithm': ['AES-256'],
                                                                  'IntegrityAlgorithm': ['SHA2-256'],
                                                                  'Lifetime': 80000}],
                                              'InstallPolicies': True,
                                              'ReplayWindowSize': 12}},
                  'EPDGResolutionFallbackEnabled': True,
                  'ExtraConfigurationAttributeRequestv4': [{'Identifier': 16384,
                                                            'Name': 'AssignedPCSCFIPv4',
                                                            'Type': 'IPv4Address'}],
                  'ExtraConfigurationAttributeRequestv6': [{'Identifier': 16386,
                                                            'Name': 'AssignedPCSCFIPv6',
                                                            'Type': 'IPv6Address'}],
                  'IKE': {'DeadPeerDetectionEnabled': False,
                          'DeadPeerDetectionInterval': 300,
                          'DeadPeerDetectionMaxRetries': 4,
                          'DeadPeerDetectionRetryInterval': 10,
                          'LocalIdentifier': 'Telstra@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org',
                          'NATTKeepAliveOffload': True,
                          'Proposals': [{'AuthenticationMethod': 'Certificate',
                                         'DHGroup': 14,
                                         'EAPMethod': 'EAP-AKA',
                                         'EncryptionAlgorithm': 'AES-256',
                                         'IntegrityAlgorithm': 'SHA2-256',
                                         'Lifetime': 80000,
                                         'PRFAlgorithm': 'SHA2-256'}],
                          'RemoteAddress': 'epdg.epc.mnc001.mcc505.pub.3gppnetwork.org',
                          'RemoteCertificateAuthorityName': 'DigiCert Global '
                                                            'Root G2',
                          'RemoteCertificateHostname': 'epdg.epc.mnc001.mcc505.pub.3gppnetwork.org',
                          'Username': '0$imsi@nai.epc.mnc001.mcc505.3gppnetwork.org',
                          'ValidateRemoteCertificate': True},

	"""
	ikev2_params={
		"ikev2_encr_algo_list":[],
		"ikev2_prf_algo_list":[],
		"ikev2_hash_algo_list":[],
		"ikev2_dh_group_list":[],
		"ikev2_lifetime":[]
	}
	
	# Extract the ikev2 parameters from the plist dictionary
	if "TechSettings" in plist_dict:
		tech_settings=plist_dict["TechSettings"]
		try:
			ikev2_params["ikev2_encr_algo_list"]=[{"id":x for x in [tech_settings["IKE"]["Proposals"][0]["EncryptionAlgorithm"]]}]
		except:
			pass
		try:
			ikev2_params["ikev2_prf_algo_list"]=[{"id":x for x in [tech_settings["IKE"]["Proposals"][0]["PRFAlgorithm"]]}]
		except:
			pass
		try:
			ikev2_params["ikev2_hash_algo_list"]=[{"id":x for x in [tech_settings["IKE"]["Proposals"][0]["IntegrityAlgorithm"]]}]
		except:
			pass
		try:
			ikev2_params["ikev2_dh_group_list"]=[{"id":x for x in [tech_settings["IKE"]["Proposals"][0]["DHGroup"]]}]
		except:
			pass
		try:
			ikev2_params["ikev2_lifetime"]=[{"id":x for x in [tech_settings["IKE"]["Proposals"][0]["Lifetime"]]}]
		except:
			pass

	# Convert the ikev2 parameters to a standardized format
	#ikev2_params=ikev2_params_converter.convert_ikev2_params(ikev2_params)
	return ikev2_params



def reduce_ikev2_results(ikev2_results):
	"""
		Count the occurence of each list element for each parameter and reduce the list to unique values.
	"""
	for param in ikev2_results.keys():
		out_res={}
		for res in ikev2_results[param]:
			for elem in res:
				if "key_size" in elem:
					elem=str(elem["id"])+"|"+str(elem["key_size"])
				else:
					elem=str(elem["id"])
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

def output_stdout(ikev2_results):
	# STDOUT
	
	ikev2_results=reduce_ikev2_results(ikev2_results)

	#print(ikev2_results)
	for param in ikev2_results.keys():
		print(param)	
		for elem in ikev2_results[param]:			
			#if param == "ikev2_encr_algo_list":
			#	print(elem)
			#	encr=elem.split("|")
			#	encr_algo=encr[0]
			#	elem=encr_algo				
			#	if len(encr)>1:
			#		key_size=encr[1].split(",")
			#		name=ikev2_params_converter.get_ikev2_encryption_algorithm_name(encr_algo,key_size)
			#	else:
			#		name=ikev2_params_converter.get_ikev2_encryption_algorithm_name(encr_algo)
			#elif param=="ikev2_prf_algo_list":
			#	name=ikev2_params_converter.get_ikev2_prf_algorithm_name(elem)
			#elif param=="ikev2_hash_algo_list":
			#	name=ikev2_params_converter.get_ikev2_hash_algorithm_name(elem)
			if param=="ikev2_dh_group_list":
				name=ikev2_params_converter.get_ikev2_dh_group_name(elem)
			if elem == "None":
				name="None"
			
			print(str(ikev2_results[param][elem])+","+elem+","+name) #str(round(ikev2_results[param][elem]/statistics["total_configs"]*100,2))+","+


def retrieve_update_time(config_dir,urls,update_time_error,update_time_error_configs):
				"""
					Return update time of the config directory.
				"""
				update_time="Unknown"
				# Extract date from config_dir
				if config_dir.count(".")>1:
					try:
						date_str=config_dir.split(".")[1][-8:]
						
						update_time=datetime.strptime(date_str,'%Y%m%d')
					except:					
						update_time="Unknown"
					if update_time == "Unknown":
						try:
							date_str=config_dir.split(".")[0][-8:]
							update_time=datetime.strptime(date_str,'%Y%m%d')
						except:
							update_time="Unknown"
					
				else:	
					try:
						date_str=config_dir.split("-")[2]
						if len(date_str) == 8:
							update_time=datetime.strptime(date_str,"%Y%m%d")
					except:
						update_time="Unknown"

				# If normal way does not work, retrieve date over download url
				if update_time == "Unknown":
					try:
						retrieved_url=[x for x in urls if config_dir.split("_")[0] in x]
						print(retrieved_url)
						date_str=retrieved_url[0].split("/")[3]
						if len(date_str)==8:
							update_time=datetime.strptime(date_str,"%Y%m%d")
						else:
							update_time=datetime.strptime(date_str,"%Y")
					except:
						update_time="Unknown"
				if update_time == "Unknown":
					update_time_error+=1
					update_time_error_configs.append(config_dir)
				else:
					print("--"+config_dir+","+update_time.strftime("%Y-%m-%d"))
				return update_time,update_time_error,update_time_error_configs


def retrieve_udpate_times(config_dirs,providers,urls):
	"""
		Retrieve config directories and extract the update time from the directory name.
	"""
	config_dict={}
	update_time_error=0
	update_time_error_configs=[]


	for provider in providers:
		if provider not in config_dict:
			config_dict[provider]={}
		print(provider)
		# Collect all ipccs for a provider
		for config_dir in config_dirs:			
			if provider in config_dir:
				if config_dir not in config_dict[provider]:
					update_time,update_time_error,update_time_error_configs=retrieve_update_time(config_dir,urls,update_time_error,update_time_error_configs)
					config_dir=str(config_dir)
					config_dict[provider][config_dir]={}
					config_dict[provider][config_dir]["update_time"]={}
					config_dict[provider][config_dir]["update_time_str"]={}
					
					config_dict[provider][config_dir]["update_time"]=update_time
					if update_time!="Unknown":
						config_dict[provider][config_dir]["update_time_str"]=update_time.strftime("%Y-%m-%d")
					else:
						config_dict[provider][config_dir]["update_time_str"]=update_time
	
	print("Finished - in "+str(update_time_error)+" cases the update time could not be retrieved.")
	print(update_time_error_configs)
	return config_dict

def iterdict(d):
    for k, v in d.items():
        if isinstance(v, dict):
            iterdict(v)
        else:
            v = str(v)
            d.update({k: v})
    return d

def evaluate_apple_ipccs(apple_folder,carrier_file,output_file,update_file):
	ipcc_urls=apple_folder+"/ipcc_urls.txt"
	with open(ipcc_urls) as f:
		urls = f.readlines()
		urls = [x.strip() for x in urls]

	#Read providers file
	with open(carrier_file) as f:
		providers = f.readlines()
		providers = [x.strip() for x in providers]
	
	# List all directories in apple_folder
	config_dirs=[a for a in os.listdir(apple_folder) if os.path.isdir(apple_folder+"/"+a)] #glob.glob('*' + os.path.sep)#[x[0] for x in os.walk(apple_folder)]
	# Check if case insensitive string Iphone is present in folder name
	config_dirs=[x for x in config_dirs if "iphone" in x.lower()]
	config_dict=retrieve_udpate_times(config_dirs,providers,urls)
	

	supported_sims_fails=0
	#Save update time dict to json file
	#Strip "update_time" from config_dict
	exit_true=False
	for provider in config_dict.keys():
		for config_dir in config_dict[provider]:
			#Retrieve HNI from config_dir
			# Open Payload/<provider_named_folder>/carrier.plist.xml
			# Parse apple XML format
			# Extract HNI
			# 1. Check if file exists
			# Retrieve provider named folder, by listing the first directory from the payload dir
			bundle_dirs=[a for a in os.listdir(apple_folder+"/"+config_dir+"/Payload") if os.path.isdir(apple_folder+"/"+config_dir+"/Payload/"+a)] #glob.glob('*' + os.path.sep)#[x[0] for x in os.walk(apple_folder)]
			print(bundle_dirs)
			carrier_file=apple_folder+"/"+config_dir+"/Payload/"+bundle_dirs[0]+"/carrier.plist.xml"
			if os.path.isfile(carrier_file):
				# 2. Parse file
				plist_dict=parse_xml(carrier_file)
				# 3. Extract HNI
				try:
					hni=plist_dict["SupportedSIMs"]
				except:
					supported_sims_fails+=1
					hni="Unknown"
			else:
				hni="Unknown"

			config_dict[provider][config_dir]["hni"]=hni
			
	
			ipcc_plist=extract_xml_files(apple_folder+"/"+config_dir+"/Payload/"+bundle_dirs[0]+"/",[])
	
				
			for config_file in ipcc_plist:
				if "version" not in config_file and "hexvalues" not in config_file:
					print(config_file)
					plist_dict=parse_xml(config_file)

					ikev2_params=parse_parameters_from_apple_plist(plist_dict)
					config_dict[provider][config_dir][config_file]=ikev2_params
					
				
			if exit_true:
				exit(1)
			
			#config_dict[provider][config_dir].pop("update_time")


	# Go through all update bundles and evaluate ikev2 parameters, newer updates overwrite older ones
	apple_results={}
	for provider in config_dict.keys():
		provider_latest={
			"update_time":datetime.strptime("1900-01-01","%Y-%m-%d"),
			"hni":[], 		
			"ikev2_encr_algo_list":[],
			"ikev2_prf_algo_list":[],
			"ikev2_hash_algo_list":[],
			"ikev2_dh_group_list":[],
			"ikev2_lifetime":[]
		}
		for config_dir in config_dict[provider]:
			# Go through all the keys in provider_latest and see if the update includes one, only update if the update is newer
			if config_dict[provider][config_dir]["update_time"] != "Unknown":
				# Only consider updates that include one of the ike parameters in an override
				update_includes_ike_params=False
				for override in config_dict[provider][config_dir]:
					if override != "update_time" and override != "update_time_str" and override != "hni":
						for key in provider_latest.keys():
							if key.startswith("ikev2"):
								if len(config_dict[provider][config_dir][override][key]) > 0:
									update_includes_ike_params=True
				if update_includes_ike_params:
					# If update time is newer, update provider_latest
					if config_dict[provider][config_dir]["update_time"] > provider_latest["update_time"]:
						provider_latest["update_time"]=config_dict[provider][config_dir]["update_time"]
						provider_latest["update_time_str"]=config_dict[provider][config_dir]["update_time_str"]
						provider_latest["hni"]=config_dict[provider][config_dir]["hni"]
						# Each config dir has device specific overrides
						for override in config_dict[provider][config_dir]:
							if override != "update_time" and override != "update_time_str" and override != "hni":
									for key in provider_latest.keys():
										if key.startswith("ikev2"):
											# If value not in list, add it
											if len(config_dict[provider][config_dir][override][key]) > 0:
												values=[x["id"] for x in config_dict[provider][config_dir][override][key]]
												to_add=[]
												for value in values:
													if value not in provider_latest[key]:
														to_add.append(value)
												provider_latest[key].extend(to_add)
						
		# Add results to global results			
		apple_results[provider]=provider_latest


	string_config_dict = iterdict(config_dict)
	with open(update_file, "w") as outfile: 
		json.dump(string_config_dict, outfile,indent=4,ensure_ascii=True)
	
	string_provider_dict=iterdict(apple_results)
	with open(output_file, "w") as outfile: 
		json.dump(string_provider_dict, outfile,indent=4,ensure_ascii=True)

	print("Finished: "+str(supported_sims_fails) + " failed to list HNI key (SupportedSIMS)")
	print("Total Providers: " +str(len(config_dict)))
	config_dict_red={x for x in config_dict.keys() if len(config_dict[x])>0}#
	print("Providers with iPhone Config Bundles: "+str(len(config_dict_red)))

def main():
	# Parse	arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--folder", required=True, type=str, help="Folder with IPCC bundles")
	parser.add_argument("-p", "--providers", required=True, type=str, help="File including a list of providers for which IPCC configurations are present")
	parser.add_argument("-o", "--outputfile", required=False, default="apple_ike_configuration_parameters.json", type=str, help="File to store Apple results in JSON Format")
	parser.add_argument("-u", "--updatefile", required=False, default="config_dirs_update_time.json", type=str, help="File to store Apple bundle update times in JSON Format")

	args=parser.parse_args()
	
	evaluate_apple_ipccs(args.folder,args.providers,args.outputfile,args.updatefile)
	
		
if __name__ == "__main__":
    main()