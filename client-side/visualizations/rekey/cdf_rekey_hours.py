import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
from matplotlib import cm

from matplotlib.colors import ListedColormap

#Getting the 'Dark2' colormap
dark2 = cm.get_cmap('Dark2_r', 8)  
# Extracting the colors as a list
dark2_colors = dark2.colors

matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42

def rekey_cdf(rekey_dict,visfile):
	# Convert the rekey_dict data into DataFrame
	def convert_to_df(data, columns):
		data = {k: v for k, v in data.items() if k}
		df = pd.DataFrame(data.items(), columns=columns).astype(int)
		df_sorted = df.sort_values('seconds')
		df_sorted['cumulative_count'] = df_sorted['count'].cumsum()
		df_sorted['cdf'] = df_sorted['cumulative_count'] / df_sorted['cumulative_count'].iloc[-1]
		df_sorted['hours'] = df_sorted['seconds'] / 3600
		return df_sorted

	df_dict = {}
	for key, data in rekey_dict.items():
		df_dict[key] = convert_to_df(data, ['seconds', 'count'])
		
		
	# Plotting the CDF with hours on the x-axis
	plt.figure(figsize=(4.5, 2.5))
	styles = {
		'Apple': {"color": dark2_colors[3], "linestyle": "--"},
		'Xiaomi': {"color": dark2_colors[2], "linestyle": "-"},
		'Oppo': {"color": dark2_colors[1], "linestyle": "dashdot"},
		'Samsung': {"color": dark2_colors[0], "linestyle": "dotted"}
	}

	for key, df in df_dict.items():
		print(key)
		print(df)
		plt.step(df['hours'], df['cdf'], where='post', label=key, alpha=0.95, **styles[key])

	plt.xlabel('Hours')
	plt.ylabel('CDF')
	plt.xlim(0, 40)
	plt.legend()
		
	# Safe figure to file
	plt.savefig(visfile, dpi=300, bbox_inches='tight')

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--visfile", required=True, type=str, help="File to store visualization (.png,.pdf)")
	args = parser.parse_args()

	rekey_dict = {
		"Apple": {
			80000: 160,
			86400: 53,
			87000: 2,
			8640: 1,
			864000: 1,
			43200: 1,
			3600: 1
		},
		"Xiaomi": {
			64800: 122,
			3000: 13,
			86600: 1,
			86400: 51,
			43200: 7,
			1500: 1,
			86200: 3,
			3600: 7,
			28800: 5,
			86300: 1,
			129500: 1,
			79200: 1,
			129400: 2,
			63000: 1,
			71000: 1,
			80000: 2,
			3900: 2
		},
		"Oppo": {
			64800: 176,
			86400: 66,
			3000: 6,
			1500: 4,
			3600: 4,
			82800: 4,
			86220: 7,
			86200: 3,
			3001: 2,
			3420: 1,
			43200: 11,
			86300: 15,
			129500: 1,
			79200: 1,
			129400: 1,
			71000: 1,
			80000: 1,
			64700: 1,
			87900: 6,
			28700: 2,
			82600: 1,
			3500: 1,
			43020: 2,
			43100: 2,
			720: 3,
			28800: 4,
			86280: 1,
			1200: 2,
			900: 2,
			7200: 1,
			32400: 1,
			82700: 1,
			21500: 1,
			14300: 1,
			77760: 1,
			3900: 1,
			1800: 1,
			14700: 1
		},
		"Samsung": {
			86400: 1,
			82200: 1,
			64800: 18,
			3600: 10,
			43200: 16,
			900: 6,
			28800: 17,
			14800: 1,
			82800: 2,
			71000: 2,
			14400: 1,
			1800: 1,
			87900: 9,
			7200: 2,
			80000: 2,
			87000: 2,
			31536000: 3,
			3000: 1,
			180: 1,
			6400: 1,
			3900: 1
		}
	}

	rekey_cdf(rekey_dict,args.visfile)

if __name__ == "__main__":
	main()