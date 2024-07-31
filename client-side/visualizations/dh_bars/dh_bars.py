import math
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from natsort import index_natsorted
from matplotlib import cm
import matplotlib
# Dark2
dark2 = cm.get_cmap('Dark2_r', 8)  # '8' to get the number of distinct colors in this colormap
# Extracting the colors as a list
dark2_colors = dark2.colors

matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42




def visualize_dh_groups(ikev2_dh_group_data,visfile):

    # Group Name Mapping
    dh_group_name_mapping = {   
        '1': '(1) 768-bit',
        '2': '(2) 1024-bit',
        '5': '(5) 1536-bit',
        '14': '(14) 2048-bit',
        #'15': '(15) 3072-bit',
        #'16': '(16) 4096-bit',
        #'17': '(17) 6144-bit',
        #'18': '(18) 8192-bit',
        #'19': '(19) 256-bit',
        '>15': '(>=) 3072-bit'
    }
    
    # Convert this data into a format suitable for plotting
    provider_data_list = []
    for provider, groups in ikev2_dh_group_data.items():
        groups = groups['dh_groups']
        for group, count in groups.items():
            if group in dh_group_name_mapping:      
                provider_data_list.append({'provider': provider, 'dh_group': dh_group_name_mapping[group], 'count': count})
    
    
    # Create a DataFrame from the list
    provider_df = pd.DataFrame(provider_data_list)
    
    # Summing up MODP groups >= 3072 into one category
    provider_df['grouped_dh_group'] = provider_df['dh_group'].apply(lambda x: '(>=) 3072-bit' if x in ['(15) 3072-bit', '(16) 4096-bit', '(17) 6144-bit', '(18) 8192-bit', '(19) 256-bit' ] else x)
    
    # Recalculate counts and percentages for the grouped category
    grouped_provider_df = provider_df.groupby(['provider', 'grouped_dh_group'], as_index=False).agg({'count': 'sum'})
    print(grouped_provider_df)
    # Total count is the sum of all counts for each provider
    
    #grouped_provider_df['total_count'] = grouped_provider_df.groupby('provider')['count'].transform('sum')
    grouped_provider_df['total_count'] = [ikev2_dh_group_data[provider]["set"] for provider in grouped_provider_df['provider']]
    grouped_provider_df['percentage'] = grouped_provider_df['count'] / grouped_provider_df['total_count'] * 100
    
    # Sorting and organizing data for plotting
    #grouped_provider_df.sort_values(by=['grouped_dh_group', 'provider'], ascending=[True, False], inplace=True)
    #grouped_provider_df.sort_values(by=['grouped_dh_group'],key=lambda x: np.argsort(index_natsorted(grouped_provider_df["grouped_dh_group"])),ascending=False)
    print(grouped_provider_df)
    
    # Plotting
    plt.figure(figsize=(4, 3))
    bar_width = 0.2  # Adjust bar width to fit more bars
    # Sort groups by name
    dh_groups = ['(1) 768-bit','(2) 1024-bit', '(5) 1536-bit', '(14) 2048-bit', '(>=) 3072-bit'][::-1] #grouped_provider_df['grouped_dh_group'].unique()
    print(dh_groups)
    indices = np.arange(len(dh_groups))  # Base indices for groups
    provider_list=["Apple","Xiaomi","Oppo","Samsung"][::-1]
    # Plot bars for each providre in each DH group
    for i, group in enumerate(dh_groups):
        group_data = grouped_provider_df[grouped_provider_df['grouped_dh_group'] == group]
        provider_idx=0
        color_idx=len(provider_list)-1
        for provider in provider_list:
    
            for j, row in group_data.iterrows():
                if row["provider"] == provider:
                    #provider_idx = list(ikev2_dh_group_data.keys()).index(row['provider'])
                    plt.barh(indices[i] + (provider_idx - len(ikev2_dh_group_data) / 2) * bar_width, row['percentage'], bar_width, alpha=0.8, color=dark2_colors[provider_idx], linewidth=0.7, edgecolor="black", label=row['provider'] if i == color_idx else None)
                    if row['percentage'] > 12:
                            plt.text(row["percentage"], indices[i] + (provider_idx - len(ikev2_dh_group_data) / 1.95) * bar_width, str(row["count"]) + f" ({row['percentage']:.0f}%)", va='center', ha='right', rotation=0, color='black', fontsize=6.2)
                    else:
                        plt.text(row['percentage']+13, indices[i] + (provider_idx - len(ikev2_dh_group_data) / 1.95) * bar_width,str(row["count"]) + f" ({row['percentage']:.0f}%)", va='center', ha='right', rotation=0, color='black', fontsize=6.2)
            provider_idx+=1
            color_idx-=1
    plt.xlabel('Percentage (%)',fontsize=8.5)
    plt.ylabel("DH Groups",fontsize=8.5)
    plt.yticks(indices, dh_groups,fontsize=8.5)
    
    plt.xlim(xmin=0,xmax=81)
    plt.xticks(range(0, 82, 10))
    matplotlib.rcParams.update({'font.size': 8.5})
    
    
    # Add a legend outside the plot
    plt.legend(loc='upper right', title="Provider",ncol=2,fontsize=7)
    plt.grid(True,linestyle='dotted')
    plt.tight_layout()
    
    
    # Save the plot
    plt.savefig(visfile, dpi=300,bbox_inches='tight')



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--visfile", required=True, type=str, help="File to store visualization (.png,.pdf)")
    args=parser.parse_args()
    
    ikev2_dh_group_data = {
        'Apple': {"dh_groups":{'1': 19, '2': 94, '5': 16, '14': 88,'15': 4, '16': 1, '17': 0, '18': 0, '19': 0 ,'>15': 5},"set":219},
        'Xiaomi': {"dh_groups":{'1': 0, '2': 102, '5': 76, '14': 111,'15': 5, '16': 7, '17': 3, '18': 3, '19': 0 ,'>15':8},"set":150},
        'Oppo':{"dh_groups":{'1': 12, '2': 175, '5': 85, '14': 142,'15': 12, '16': 8, '17': 6, '18': 6, '19': 0 , '>15': 12},"set":221},
        'Samsung': {"dh_groups":{'1': 13, '2': 34, '5': 22, '14': 122,'15': 16, '16': 12, '17': 8, '18': 8, '19': 1, '>15': 17 },"set":156}
    }

    visualize_dh_groups(ikev2_dh_group_data,args.visfile)

if __name__ == "__main__":
    main()
