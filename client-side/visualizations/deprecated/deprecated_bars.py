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

deprecated_ike_parameters= {
        'Apple': {
			 'ikev2_prf_algo_list': {'algorithms': {1: 10, 3: 0},
                                        'count': 10,
                                        'set': 219},
            
             
             'ikev2_hash_algo_list': {'algorithms': {1: 11,
                                                        3: 0,
                                                        4: 0,
                                                        6: 0,
                                                        7: 0},
                                         'count': 11,
                                         'set': 219},
              'ikev2_encr_algo_list': {'algorithms': {1: 0,
                                                        2: 0,
                                                        4: 0,
                                                        5: 0,
                                                        6: 0,
                                                        7: 0,
                                                        8: 0,
                                                        9: 0},
                                         'count': 0,
                                         'set': 219},                             
		    'ikev2_dh_group_list': {'algorithms': {1: 19,
                                                       2: 93,
                                                       5: 16,
                                                       22: 0},
                                        'count': 128,
                                        'set': 219}},

           
               
    'Xiaomi': {
             'ikev2_prf_algo_list': {'algorithms': {1: 10, 3: 0},
                                        'count': 10,
                                        'set': 120},               
     
         
            
               'ikev2_hash_algo_list': {'algorithms': {1: 25,
                                                        3: 0,
                                                        4: 0,
                                                        6: 0,
                                                        7: 0},
                                         'count': 25,
                                         'set': 130},

                 'ikev2_encr_algo_list': {'algorithms': {1: 0,
                                                        2: 20,
                                                        4: 0,
                                                        5: 0,
                                                        6: 0,
                                                        7: 0,
                                                        8: 0,
                                                        9: 0},
                                         'count': 20,
                                         'set': 126},
                'ikev2_dh_group_list': {'algorithms': {1: 0,
                                                       2: 102,
                                                       5: 76,
                                                       22: 0},
                                        'count': 115,
                                        'set': 150}},
    'Oppo': {
		'ikev2_prf_algo_list': {'algorithms': {1: 7, 3: 0},
                                        'count': 7,
                                        'set': 203},
        
        'ikev2_hash_algo_list': {'algorithms': {1: 42,
                                                        3: 0,
                                                        4: 0,
                                                        6: 0,
                                                        7: 0},
                                         'count': 42,
                                         'set': 212},

        'ikev2_encr_algo_list': {'algorithms': {1: 0,
                                                        2: 22,
                                                        4: 0,
                                                        5: 0,
                                                        6: 0,
                                                        7: 0,
                                                        8: 0,
                                                        9: 0},
                                         'count': 22,
                                         'set': 211},
        'ikev2_dh_group_list': {'algorithms': {1: 12,
                                                       2: 175,
                                                       5: 85,
                                                       22: 0},
                                        'count': 184,
                                        'set': 221}},
   
   
             

    'Samsung': {
		        'ikev2_prf_algo_list': {'algorithms': {1: 0, 3: 0},
                                        'count': 0,
                                        'set': 0},
     

               'ikev2_hash_algo_list': {'algorithms': {1: 9,
                                                        3: 0,
                                                        4: 0,
                                                        6: 0,
                                                        7: 0},
                                         'count': 9,
                                         'set': 144},
        
        'ikev2_encr_algo_list': {'algorithms': {1: 0,
                                                        2: 0,
                                                        4: 0,
                                                        5: 0,
                                                        6: 0,
                                                        7: 0,
                                                        8: 0,
                                                        9: 0},
                                         'count': 0,
                                         'set': 141},

        'ikev2_dh_group_list': {'algorithms': {1: 13,
                                                       2: 34,
                                                       5: 22,
                                                       22: 0},
                                        'count': 52,
                                        'set': 156},

    }
        
}

# Transform dict for plotting
provider_data={x:[] for x in deprecated_ike_parameters.keys()}
for provider, parameters in deprecated_ike_parameters.items():
    for parameter in parameters:
        if parameters[parameter]["set"] > 0:
            provider_data[provider].append(parameters[parameter]["count"]/parameters[parameter]["set"]*100)
        else:
            provider_data[provider].append(0)
algorithms ={
     "ikev2_prf_algo_list": "PRF",    
    "ikev2_hash_algo_list": "Integrity",
    "ikev2_encr_algo_list": "Encryption",  
    "ikev2_dh_group_list": "DH < 2048",
}

# Create a new plot
fig, ax = plt.subplots(figsize=(4.5, 2.5))
barWidth = 0.2  # Width of bars
positions = list(range(len(algorithms)))  # Algorithm positions on Y axis

# Generating bars for each provider
# Adding legend for providers

for i, provider in enumerate(["Samsung", "Oppo", "Xiaomi", "Apple"]):
    
    # Offset positions for Oppo to the right of Xiaomi
    pos = [p + (i * barWidth) for p in positions]
    bars=ax.barh(pos, provider_data[provider], height=barWidth, label=provider,edgecolor='black',linewidth=0.7, color=dark2_colors[i],alpha=0.95)
    for x,bar in enumerate(bars):
        #if provider_data[provider][x] > 0:
            percentage = f"{provider_data[provider][x]:.0f}%"
            ax.text(bar.get_width()+1, bar.get_y() + bar.get_height() / 2, percentage, va='center',fontsize=6.5)

handles, labels = ax.get_legend_handles_labels()
ax.legend(handles[::-1], labels[::-1], loc='lower right')

# Adding labels and title
plt.xlabel('Percentage Deprecated (%)')
plt.ylabel('IKEv2 SA Parameters')
#plt.title('Deprecated Sum for IKE Algorithms by Provider', fontweight='bold')

# Set x ticks min max
plt.xticks(range(0, 101, 10))
# Setting y-ticks to be in the middle of the grouped bars
plt.yticks([r + 2* barWidth - barWidth/2 for r in range(len(algorithms))], algorithms.values())


plt.grid(True,linestyle='dotted')
# Display the plot
plt.tight_layout()

plt.savefig('ike_deprecated_CR.pdf', dpi=300,bbox_inches='tight')
plt.savefig('ike_deprecated_CR.png', dpi=300,bbox_inches='tight')

exit(1)

# Create a DataFrame from the list
provider_df = pd.DataFrame(provider_data_list)

# Summing up MODP groups >= 3072 into one category
provider_df['grouped_dh_group'] = provider_df['dh_group'].apply(lambda x: '3072-bit MODP (>=)' if x in ['3072-bit MODP (15)', '4096-bit MODP (16)', '6144-bit MODP (17)', '8192-bit MODP (18)', '256-bit ECP (19)' ] else x)

# Recalculate counts and percentages for the grouped category
grouped_provider_df = provider_df.groupby(['provider', 'grouped_dh_group'], as_index=False).agg({'count': 'sum'})
print(grouped_provider_df)
# Total count is the sum of all counts for each provider

grouped_provider_df['total_count'] = grouped_provider_df.groupby('provider')['count'].transform('sum')
grouped_provider_df['percentage'] = grouped_provider_df['count'] / grouped_provider_df['total_count'] * 100

# Sorting and organizing data for plotting
#grouped_provider_df.sort_values(by=['grouped_dh_group', 'provider'], ascending=[True, False], inplace=True)
#grouped_provider_df.sort_values(by=['grouped_dh_group'],key=lambda x: np.argsort(index_natsorted(grouped_provider_df["grouped_dh_group"])),ascending=False)
print(grouped_provider_df)

# Plotting
plt.figure(figsize=(7, 5))
bar_width = 0.2  # Adjust bar width to fit more bars
# Sort groups by name
dh_groups = ['768-bit MODP (1)','1024-bit MODP (2)', '1536-bit MODP (5)', '2048-bit MODP (14)', '3072-bit MODP (>=)'][::-1] #grouped_provider_df['grouped_dh_group'].unique()
print(dh_groups)
indices = np.arange(len(dh_groups))  # Base indices for groups

# Plot bars for each provider in each DH group
for i, group in enumerate(dh_groups):
    group_data = grouped_provider_df[grouped_provider_df['grouped_dh_group'] == group]
    for j, row in group_data.iterrows():
        provider_idx = list(ikev2_dh_group_data.keys()).index(row['provider'])
        plt.barh(indices[i] + (provider_idx - len(ikev2_dh_group_data) / 2) * bar_width, row['percentage'], bar_width, alpha=0.8, color=dark2_colors[provider_idx], linewidth=0.7, edgecolor="black", label=row['provider'] if i == 0 else None)
        if row['percentage'] > 5:
            plt.text(row['percentage'], indices[i] + (provider_idx - len(ikev2_dh_group_data) / 2) * bar_width, f"{row['percentage']:.0f}%", va='center', ha='right', rotation=0, color='black', fontsize=8)
plt.xlabel('Percentage (%)')
plt.yticks(indices, dh_groups)

# Add a legend outside the plot
plt.legend(loc='upper right', title="Provider")
plt.grid(True,linestyle='dotted')
plt.tight_layout()


# Save the plot
plt.savefig('ike_dh_groups_CR.pdf', dpi=300,bbox_inches='tight')
