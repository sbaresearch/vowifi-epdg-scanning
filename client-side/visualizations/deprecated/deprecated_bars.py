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

def visualize_deprecated_bars(deprecated_ike_parameters,visfile):
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
    
    plt.savefig(visfile, dpi=300,bbox_inches='tight')
    plt.savefig('ike_deprecated_CR.png', dpi=300,bbox_inches='tight')







def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--visfile", required=True, type=str, help="File to store visualization (.png,.pdf)")
    args=parser.parse_args()
    
    
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

    visualize_deprecated_bars(deprecated_ike_parameters,args.visfile)

if __name__ == "__main__":
    main()

