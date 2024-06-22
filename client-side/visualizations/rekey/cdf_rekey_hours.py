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

# Provided data as a multiline string (assuming each line represents count,ikev2_sa_rekey_timer in seconds)
data_soft = """
122,64800
13,3000
1,86600
51,86400
7,43200
1,1500
3,86200
7,3600
5,28800
1,86300
1,129500
1,79200
2,129400
1,63000
1,71000
2,80000
2,3900
1,900
3,87900
2,28805
1,1800
1,82800
1,14700
1,1200
"""
data_hard="""
121,64900
14,3600
1,86700
6,87000
6,43300
1,2100
17,86400
1,4200
36,86500
2,28900
1,3100
1,129600
1,79300
2,129500
1,64800
1,71100
1,80100
2,4000
1,1000
1,90
2,88000
1,87900
2,28905
4,3700
1,43200
1,1900
1,82900
1,14800
1,1500
"""

apple_ike_lifetime = {
        "80000": 160,
        "86400": 53,
        "87000": 2,
        "8640": 1,
        "864000": 1,
        "43200": 1,
        "3600": 1
} # "": 526,

samsung_rekey = {
        "86400": 1,
        "82200": 1,
        "64800": 18,
        "3600": 10,
        "43200": 16,
        "900": 6,
        "28800": 17,
        "14800": 1,
        "82800": 2,
        "71000": 2,
        "14400": 1,
        "1800": 1,
        "87900": 9,
        "7200": 2,
        "80000": 2,
        "87000": 2,
        "31536000": 3,
        "3000": 1,
        "180": 1,
        "6400": 1,
        "3900": 1
}

data_oppo="""
176,64800
66,86400
6,3000
4,1500
4,3600
4,82800
7,86220
3,86200
2,3001
1,3420
11,43200
15,86300
1,129500
1,79200
1,129400
1,71000
1,80000
1,64700
6,87900
2,28700
1,82600
1,3500
2,43020
2,43100
3,720
4,28800
1,86280
2,1200
2,900
1,7200
1,32400
1,82700
1,21500
1,14300
1,77760
1,3900
1,1800
1,14700
"""

# Loading data into a DataFrame
data_hard_lines = [line.split(',') for line in data_hard.strip().split('\n')]
data_soft_lines = [line.split(',') for line in data_soft.strip().split('\n')]

data_oppo_lines = [line.split(',') for line in data_oppo.strip().split('\n')]
data_apple_lines=[[x,y] for x,y in apple_ike_lifetime.items()]
data_samsung_lines=[[x,y] for x,y in samsung_rekey.items()]

df_hard = pd.DataFrame(data_hard_lines, columns=['count', 'seconds']).astype(int)
df_soft = pd.DataFrame(data_soft_lines, columns=['count', 'seconds']).astype(int)

data_oppo = pd.DataFrame(data_oppo_lines, columns=['count', 'seconds']).astype(int)
df_apple = pd.DataFrame(data_apple_lines, columns=['seconds', 'count']).astype(int)
df_samsung = pd.DataFrame(data_samsung_lines, columns=['seconds', 'count']).astype(int)

# Sorting by seconds for cumulative calculation
df_hard_sorted = df_hard.sort_values('seconds')
df_soft_sorted = df_soft.sort_values('seconds')

df_oppo_sorted=data_oppo.sort_values('seconds')
df_apple_sorted = df_apple.sort_values('seconds')
df_samsung_sorted = df_samsung.sort_values('seconds')

# Calculating cumulative count for CDF
df_hard_sorted['cumulative_count'] = df_hard_sorted['count'].cumsum()
df_soft_sorted['cumulative_count'] = df_soft_sorted['count'].cumsum()

df_oppo_sorted['cumulative_count'] = df_oppo_sorted['count'].cumsum()
df_apple_sorted['cumulative_count'] = df_apple_sorted['count'].cumsum()
df_samsung_sorted['cumulative_count'] = df_samsung_sorted['count'].cumsum()

# Normalizing cumulative count to get CDF
df_hard_sorted['cdf'] = df_hard_sorted['cumulative_count'] / df_hard_sorted['cumulative_count'].iloc[-1]
df_soft_sorted['cdf'] = df_soft_sorted['cumulative_count'] / df_soft_sorted['cumulative_count'].iloc[-1]

df_oppo_sorted['cdf'] = df_oppo_sorted['cumulative_count'] / df_oppo_sorted['cumulative_count'].iloc[-1]
df_apple_sorted['cdf'] = df_apple_sorted['cumulative_count'] / df_apple_sorted['cumulative_count'].iloc[-1]
df_samsung_sorted['cdf'] = df_samsung_sorted['cumulative_count'] / df_samsung_sorted['cumulative_count'].iloc[-1]

# Converting "seconds" to "hours" for plotting
df_hard_sorted['hours'] = df_hard_sorted['seconds'] / 3600
df_soft_sorted['hours'] = df_soft_sorted['seconds'] / 3600

df_oppo_sorted['hours'] = df_oppo_sorted['seconds'] / 3600
df_apple_sorted['hours'] = df_apple_sorted['seconds'] / 3600
df_samsung_sorted['hours'] = df_samsung_sorted['seconds'] / 3600


# Plotting the CDF with hours on the x-axis
plt.figure(figsize=(4.5, 2.5))
plt.step(df_apple_sorted['hours'], df_apple_sorted['cdf'], where='post', label='Apple',alpha=0.95,color=dark2_colors[3],linestyle="--")
plt.step(df_soft_sorted['hours'], df_soft_sorted['cdf'], where='post', label='Xiaomi',alpha=0.95,color=dark2_colors[2])
plt.step(df_oppo_sorted['hours'], df_oppo_sorted['cdf'], where='post', label='Oppo',alpha=0.95,color=dark2_colors[1],linestyle="dashdot")
plt.step(df_samsung_sorted['hours'], df_samsung_sorted['cdf'], where='post', label='Samsung',alpha=0.95,color=dark2_colors[0],linestyle="dotted")
plt.xlabel('Hours')
plt.ylabel('CDF')

# Cap x axis
plt.xlim(0, 40)
plt.legend()

# Safe figure to file
plt.savefig("cdf_rekey_hours_CR.pdf", dpi=300, bbox_inches='tight')
