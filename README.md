# VoWiFi ePDG Scanning

This artifact contains the source code necessary to run client- and server-side evaluation scripts for our VoWiFi security analysis.
While the scripts can be used to scan for various security parameters (e.g., ciphers), our evaluation focuses on the key exchange (i.e., the supported Diffie-Hellman (DH) groups and the rekey-timings) that are used for the first (i.e., phase 1) VoWiFi tunnel that is essential to the security of the overall communication.

The full paper can be found [here](usenix-security-24/USENIX_Security_2024_Diffie_Hellman_Picture_Show_Key_Exchange_Stories_from_Commercial_VoWiFi_Deployments_PN.pdf).

## Cloning the repository

We use Git LFS (Git Large File Storage) for the dumps.zip file containing client-side operator configurations. To successfully clone the repository including the 400MB dumps.zip file, Git LFS hooks are required.

Thefore:

- Make sure to have [Git LFS installed](https://docs.github.com/en/repositories/working-with-files/managing-large-files/installing-git-large-file-storage).

- Setup the LFS hooks by running `git lfs install`.

- Clone the repository by running `git clone https://github.com/sbaresearch/vowifi-epdg-scanning.git`.

Alternatively, if you do not want to use Git LFS you can clone the repository without the prior instructions and [download the dumps.zip file via a mirror at our scientific artifact storage](https://phaidra.univie.ac.at/detail/o:2083413).

```
git clone https://github.com/sbaresearch/vowifi-epdg-scanning.git
wget -O vowifi-epdg-scanning/client-side/dumps.zip https://services.phaidra.univie.ac.at/api/object/o:2083413/download
```

## Client Side Configuration Extraction (Passive/Static Analysis)

This README file contains the instructions for the client-side VoWiFi parameter analysis (Section 5).

You can reproduce all the client-side analysis steps using the provided jupyter notebook.

#### Installation
```bash
cd client-side
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To run the notebook:

```bash
jupyter notebook client_side_evaluation.ipynb
```

The jupyter notebook provides step-by-step instructions for extracting and harmonizing the client-side configuration data for different device types. Furthermore, it allows using the harmonized results in json-format (created via the first part of the notebook) to generate graphs representing the summarized results in a more convenient and human-friendly way.

#### Extracting Client Configurations from Firmware ROMs
Since this requires downloading complete firmware ROMs (having often more than 10GB) from external sources and since unpacking the relevant configurations from the ROM is an overall time-consuming extraction approach, we took a shorter path for the artifact evaluation and just provide the configuration files that were used within our publication in the dumps.zip file.

To make it easier for other researchers to repeat the full configuration extraction at a later point in time (e.g., with more recent or different firmware ROMs) we reference the used approach [here](#extracting-configurations-for-other-devices).


## Server Side ePDG Probing (Active/Dynamic Analysis)

This README section contains the instructions for the server-side ePDG probing (Section 6).

#### Installation

```bash
cd server-side
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Execution

> [!NOTE]
> The server-side scans use scapy to send and receive packets and thus require root privileges.

```bash
sudo su
source venv/bin/activate
./epdg_scanner.py --testcase SUPPORT_DH_768MODP
./epdg_scanner.py --testcase SUPPORT_DH_1024MODP
./epdg_scanner.py --testcase SUPPORT_DH_1536MODP
```

##### Dockerized Execution

If you have troubles running the server-side scans on your system you can also run it within a docker container.

Run the ubuntu container via docker (interactive mode):

`docker run -i -t ubuntu bash`

Setup the docker system and run the scan:
```
apt update
apt install -y git python3-pip python3-venv tcpdump
git clone https://github.com/sbaresearch/vowifi-epdg-scanning.git
cd vowifi-epdg-scanning/server-side/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

./epdg_scanner.py --testcase SUPPORT_DH_768MODP
```

#### Evaluation

The probing results can be found in the results directory.
The *.txt* file contains the security associations that were negotiated with each server.
The *.pcap* file can be used for further (more precise) analysis with Wireshark.

For simple evaluation, the *.txt* file can filtered in the following manner:

```bash
grep successful results/SUPPORT_DH_768MODP_*.txt
```

or, to just display the affected operators/domains:

```bash
grep successful results/SUPPORT_DH_768MODP_*.txt | cut -d' ' -f2 | uniq
```


## Extracting Configurations for Other Devices

Depending on the device, the following approaches were used to extract the VoWiFi configuration data:

| Provider | VoWiFi configuration through | Download & Parse                              |
| -------- | ---------------------------- | --------------------------------------------- |
| Apple    | IPCC Files                   | https://github.com/mrlnc/ipcc-downloader      |
| Oppo     | MBN Files                    | https://github.com/sbaresearch/mbn-mcfg-tools |
| Xiaomi   | MBN Files                    | https://github.com/sbaresearch/mbn-mcfg-tools |
| Samsung  | XML Files                    | Handset path: /system/etc/epdg_apns_conf.xml  |

### Apple

To extract VoWiFi configurations from IPCC files the following steps are necessary.

Download IPCC files using  [ipcc-downloader](https://github.com/mrlnc/ipcc-downloader).

``` bash
./download_ipccs.py -d # May take some time
cd data
for i in $(find . | grep plist); do plistutil -i $i -o $i.xml; done
```

The IPCC URLs (`ipcc_urls.txt`) and the unpacked carrier configurations are stored in the `data` folder.

### Samsung

1. Extract AP (.tar.md5) file

2. lz4: unpack super.img.lz4 to super.img [`lz4 super.img.lz4`]

3. simg2img: unpack super.img to super.img.raw [`simg2img super.img super.img.raw`]

4. lpunpack: extract system image from super.img.raw [`python3 lpunpack.py --partition=system super.img.raw extracted`]

5. Mount extracted/system and go to /system/etc/

The `system/etc/epdg_apns_conf.xml` file contains ePDG endpoints and the corresponding cipher configurations.


### Xiaomi + Oppo (Qualcomm-generic)

1. Extract ROM, go to images folder
2. Mount NON-HLOS.bin
3. MBN MCFG files are located at /image/modem_pr/mcfg
4. Use [mbn-mcfg-tools](https://github.com/sbaresearch/mbn-mcfg-tools) to further process MBN files