# VoWiFi ePDG Scanning

This artifact contains the source code necessary to run client- and server-side evaluation scripts for our VoWiFi security analysis.
While the scripts can be used to scan for various security parameters (e.g., ciphers), our evaluation focuses on the key exchange (i.e., the supported Diffie-Hellman (DH) groups and the rekey-timings) that are used for the first (i.e., phase 1) VoWiFi tunnel that is essential to the security of the overall communication.

## Cloning the repository

We use Git LFS (Git Large File Storage) for the dumps.zip file containing client-side operator configurations. To successfully clone the repository including the 400MB dumps.zip file, Git LFS hooks are required.

Thefore:

- Make sure to have [Git LFS installed](https://docs.github.com/en/repositories/working-with-files/managing-large-files/installing-git-large-file-storage).

- Setup the LFS hooks by running `git lfs install`.

- Clone the repository by running `git clone https://github.com/sbaresearch/vowifi-epdg-scanning.git`.

Alternatively, if you do not want to use Git LFS you can clone the repository without the prior instructions and [download the dumps.zip file via the web interace](https://github.com/sbaresearch/vowifi-epdg-scanning/raw/main/client-side/dumps.zip?download=).

## Client Side Configuration Extraction (Passive/Static Analysis)

This README file contains the instructions for the client-side VoWiFi parameter analysis (Section 5).

You can reproduce all the client-side analysis steps using the provided jupyter notebook.

Requirement: Jupyter Notebook (https://jupyter.org/install) e.g.

```bash
pip install jupyterlab
pip install notebook
```

To run the notebook:

```bash
cd client-side
pip install -r requirements.txt
jupyter notebook client_side_evaluation.ipynb
```

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
