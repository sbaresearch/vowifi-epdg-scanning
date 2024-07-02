# Server Side Probing

This README file contains the instructions for the server-side ePDG probing (Section 6).
The instructions for the client side evaluation (Section 5) can be found in the README file of the [client-side](../client-side) subdirectory.

# Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# Execution

> [!NOTE]
> The server-side scans use scapy to send and receive packets and thus require root privileges.

```bash
sudo su
source venv/bin/activate
./epdg_scanner.py --testcase SUPPORT_DH_768MODP
./epdg_scanner.py --testcase SUPPORT_DH_1024MODP
./epdg_scanner.py --testcase SUPPORT_DH_1536MODP
```

# Evaluation

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
