# IKEv2 fingerprinting

ePDGs that run the same software or setup tend to answer the IKEv2 handshake tests the same way. These scripts turn each server's answers into a fingerprint and group the servers that share one. The method is inspired by [JA3](https://github.com/salesforce/ja3), which fingerprints TLS clients and servers by hashing fields of their handshake.

## How it works

The scanner records every test case with tcpdump. Fingerprinting uses the 14 `SUPPORT_DH_*` tests. All of them offer the ePDG the same three encryption, three PRF and three integrity algorithms, but each offers only one Diffie-Hellman group. How an ePDG picks from that offer, and whether it accepts the group at all, depends on its software and configuration.

From every pcap, `fingerprint.py` takes the ePDGs' responses and keeps the parts that don't change from one handshake to the next:

- the transforms it picked for encryption, PRF, integrity and DH, in the order it sends them
- the DH group in its key exchange payload
- the attributes attached to the transforms, such as a key length
- the length of its nonce. The nonce itself is random, so only its length counts.

If an ePDG rejects the group, these fields stay empty. If it doesn't answer at all, nothing is added for that test. Both count as part of the fingerprint.

For every IP, the script then lines up its answers from all 14 tests, always in the same order, and hashes them with MD5. Two IPs get the same fingerprint only if they answered every test the same way. Across 14 tests that's rarely a coincidence, so a shared fingerprint hints at the same ePDG software or setup.

`graph.py` keeps the fingerprints shared by at least two IPs and draws them as packed circles: each fingerprint holds its IPs, grouped by operator or, if you switch, by network (ASN). Another switch hides the clusters that belong to one operator in one network, which leaves the ones shared across operators or networks.

## How to use it

You'll need Python 3 and `tshark`, which comes with Wireshark. There's nothing to install from pip.

1. Copy the `SUPPORT_DH_*` pcaps of one scan round into a folder `pcap/` in the same directory, one per DH group. The scanner keeps them in `epdg-container/data/results/`, next to its JSON results. Leave out the two downgrade tests, the script doesn't handle them.

2. Build the fingerprints:

   ```bash
   python3 fingerprint.py
   ```

   This writes the fingerprints to `csv/hashes_<time>.csv` and prints the ones that more than one server shares, with the operators behind them.

3. Draw the clusters:

   ```bash
   python3 graph.py
   ```

   This reads the newest `csv/hashes_*.csv`, adds the operator and network (ASN) of every IP in a cluster and writes `fingerprint.html`. Open it in a browser.

Operators come from the public watchdog API, ASNs from Team Cymru's whois service. If the API asks for a key, take the one the website uses (`apps/frontend/static/js/table.js`) and put it into `API_KEY` in `enrich.py`.
