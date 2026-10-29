# IKE_AUTH probes (opt-in)

Standalone IKE_AUTH-level probes on top of the IKE_SA_INIT scanner. Opt-in:
generated into `TEST_CONFIG`, never added to `scanner/main.py` TESTCASES. Use a
nulled EAP-AKA pseudonym (no SIM) — the ePDG checks the SA proposal before the
subscriber, so the reply still reveals accepted crypto / the cert.

Testcases:
- `PROBE_EPDG_CERT` — fetch the cert chain via CERTREQ (RFC 7383 reassembly).
- `PROBE_IPSEC_ENCR_*` / `PROBE_IPSEC_INTEG_*` — child-SA (ESP) encr/integ.
- `PROBE_IPSEC_ENCR_{NULL,AES_GCM_16_128}_WRONGREALM` — identity-axis control
  (IDi from the 001/01 test PLMN); trust an "accept" only when the ePDG also
  rejects some cipher with NO_PROPOSAL_CHOSEN (proves pre-auth crypto eval).

Classify: `NO_PROPOSAL_CHOSEN`(14) = not supported, else supported.

Run (root): `EPDG_DOMAINS_FILE=... python -m scanner.ikev2.epdg_scanner --testcase PROBE_EPDG_CERT`
Results: one JSON line per target in `data/results/<TESTCASE>.json`.

Env: `EPDG_CA_CERTS_DIR` (CA certs -> CERTREQ authority; empty = any CA),
`EPDG_DOMAINS_FILE` (target list).
