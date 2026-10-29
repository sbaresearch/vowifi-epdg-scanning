"""Offline tests for the Phase A cert-probe building blocks.

These exercise everything except the live network receive: CERTREQ building,
fragmentation-support negotiation, the UDP/4500 parse path, RFC 7383 fragment
reassembly (round-trip through the real crypto), CA-hash construction, cert
parsing, and F10 classification.

    PYTHONPATH=server-side/apps/core python3 -m unittest \
        scanner.ikev2.tests.test_cert_probe
"""

import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

import scanner.ikev2.ikev2_crypto as ikev2_crypto
from scanner.ikev2.ikev2_class import (
    EpdgIKEv2,
    certreq_authority_from_cas,
    parse_certificate,
)

from scapy.contrib.ikev2 import (
    IKEv2,
    IKEv2CertificateEncodings,
    IKEv2PayloadTypes,
    IKEv2_CERT,
    IKEv2_CERTREQ,
    IKEv2_EAP,
    IKEv2_Encrypted_Fragment,
    IKEv2_IDr,
    IKEv2_Notify,
)
from scapy.layers.inet import IP, UDP
from scapy.contrib.ikev2 import NON_ESP

NAME_TO_PAYLOAD_NUM = {v: num for num, v in IKEv2PayloadTypes.items()}


def make_self_signed_der(common_name="test-epdg.example"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


class FragmentationNegotiationTest(unittest.TestCase):
    def test_sa_init_without_flag_has_no_frag_notify(self):
        ike = EpdgIKEv2("192.0.2.1", 500, mcc="232", mnc="05")
        sa = [[EpdgIKEv2.ENC_AES_128, EpdgIKEv2.PRF_SHA2_256,
               EpdgIKEv2.INT_SHA2_256_128, EpdgIKEv2.DH_2048MODP]]
        pkt = ike.ike_sa_init_create_packet(sa, EpdgIKEv2.KE_DH_2048MODP)
        notify_types = [n.type for n in self._notifies(pkt)]
        self.assertNotIn(16430, notify_types)  # IKEV2_FRAGMENTATION_SUPPORTED

    def test_sa_init_with_flag_advertises_fragmentation(self):
        ike = EpdgIKEv2("192.0.2.1", 500, mcc="232", mnc="05")
        sa = [[EpdgIKEv2.ENC_AES_128, EpdgIKEv2.PRF_SHA2_256,
               EpdgIKEv2.INT_SHA2_256_128, EpdgIKEv2.DH_2048MODP]]
        pkt = ike.ike_sa_init_create_packet(
            sa, EpdgIKEv2.KE_DH_2048MODP, fragmentation_supported=True
        )
        # reparse from the wire to be sure it serialises/dissects cleanly
        reparsed = IP(bytes(pkt))
        notify_types = [n.type for n in self._notifies(reparsed)]
        self.assertIn(16430, notify_types)

    @staticmethod
    def _notifies(pkt):
        out, cur = [], pkt[IKEv2]
        while IKEv2_Notify in cur:
            n = cur[IKEv2_Notify]
            out.append(n)
            cur = n.payload
        return out


class CertReqBuildTest(unittest.TestCase):
    def _auth_packet(self, cert_authority):
        ike = EpdgIKEv2("192.0.2.1", 500, mcc="232", mnc="05")
        ike.encr_id = ikev2_crypto.EncrId.ENCR_NULL  # skip encryption for inspection
        return ike.create_packet_ike_auth(
            EpdgIKEv2.ENC_AES_128, EpdgIKEv2.INT_SHA1_96, cert_authority=cert_authority
        )

    def test_no_certreq_by_default(self):
        ike = EpdgIKEv2("192.0.2.1", 500, mcc="232", mnc="05")
        ike.encr_id = ikev2_crypto.EncrId.ENCR_NULL
        pkt = ike.create_packet_ike_auth(EpdgIKEv2.ENC_AES_128, EpdgIKEv2.INT_SHA1_96)
        self.assertNotIn(IKEv2_CERTREQ, pkt)

    def test_certreq_present_with_empty_authority(self):
        pkt = self._auth_packet(b"")
        self.assertIn(IKEv2_CERTREQ, pkt)
        self.assertEqual(pkt[IKEv2_CERTREQ].cert_encoding, 4)
        self.assertEqual(bytes(pkt[IKEv2_CERTREQ].cert_authority), b"")

    def test_certreq_carries_authority_and_reparses(self):
        authority = b"\x11" * 20
        pkt = IP(bytes(self._auth_packet(authority)))  # round-trip the wire
        self.assertEqual(bytes(pkt[IKEv2_CERTREQ].cert_authority), authority)

    def test_broad_esp_proposal_offers_every_transform(self):
        # A list of ciphers/integrities must all land in one ESP proposal, with
        # the chain correctly terminated (last transform next_payload == 0).
        from scapy.contrib.ikev2 import IKEv2_Proposal, IKEv2_Transform

        ike = EpdgIKEv2("192.0.2.1", 500, mcc="505", mnc="01")
        ike.encr_id = ikev2_crypto.EncrId.ENCR_NULL
        encr = [EpdgIKEv2.ENC_AES_256, EpdgIKEv2.ENC_AES_128, EpdgIKEv2.ENC_3DES]
        integ = [EpdgIKEv2.INT_SHA2_256_128, EpdgIKEv2.INT_SHA1_96]
        pkt = IP(bytes(ike.create_packet_ike_auth(encr, integ, cert_authority=b"")))

        prop = pkt[IKEv2_Proposal]
        self.assertEqual(prop.proto, 3)  # ESP
        self.assertEqual(prop.trans_nb, len(encr) + len(integ) + 1)  # +1 ESN

        transforms, cur = [], prop.trans
        while isinstance(cur, IKEv2_Transform):
            transforms.append(cur)
            cur = cur.payload
        by_type = {}
        for t in transforms:
            by_type.setdefault(t.transform_type, []).append(t)
        self.assertEqual(len(by_type[1]), len(encr))  # Encryption
        self.assertEqual(len(by_type[3]), len(integ))  # Integrity
        self.assertEqual(len(by_type[5]), 1)  # ESN
        self.assertEqual(transforms[-1].transform_type, 5)
        self.assertEqual(transforms[-1].next_payload, 0)  # chain terminated


class CertReqAuthorityTest(unittest.TestCase):
    def test_hash_is_20_bytes_per_ca(self):
        with tempfile.TemporaryDirectory() as d:
            p1 = Path(d) / "ca1.der"
            p2 = Path(d) / "ca2.der"
            p1.write_bytes(make_self_signed_der("ca-one"))
            p2.write_bytes(make_self_signed_der("ca-two"))
            self.assertEqual(len(certreq_authority_from_cas([p1])), 20)
            self.assertEqual(len(certreq_authority_from_cas([p1, p2])), 40)

    def test_empty_list_is_empty_authority(self):
        self.assertEqual(certreq_authority_from_cas([]), b"")


class ParseCertificateTest(unittest.TestCase):
    def test_parses_x509_fields(self):
        der = make_self_signed_der("my-epdg.example")
        info = parse_certificate(4, der)
        self.assertEqual(info["cert_encoding"], 4)
        self.assertIn("my-epdg.example", info["subject"])
        self.assertEqual(info["not_valid_before"], "2026-01-01T00:00:00+00:00")
        self.assertIn("sha256_fingerprint", info)
        self.assertNotIn("parse_error", info)
        # PEM captured and round-trips
        self.assertTrue(info["pem"].startswith("-----BEGIN CERTIFICATE-----"))
        reloaded = x509.load_pem_x509_certificate(info["pem"].encode())
        self.assertEqual(
            reloaded.fingerprint(hashes.SHA256()).hex(), info["sha256_fingerprint"]
        )

    def test_non_x509_encoding_records_raw(self):
        info = parse_certificate(1, b"\xde\xad\xbe\xef")  # PKCS#7 bundle, not parsed
        self.assertEqual(info["cert_encoding"], 1)
        self.assertEqual(info["raw_hex"], "deadbeef")

    def test_malformed_x509_does_not_raise(self):
        info = parse_certificate(4, b"not a cert")
        self.assertIn("parse_error", info)


class EncryptIcvLengthTest(unittest.TestCase):
    """The IKE_AUTH ICV must match the negotiated integrity algorithm's length.

    A live Magenta (232-03) ePDG negotiated HMAC-SHA2-256-128 (16-byte ICV); the
    old hardcoded 12-byte ICV made every IKE_AUTH fail integrity and get dropped.
    """

    def _build_and_check(self, integ_transform, integ_id, expected_icv):
        ike = EpdgIKEv2("192.0.2.1", 500, mcc="232", mnc="03",
                        identity_type="aka_pseudonym", identity_username="fakeuser")
        ike.encr_id = ikev2_crypto.EncrId.ENCR_AES_CBC
        ike.encr_key_len = 256
        ike.integ_id = integ_id
        ike.sk_ei = b"\x02" * 32  # AES-256 key
        ike.sk_er = ike.sk_ei     # self round-trip
        ike.sk_ai = b"\x03" * 32  # integrity key

        pkt = ike.create_packet_ike_auth(
            EpdgIKEv2.ENC_AES_128, integ_transform, cert_authority=b""
        )
        from scapy.contrib.ikev2 import IKEv2, IKEv2_Encrypted

        raw = bytes(pkt[IKEv2])
        # the trailing ICV must equal a checksum recomputed over everything before
        # it -- exactly the check the responder performs.
        recomputed = ikev2_crypto.calculate_checksum(raw[:-expected_icv], ike.sk_ai, integ_id)
        self.assertEqual(len(recomputed), expected_icv)
        self.assertEqual(raw[-expected_icv:], recomputed)

        # and it must decrypt back to the CERTREQ we put in
        decrypted = EpdgIKEv2.decrypt_ikev2_packet(
            pkt[IKEv2], ike.encr_id, ike.sk_er, integ_id
        )
        self.assertIn(IKEv2_CERTREQ, decrypted)

    def test_sha1_96_icv_12_bytes(self):
        self._build_and_check(
            EpdgIKEv2.INT_SHA1_96, ikev2_crypto.IntegId.AUTH_HMAC_SHA1_96, 12
        )

    def test_sha2_256_128_icv_16_bytes(self):
        self._build_and_check(
            EpdgIKEv2.INT_SHA2_256_128,
            ikev2_crypto.IntegId.AUTH_HMAC_SHA2_256_128,
            16,
        )


class ReassembleAndClassifyTest(unittest.TestCase):
    def setUp(self):
        self.encr_id = ikev2_crypto.EncrId.ENCR_AES_CBC
        self.integ_id = ikev2_crypto.IntegId.AUTH_HMAC_SHA1_96
        self.sk_er = b"\x01" * 16  # AES-128 key
        self.der = make_self_signed_der("frag-epdg.example")
        # inner payload chain the ePDG would return: IDr, CERT, EAP
        self.inner = (
            IKEv2_IDr(next_payload="CERT", IDtype="FQDN", ID="ims")
            / IKEv2_CERT(next_payload="EAP", cert_encoding=4, cert_data=self.der)
            / IKEv2_EAP(next_payload="None")
        )
        self.first_next = NAME_TO_PAYLOAD_NUM["IDr"]

    def _wrap_fragment(self, frag_number, frag_total, load, next_payload):
        pkt = (
            IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=4500, dport=12345)
            / NON_ESP()
            / IKEv2(
                init_SPI=b"\xaa" * 8,
                resp_SPI=b"\xbb" * 8,
                exch_type="IKE_AUTH",
                flags="Response",
                next_payload="Encrypted_Fragment",
            )
            / IKEv2_Encrypted_Fragment(
                next_payload=next_payload,
                frag_number=frag_number,
                frag_total=frag_total,
                load=load,
            )
        )
        return IP(bytes(pkt))  # force a wire round-trip

    def test_udp_4500_response_parses_as_ikev2(self):
        # Guards the receive path: a sport-4500 IKE datagram must dissect to IKEv2.
        pkt = self._wrap_fragment(1, 1, b"\x00" * 32, self.first_next)
        self.assertIn(IKEv2, pkt)
        self.assertIn(IKEv2_Encrypted_Fragment, pkt)

    def test_reassembles_two_fragments_round_trip(self):
        plain = bytes(self.inner)
        split = len(plain) // 2
        enc1 = ikev2_crypto.encrypt(plain[:split], self.sk_er, self.encr_id, self.integ_id)
        enc2 = ikev2_crypto.encrypt(plain[split:], self.sk_er, self.encr_id, self.integ_id)
        r1 = self._wrap_fragment(1, 2, enc1, self.first_next)
        r2 = self._wrap_fragment(2, 2, enc2, 0)

        chain, n = EpdgIKEv2.reassemble_encrypted_response(
            [r2, r1], self.encr_id, self.sk_er, self.integ_id  # out of order on purpose
        )
        self.assertEqual(n, 2)
        self.assertIsNotNone(chain)
        self.assertIn(IKEv2_CERT, chain)
        self.assertIn(IKEv2_EAP, chain)

    def test_classify_cert_present(self):
        plain = bytes(self.inner)
        enc = ikev2_crypto.encrypt(plain, self.sk_er, self.encr_id, self.integ_id)
        r1 = self._wrap_fragment(1, 1, enc, self.first_next)
        chain, n = EpdgIKEv2.reassemble_encrypted_response(
            [r1], self.encr_id, self.sk_er, self.integ_id
        )
        result = EpdgIKEv2.classify_cert_response(chain, n)
        self.assertTrue(result["cert_present"])
        self.assertTrue(result["eap_started"])
        self.assertEqual(result["finding"], "cert_present")
        self.assertEqual(len(result["certs"]), 1)
        self.assertIn("frag-epdg.example", result["certs"][0]["subject"])

    def test_classify_vulnerable_no_cert_eap(self):
        inner = IKEv2_IDr(next_payload="EAP", IDtype="FQDN", ID="ims") / IKEv2_EAP(
            next_payload="None"
        )
        enc = ikev2_crypto.encrypt(bytes(inner), self.sk_er, self.encr_id, self.integ_id)
        r1 = self._wrap_fragment(1, 1, enc, NAME_TO_PAYLOAD_NUM["IDr"])
        chain, n = EpdgIKEv2.reassemble_encrypted_response(
            [r1], self.encr_id, self.sk_er, self.integ_id
        )
        result = EpdgIKEv2.classify_cert_response(chain, n)
        self.assertFalse(result["cert_present"])
        self.assertTrue(result["eap_started"])
        self.assertEqual(result["finding"], "vulnerable_no_cert_eap")

    def test_classify_notify_only_inconclusive(self):
        # Reproduces live Magenta 232-03: a single encrypted IKEv2_Notify(9003),
        # no cert, no EAP. The notify type must surface in the result.
        from scapy.contrib.ikev2 import IKEv2_Notify

        inner = IKEv2_Notify(next_payload="None", type=9003)
        enc = ikev2_crypto.encrypt(bytes(inner), self.sk_er, self.encr_id, self.integ_id)
        r1 = self._wrap_fragment(1, 1, enc, NAME_TO_PAYLOAD_NUM["Notify"])
        chain, n = EpdgIKEv2.reassemble_encrypted_response(
            [r1], self.encr_id, self.sk_er, self.integ_id
        )
        result = EpdgIKEv2.classify_cert_response(chain, n)
        self.assertFalse(result["cert_present"])
        self.assertFalse(result["eap_started"])
        self.assertEqual(result["notify_types"], [9003])
        self.assertEqual(result["finding"], "inconclusive")

    def test_classify_no_decryptable_response(self):
        result = EpdgIKEv2.classify_cert_response(None, 0)
        self.assertEqual(result["finding"], "no_decryptable_response")

    # --- Phase B: child-SA (ESP) proposal accept/reject ---------------------

    def _ipsec_classify(self, inner, first_next):
        enc = ikev2_crypto.encrypt(bytes(inner), self.sk_er, self.encr_id, self.integ_id)
        r1 = self._wrap_fragment(1, 1, enc, first_next)
        chain, n = EpdgIKEv2.reassemble_encrypted_response(
            [r1], self.encr_id, self.sk_er, self.integ_id
        )
        return EpdgIKEv2.classify_ipsec_proposal_response(chain, n)

    def test_ipsec_not_supported_on_no_proposal_chosen(self):
        from scapy.contrib.ikev2 import IKEv2_Notify

        inner = IKEv2_Notify(next_payload="None", type=14)  # NO_PROPOSAL_CHOSEN
        result = self._ipsec_classify(inner, NAME_TO_PAYLOAD_NUM["Notify"])
        self.assertTrue(result["proposal_rejected"])
        self.assertEqual(result["result"], "not_supported")

    def test_ipsec_supported_when_eap_starts(self):
        inner = IKEv2_IDr(next_payload="EAP", IDtype="FQDN", ID="ims") / IKEv2_EAP(
            next_payload="None"
        )
        result = self._ipsec_classify(inner, NAME_TO_PAYLOAD_NUM["IDr"])
        self.assertFalse(result["proposal_rejected"])
        self.assertTrue(result["eap_started"])
        self.assertEqual(result["result"], "supported")

    def test_ipsec_supported_on_later_vendor_error(self):
        # a vendor/identity error (not NO_PROPOSAL_CHOSEN) still means the
        # accepted -> supported; raw code surfaced
        from scapy.contrib.ikev2 import IKEv2_Notify

        inner = IKEv2_Notify(next_payload="None", type=9003)
        result = self._ipsec_classify(inner, NAME_TO_PAYLOAD_NUM["Notify"])
        self.assertFalse(result["proposal_rejected"])
        self.assertEqual(result["notify_types"], [9003])
        self.assertEqual(result["result"], "supported")

    def test_ipsec_inconclusive_without_response(self):
        result = EpdgIKEv2.classify_ipsec_proposal_response(None, 0)
        self.assertEqual(result["result"], "inconclusive")


class IpsecProposalBuildTest(unittest.TestCase):
    def _esp_transforms(self, encr, integ):
        from scapy.contrib.ikev2 import IKEv2_Proposal, IKEv2_Transform

        ike = EpdgIKEv2("192.0.2.1", 500, mcc="001", mnc="01")
        ike.encr_id = ikev2_crypto.EncrId.ENCR_NULL
        pkt = IP(bytes(ike.create_packet_ike_auth(encr, integ)))
        prop = pkt[IKEv2_Proposal]
        transforms, cur = [], prop.trans
        while isinstance(cur, IKEv2_Transform):
            transforms.append(cur)
            cur = cur.payload
        by_type = {}
        for t in transforms:
            by_type.setdefault(t.transform_type, []).append(t)
        return prop, by_type

    def test_child_sa_proposal_has_no_dh_group(self):
        # no child-SA PFS (SWu profile); ESP = ENCR + INTEG + ESN
        prop, by_type = self._esp_transforms(
            [EpdgIKEv2.ENC_AES_256], [EpdgIKEv2.INT_SHA2_256_128],
        )
        self.assertEqual(len(by_type[1]), 1)  # ENCR
        self.assertEqual(len(by_type[3]), 1)  # INTEG
        self.assertNotIn(4, by_type)          # no GroupDesc (no PFS)
        self.assertEqual(len(by_type[5]), 1)  # ESN
        self.assertEqual(prop.trans_nb, 3)

    def test_aead_cipher_has_no_integrity_transform(self):
        prop, by_type = self._esp_transforms([EpdgIKEv2.AES_GCM_16_256], [])
        self.assertEqual(len(by_type[1]), 1)  # ENCR (GCM)
        self.assertNotIn(3, by_type)  # no INTEG
        self.assertEqual(len(by_type[5]), 1)  # ESN
        self.assertEqual(prop.trans_nb, 2)


class ProbeTestConfigGuardTest(unittest.TestCase):
    """opt-in probes must not leak into production TESTCASES."""

    def test_no_probe_in_production_testcases(self):
        # parse main.py statically (importing it pulls in the DB layer)
        import ast
        import pathlib

        src = (pathlib.Path(__file__).resolve().parents[2]
               / "main.py").read_text()
        tree = ast.parse(src)
        names = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign)
                    and any(getattr(t, "id", None) == "TESTCASES"
                            for t in node.targets)):
                names = [e.value for e in node.value.elts]
        self.assertIsNotNone(names)
        for name in names:
            self.assertFalse(name.startswith("PROBE_"))


class IkeOuterProbeTestConfigTest(unittest.TestCase):
    """Outer (IKE SA) crypto sweep: additive PROBE_IKE_* names; SUPPORT_* untouched."""

    def _cfg(self):
        from scanner.ikev2.epdg_scanner import TEST_CONFIG
        return TEST_CONFIG

    def test_sweep_generated(self):
        t = self._cfg()
        encr = [k for k in t if k.startswith("PROBE_IKE_ENCR_")]
        integ = [k for k in t if k.startswith("PROBE_IKE_INTEG_")]
        dh = [k for k in t if k.startswith("PROBE_IKE_DH_")]
        self.assertEqual(len(encr), 10)
        self.assertEqual(len(integ), 6)
        self.assertEqual(len(dh), 14)
        # outer layer rides the IKE_SA_INIT path -> no inner/probe flags
        for k in encr + integ:
            self.assertNotIn("ipsec_encr", t[k])
            self.assertNotIn("ipsec_probe", t[k])

    def test_dh_alias_is_same_object(self):
        # identical object => byte-identical pipeline behaviour
        t = self._cfg()
        self.assertIs(t["PROBE_IKE_DH_2048MODP"], t["SUPPORT_DH_2048MODP"])

    def test_aead_offers_no_integrity(self):
        # GCM proposal omits the integrity transforms a CBC proposal carries
        t = self._cfg()
        cbc = len(t["PROBE_IKE_ENCR_AES_CBC_128"]["sa_list"][0])
        gcm = len(t["PROBE_IKE_ENCR_AES_GCM_16_128"]["sa_list"][0])
        self.assertEqual(cbc, 13)   # 1 encr + 5 prf + 6 integ + 1 dh
        self.assertEqual(gcm, 7)    # 1 encr + 5 prf + 1 dh (no integ)


if __name__ == "__main__":
    unittest.main()
