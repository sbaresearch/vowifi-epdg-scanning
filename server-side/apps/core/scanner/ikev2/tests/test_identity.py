"""Tests for the 3GPP identity helpers in ikev2_class.

Run from the package root (apps/core):

    PYTHONPATH=server-side/apps/core python3 -m unittest \
        scanner.ikev2.tests.test_identity
"""

import unittest

from scanner.ikev2.ikev2_class import (
    EAP_IDENTITY_PREFIX,
    EpdgIKEv2,
    build_epc_nai,
    generate_probe_imsi,
)


class GenerateProbeImsiTest(unittest.TestCase):
    def test_two_digit_mnc(self):
        # MCC(3) + MNC(2) + MSIN(10 zeros) = 15 digits.
        imsi = generate_probe_imsi("232", "05")
        self.assertEqual(imsi, "232050000000000")
        self.assertEqual(len(imsi), 15)

    def test_three_digit_mnc(self):
        # MCC(3) + MNC(3) + MSIN(9 zeros) = 15 digits.
        imsi = generate_probe_imsi("310", "260")
        self.assertEqual(imsi, "310260000000000")
        self.assertEqual(len(imsi), 15)

    def test_mnc_three_digit_with_leading_zero(self):
        imsi = generate_probe_imsi("334", "020")
        self.assertEqual(imsi, "334020000000000")
        self.assertEqual(len(imsi), 15)

    def test_rejects_bad_input(self):
        for mcc, mnc in [("23", "05"), ("2322", "05"), ("abc", "05"), ("232", "5")]:
            with self.assertRaises(ValueError):
                generate_probe_imsi(mcc, mnc)


class BuildEpcNaiTest(unittest.TestCase):
    def test_permanent_matches_legacy_output(self):
        # Must reproduce the exact NAI the scanner sent before the refactor
        # (see the comment example in ikev2_class.py).
        imsi = generate_probe_imsi("232", "05")
        nai = build_epc_nai("232", "05", imsi=imsi, identity_type="aka_permanent")
        self.assertEqual(
            nai, "0232050000000000@nai.epc.mnc005.mcc232.3gppnetwork.org"
        )

    def test_realm_pads_mnc_and_mcc_to_three_digits(self):
        nai = build_epc_nai("1", "5", imsi="100050000000000")
        self.assertIn("@nai.epc.mnc005.mcc001.3gppnetwork.org", nai)

    def test_pseudonym_uses_prefix_two_and_username(self):
        # F10 (thesis 7.10.2): a temporary identity with the EAP-AKA pseudonym tag.
        nai = build_epc_nai(
            "232", "05", username="fakeuser", identity_type="aka_pseudonym"
        )
        self.assertEqual(
            nai, "2fakeuser@nai.epc.mnc005.mcc232.3gppnetwork.org"
        )

    def test_every_identity_type_has_distinct_prefix(self):
        prefixes = list(EAP_IDENTITY_PREFIX.values())
        self.assertEqual(len(prefixes), len(set(prefixes)))

    def test_unknown_identity_type_rejected(self):
        with self.assertRaises(ValueError):
            build_epc_nai("232", "05", imsi="x", identity_type="nope")

    def test_requires_imsi_or_username(self):
        with self.assertRaises(ValueError):
            build_epc_nai("232", "05", identity_type="aka_permanent")


class IdiRealmOverrideTest(unittest.TestCase):
    """IDi realm override changes only the IDi; default stays byte-identical."""

    def test_default_realm_is_the_target(self):
        e = EpdgIKEv2("192.0.2.1", 500, mcc="505", mnc="01")
        self.assertEqual((e.idi_mcc, e.idi_mnc), ("505", "01"))
        self.assertTrue(e.imsi.startswith("50501"))  # IMSI carries target MCC+MNC

    def test_no_override_keeps_nai_byte_identical(self):
        e = EpdgIKEv2("192.0.2.1", 500, mcc="232", mnc="05")
        nai = build_epc_nai(e.idi_mcc, e.idi_mnc, imsi=e.imsi,
                            identity_type="aka_permanent")
        self.assertTrue(nai.endswith("@nai.epc.mnc005.mcc232.3gppnetwork.org"))

    def test_override_changes_realm_and_imsi_only(self):
        e = EpdgIKEv2("192.0.2.1", 500, mcc="505", mnc="01",
                      idi_mcc="001", idi_mnc="01")
        self.assertEqual((e.idi_mcc, e.idi_mnc), ("001", "01"))
        self.assertTrue(e.imsi.startswith("00101"))   # foreign (test-PLMN) IMSI
        nai = build_epc_nai(e.idi_mcc, e.idi_mnc, imsi=e.imsi,
                            identity_type="aka_permanent")
        self.assertIn("mnc001.mcc001", nai)


if __name__ == "__main__":
    unittest.main()
