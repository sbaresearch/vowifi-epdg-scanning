import json
from pathlib import Path


def generator(output_path):
    epdg_domains = []

    # adding all 3 digit mcc's (1.000.000)
    for mnc in range(1000):
        for mcc in range(1000):
            mnc_padded = "{:03d}".format(mcc)
            mcc_padded = "{:03d}".format(mnc)

            epdg_domains.append(
                "epdg.epc.mnc{0}.mcc{1}.pub.3gppnetwork.org".format(
                    mnc_padded, mcc_padded
                )
            )

    # adding all 2 digit mcc's (100.000)
    for mnc in range(1000):
        for mcc in range(100):
            mnc_padded = "{:02d}".format(mcc)
            mcc_padded = "{:03d}".format(mnc)

            epdg_domains.append(
                "epdg.epc.mnc{0}.mcc{1}.pub.3gppnetwork.org".format(
                    mnc_padded, mcc_padded
                )
            )

    """
    for r in epdg_domains[:10]:
        print(r)
    """

    """
    # json solution, left for later.
    with open('epdg_domains_generated.json', 'w', encoding='utf-8') as file:
        json.dump(epdg_domains, file, ensure_ascii=False, indent=4)
    """

    with open(output_path, "w", encoding="utf-8") as file:
        for entry in epdg_domains:
            file.write("{}\n".format(entry))

    print("\nAdded {} entries to epdg_domains_generated.txt".format(len(epdg_domains)))


if __name__ == "__main__":
    generator()
