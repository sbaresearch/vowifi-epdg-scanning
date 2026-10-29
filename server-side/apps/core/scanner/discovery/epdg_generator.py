def generator(output_path):
    epdg_domains = []

    # all 3-digit MNCs (1,000,000 combinations)
    for mcc in range(1000):
        for mnc in range(1000):
            epdg_domains.append(
                "epdg.epc.mnc{0:03d}.mcc{1:03d}.pub.3gppnetwork.org".format(mnc, mcc)
            )

    # all 2-digit MNCs (100,000 combinations)
    for mcc in range(1000):
        for mnc in range(100):
            epdg_domains.append(
                "epdg.epc.mnc{0:02d}.mcc{1:03d}.pub.3gppnetwork.org".format(mnc, mcc)
            )

    with open(output_path, "w", encoding="utf-8") as file:
        for entry in epdg_domains:
            file.write("{}\n".format(entry))

    print("\nAdded {} entries to epdg_domains_generated.txt".format(len(epdg_domains)))
