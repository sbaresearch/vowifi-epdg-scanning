from mobile_codes import MobileCodeSearcher

searcher = MobileCodeSearcher('mccmnc.csv')

# Search by MCC
mcc_results = searcher.search_by_mcc('520')
print(mcc_results)

# Search by MCC and MNC
mcc_mnc_results = searcher.search_by_mcc_mnc('289', '88')
print(mcc_mnc_results)
