import csv

class MobileCodeSearcher:
    def __init__(self, csv_file_path):
        self.csv_file_path = csv_file_path
        self.data = []
        self.load_data()

    def load_data(self):
        with open(self.csv_file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                self.data.append(row)

    def search_by_mcc(self, mcc):
        results = list(set([row["Country"] for row in self.data if row['MCC'] == mcc]))
        return results

    def search_by_mcc_mnc(self, mcc, mnc):
        results = [row for row in self.data if row['MCC'] == mcc and row['MNC'] == mnc]
        return [{"Country": row['Country'], "Network": row['Network']} for row in results]
