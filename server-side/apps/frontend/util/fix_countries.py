import json
import unicodedata
from pathlib import Path

# this takes a list of country names from your DB and tries to
# map them to ISO3 codes from Natural Earth 50m json.
# it then outputs a json with the mappings and a txt file with
# countires that could not be matched, these need to be manually
# reviewed and added to the MANUAL dict in this script.

# this must be run frequently until all countries are mapped.

db_countries = {
    "Albania",
    "Andorra",
    "Anguilla",
    "Antigua and Barbuda",
    "Argentina",
    "Armenia",
    "Australia",
    "Austria",
    "Azerbaijan",
    "Bahamas",
    "Bahrain",
    "Bangladesh",
    "Barbados",
    "Belarus",
    "Belgium",
    "Bermuda",
    "Brazil",
    "British Virgin Islands",
    "Bulgaria",
    "Cambodia",
    "Canada",
    "Cayman Islands",
    "Chile",
    "Colombia",
    "Cook Islands",
    "Costa Rica",
    "Croatia",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Dominica",
    "Dominican Republic",
    "Ecuador",
    "Egypt",
    "Estonia",
    "Ethiopia",
    "Faroe Islands",
    "Finland",
    "France",
    "French Departments and Territories in the Indian Ocean",
    "French Guiana",
    "French Polynesia",
    "Germany",
    "Ghana",
    "Greece",
    "Grenada",
    "Hong Kong",
    "Hungary",
    "Iceland",
    "India",
    "Indonesia",
    "Iraq",
    "Ireland",
    "Israel",
    "Italy",
    "Jamaica",
    "Japan",
    "Jordan",
    "Kazakhstan",
    "Kenya",
    "Kiribati",
    "Kuwait",
    "Kyrgyzstan",
    "Latvia",
    "Lesotho",
    "Libya",
    "Liechtenstein",
    "Lithuania",
    "Luxembourg",
    "Malaysia",
    "Maldives",
    "Malta",
    "Mauritius",
    "Mexico",
    "Moldova",
    "Monaco",
    "Mongolia",
    "Montenegro",
    "Montserrat",
    "Morocco",
    "Myanmar",
    "Namibia",
    "Nepal",
    "Netherlands",
    "New Zealand",
    "Norway",
    "Oman",
    "Pakistan",
    "Panama",
    "Paraguay",
    "Peru",
    "Philippines",
    "Poland",
    "Portugal",
    "Puerto Rico",
    "Qatar",
    "Romania",
    "Russian Federation",
    "Saint Kitts and Nevis",
    "Saint Lucia",
    "Saint Vincent and the Grenadines",
    "Saudi Arabia",
    "Singapore",
    "Slovakia",
    "Slovenia",
    "South Africa",
    "Spain",
    "Sri Lanka",
    "Sudan",
    "Sweden",
    "Switzerland",
    "Taiwan",
    "Tajikistan",
    "Tanzania",
    "Thailand",
    "Trinidad and Tobago",
    "Turkey",
    "Turks and Caicos Islands",
    "Ukraine",
    "United Arab Emirates",
    "United Kingdom",
    "United States of America",
    "United States Virgin Islands",
    "Uruguay",
    "Uzbekistan",
    "Venezuela",
    "Vietnam",
    "Zimbabwe",
}

ALIAS_FIELDS = (
    "ADMIN",
    "NAME",
    "NAME_LONG",
    "FORMAL_EN",
    "NAME_CIAWF",
)


def norm(s: str) -> str:
    s = (s or "").strip().lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    out = []
    prev_space = False
    for ch in s:
        if ch.isalnum():
            out.append(ch)
            prev_space = False
        else:
            if not prev_space:
                out.append(" ")
                prev_space = True
    return "".join(out).strip()


HERE = Path(__file__).resolve().parent
STATIC = HERE.parent / "static"
DATA = STATIC / "data"

ne_file = DATA / "ne_50m_admin_0_countries.json"
out_file = DATA / "db_to_iso3.json"
report_file = DATA / "db_to_iso3.unmatched.txt"

if not ne_file.exists():
    raise FileNotFoundError(f"Natural Earth file not found: {ne_file}")

MANUAL = {
    # naming variants
    norm("Russia"): "RUS",
    norm("United States"): "USA",
    norm("USA"): "USA",
    norm("UK"): "GBR",
    norm("Viet Nam"): "VNM",
    norm("Cote d Ivoire"): "CIV",
    norm("Ivory Coast"): "CIV",
    norm("Hong Kong"): "HKG",
    norm("Taiwan"): "TWN",
    norm("French Departments and Territories in the Indian Ocean"): "ATF",
    norm("France"): "FRA",
    norm("Norway"): "NOR",
    norm("French Guiana"): "GUF",  # or "FRA" if you want to roll it into France
}


with ne_file.open("r", encoding="utf-8") as f:
    ne = json.load(f)

features = ne.get("features", [])
if not isinstance(features, list):
    raise ValueError("Unexpected Natural Earth JSON: missing 'features' list")

alias_to_iso3 = {}
indexed = 0
skipped = 0

for feat in features:
    p = feat.get("properties") or {}

    iso3 = p.get("ISO_A3")
    if not isinstance(iso3, str) or iso3 in ("-99", ""):
        skipped += 1
        continue

    indexed += 1

    for field in ALIAS_FIELDS:
        val = p.get(field)
        if isinstance(val, str) and val.strip():
            k = norm(val)
            alias_to_iso3.setdefault(k, iso3)

print(f"Natural Earth features: {len(features)}")
print(f"Indexed (valid ISO_A3): {indexed} (skipped {skipped})")

db_to_iso3 = {}
unmatched = []

for db_name in sorted(db_countries):
    k = norm(db_name)

    iso3 = alias_to_iso3.get(k) or MANUAL.get(k)

    if iso3:
        db_to_iso3[db_name] = iso3
    else:
        unmatched.append(db_name)


with out_file.open("w", encoding="utf-8") as f:
    json.dump(db_to_iso3, f, ensure_ascii=False, indent=2)

with report_file.open("w", encoding="utf-8") as f:
    for name in unmatched:
        f.write(name + "\n")

print(f"Wrote mapping: {out_file} ({len(db_to_iso3)} matched)")
print(f"Unmatched: {len(unmatched)} -> {report_file}")

if unmatched:
    print("First unmatched examples:")
    for n in unmatched[:20]:
        print("  -", n)
