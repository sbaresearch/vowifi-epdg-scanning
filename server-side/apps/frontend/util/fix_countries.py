import json
import unicodedata
from pathlib import Path

# builds db_to_iso3.json (country name -> ISO3) from Natural Earth 50m plus MANUAL.
# unmatched names land in db_to_iso3.unmatched.txt for review -> MANUAL.

# the ePDG database's country names; each must keep a key (checked below).
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

# names Natural Earth lacks; emitted as-is and matched by normalized name.
MANUAL = {
    # --- ISO_A3 "-99" in Natural Earth 50m (its other "-99"s aren't ISO 3166) ---
    "France": "FRA",
    "Norway": "NOR",
    "Kosovo": "XKX",  # user-assigned, not in ISO 3166
    # --- missing from Natural Earth 50m ---
    "Bonaire, Sint Eustatius and Saba": "BES",
    "Bouvet Island": "BVT",
    "Christmas Island": "CXR",
    "Cocos Islands": "CCK",
    "French Guiana": "GUF",  # or "FRA" to merge into France
    "Gibraltar": "GIB",
    "Guadeloupe": "GLP",
    "Martinique": "MTQ",
    "Mayotte": "MYT",
    "Reunion": "REU",
    "Réunion": "REU",
    "Svalbard and Jan Mayen": "SJM",
    "Tokelau": "TKL",
    "Tuvalu": "TUV",
    "United States Minor Outlying Islands": "UMI",
    # --- naming variants ---
    "Bosnia": "BIH",
    "Cape Verde": "CPV",  # NE: "Cabo Verde"
    "Cote d Ivoire": "CIV",
    "French Departments and Territories in the Indian Ocean": "ATF",
    "Hong Kong": "HKG",
    "Hong Kong, SAR China": "HKG",
    "Ivory Coast": "CIV",
    "Korea": "KOR",  # CyberGhost's name; ambiguous in NE
    "Libyan Arab Jamahiriya": "LBY",  # superseded official name
    "North Macedonia": "MKD",  # NE 50m: "Macedonia"
    "Palestine, State of": "PSE",
    "Russia": "RUS",
    "Taiwan": "TWN",
    "Taiwan, Republic of China": "TWN",
    "UAE": "ARE",
    "UK": "GBR",
    "USA": "USA",
    "United States": "USA",
    "Viet Nam": "VNM",
    # --- gluetun server list spellings, typos included ---
    "Antiguaand Barbuda": "ATG",
    "Coted`Ivoire": "CIV",
    "Marocco": "MAR",  # Surfshark's misspelling
    "Republicof Djibouti": "DJI",
    "Republicof Singapore": "SGP",
    "Republicofthe Congo": "COG",
    "Saint Kittsand Nevis": "KNA",
    "Saint Pierreand Miquelon": "SPM",
    "Saint Vincentandthe Grenadines": "VCT",
    "Sao Tomeand Principe": "STP",
    "Svalbardand Jan Mayen": "SJM",
    "Trinidadand Tobago": "TTO",
    "Turksand Caicos Islands": "TCA",
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

manual_by_norm = {norm(name): iso3 for name, iso3 in MANUAL.items()}

# every Natural Earth spelling, original casing (lookups match exactly).
db_to_iso3 = {}
for feat in features:
    p = feat.get("properties") or {}

    iso3 = p.get("ISO_A3")
    if not isinstance(iso3, str) or iso3 in ("-99", ""):
        continue

    for field in ALIAS_FIELDS:
        val = p.get(field)
        if isinstance(val, str) and val.strip():
            db_to_iso3.setdefault(val.strip(), iso3)

for name, iso3 in MANUAL.items():
    db_to_iso3.setdefault(name, iso3)

# ePDG names last, by normalized lookup, so each keeps its spelling ("Czech Republic").
unmatched = []
for db_name in sorted(db_countries):
    iso3 = alias_to_iso3.get(norm(db_name)) or manual_by_norm.get(norm(db_name))
    if iso3:
        db_to_iso3.setdefault(db_name, iso3)
    else:
        unmatched.append(db_name)

db_to_iso3 = dict(sorted(db_to_iso3.items()))

with out_file.open("w", encoding="utf-8") as f:
    json.dump(db_to_iso3, f, ensure_ascii=False, indent=2)

with report_file.open("w", encoding="utf-8") as f:
    for name in unmatched:
        f.write(name + "\n")

print(f"Wrote mapping: {out_file} ({len(db_to_iso3)} names, "
      f"{len(set(db_to_iso3.values()))} distinct ISO3)")
print(f"Unmatched ePDG names: {len(unmatched)} -> {report_file}")

if unmatched:
    print("ePDG country names with no ISO3 -- add them to MANUAL:")
    for n in unmatched:
        print("  -", n)
    raise SystemExit(1)
