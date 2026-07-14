# VoWiFi ePDG Scanning

This artifact contains the source code necessary to run client- and server-side evaluation scripts for our VoWiFi security analysis.
While the scripts can be used to scan for various security parameters (e.g., ciphers), our evaluation focuses on the key exchange (i.e., the supported Diffie-Hellman (DH) groups and the rekey-timings) that are used for the first (i.e., phase 1) VoWiFi tunnel that is essential to the security of the overall communication.

> [!TIP]
> **Continuous scanning data and insights are available on the [VoWiFi Watchdog Platform](https://vowifi-watchdog.sec.univie.ac.at/).**

## 📚 Publication

Our corresponding USENIX Security '24 paper can be found [here](usenix-security-24/USENIX_Security_2024_Diffie_Hellman_Picture_Show_Key_Exchange_Stories_from_Commercial_VoWiFi_Deployments_PN.pdf).
The presentation slides are available [here](usenix-security-24/USENIX_Security_2024_Diffie_Hellman_Picture_Show_Slides.pdf).

If you want to cite our paper in your work, please use the following BibTeX entry.
```bibtex
@inproceedings{gegenhuber2024diffie,
  title={Diffie-Hellman Picture Show: Key Exchange Stories from Commercial VoWiFi Deployments},
  author={Gegenhuber, Gabriel K and Holzbauer, Florian and Frenzel, Philipp {\'E} and Weippl, Edgar and Dabrowski, Adrian},
  booktitle={33rd USENIX Security Symposium (USENIX Security 24)},
  year={2024}
}
```

## Cloning the repository

We use Git LFS (Git Large File Storage) for the dumps.zip file containing client-side operator configurations. To successfully clone the repository including the 400MB dumps.zip file, Git LFS hooks are required.

Thefore:

- Make sure to have [Git LFS installed](https://docs.github.com/en/repositories/working-with-files/managing-large-files/installing-git-large-file-storage).

- Setup the LFS hooks by running `git lfs install`.

- Clone the repository by running `git clone https://github.com/sbaresearch/vowifi-epdg-scanning.git`.

Alternatively, if you do not want to use Git LFS you can clone the repository without the prior instructions and [download the dumps.zip file via a mirror at our scientific artifact storage](https://phaidra.univie.ac.at/detail/o:2083413).

```
git clone https://github.com/sbaresearch/vowifi-epdg-scanning.git
wget -O vowifi-epdg-scanning/client-side/dumps.zip https://services.phaidra.univie.ac.at/api/object/o:2083413/download
```

## Client Side Configuration Extraction (Passive/Static Analysis)

This README file contains the instructions for the client-side VoWiFi parameter analysis (Section 5).

You can reproduce all the client-side analysis steps using the provided jupyter notebook.

#### Installation
```bash
cd client-side
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To run the notebook:

```bash
jupyter notebook client_side_evaluation.ipynb
```

The jupyter notebook provides step-by-step instructions for extracting and harmonizing the client-side configuration data for different device types. Furthermore, it allows using the harmonized results in json-format (created via the first part of the notebook) to generate graphs representing the summarized results in a more convenient and human-friendly way.

#### Extracting Client Configurations from Firmware ROMs
Since this requires downloading complete firmware ROMs (having often more than 10GB) from external sources and since unpacking the relevant configurations from the ROM is an overall time-consuming extraction approach, we took a shorter path for the artifact evaluation and just provide the configuration files that were used within our publication in the dumps.zip file.

To make it easier for other researchers to repeat the full configuration extraction at a later point in time (e.g., with more recent or different firmware ROMs) we reference the used approach [here](#extracting-configurations-for-other-devices).


## Server Side ePDG Probing (Active/Dynamic Analysis)

Automated VoWiFi server-side ePDG probing, ePDG discovery, scanning, storage, and visualization (Section 6).

#### What this Project does

This project runs an automated pipeline that discovers ePDG infrastructure and turns raw scan output into queryable data.

`apps/core/scanner/main.py` does a one-time setup first, then repeats the scan pipeline every 8 hours.

At startup, `environment_setup_check()` creates missing directories and generates baseline files when needed (the candidate ePDG domain list and `zdns` config).

Per cycle:

1. Resolve generated ePDG domains with `zdns` and write raw DNS output.
2. Filter DNS results to keep useful A/AAAA answers and valid CNAME-only domains.
3. Build the up to date ePDG target list and overwrite `epdg_domains.txt`.
4. Execute multiple first layer IKEv2 handshake test cases per target to observe behavior across DH variants.
5. Enrich discovered targets with MCC/MNC metadata (country, network, operator, ITU region).
6. Normalize and enrich scan results, then upsert into Postgres tables (`scan`, `epdg_server`, `epdg_result`).
7. Refresh latest-result snapshots (`refresh_latest_snapshot`, `refresh_country_operator_snapshot`).
8. Rebuild the key-collision dataset (`refresh_collision_keys`).
9. Cache databse takouts as sql dump and CSV files, compressed and ready to serve for download.
10. Compress older raw DNS files, keep the newest one uncompressed, then wait for the next cycle.

#### Services (Docker Compose)

- `epdg-scanner`: orchestrates DNS + scan pipeline (`scanner.main`)
- `postgres`: primary data store
- `api-backend`: FastAPI (`/api/v1/*`)
- `key-collision-zulip-bot`: Zulip bot (built from `apps/bot`) that reports IKEv2 key collisions; reads from the API (`API_ORIGIN=http://api-backend:8000`) and Postgres. No host port.
- `adminer`: database UI on `127.0.0.1:8080`
- `frontend`: multi-page static site (map, table, collisions chart, database download) on `127.0.0.1:8081`

API backend is exposed on `127.0.0.1:8000`.

#### Quick Start

1. Create your secrets file:

```bash
cp .env.secrets.example .env.secrets
```

2. Populate your secrets in `.env.secrets`:

- **Required** (Postgres): `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- **Required** (API DB connection): `DATABASE_URL` (or `DATABASE_URL_FILE`)

- Required only if running the Zulip bot (will gracefully exit if not set): `ZULIP_SERVER_URL`, `ZULIP_BOT_EMAIL`, `ZULIP_BOT_API_KEY`
- Optional (API behavior): `ENABLE_DOCS`, `DEFAULT_LIMIT`, `MAX_LIMIT`, `API_KEY` (or `API_KEY_FILE`), `ENABLE_RATE_LIMIT`, `RATE_LIMIT_REQUESTS_PER_MINUTE`, `RATE_LIMIT_TIMEOUT_SECONDS`, `LOG_LEVEL`
- Optional (API metadata): `APP_NAME`, `APP_VERSION`, `API_V1_PREFIX`
- Optional (DB pool tuning): `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT_SECONDS`, `DB_POOL_RECYCLE_SECONDS`, `DB_SLOW_QUERY_MS`

> [!NOTE]
> The frontend calls the API with the same `API_KEY`, which is currently embedded in the frontend JS. If you set `API_KEY`, also update it at the top of `apps/frontend/static/js/map.js`, `table.js`, `collisions.js` and `takeout.js`.

3. Build and start:

```bash
docker compose build
docker compose up
```

> [!NOTE]
> Persistent data is stored under `./epdg-container/` (scanner data + postgres volume + cached takout download).

4. Analyze the data via the web frontend at `127.0.0.1:8081` or via adminer at `127.0.0.1:8080`.

#### API Overview

Base path: `/api/v1` (all `/api/v1` routes require the API key).

Main route groups:

- /servers
- /scans
- /results
- /latest-results
- /all-results (paginated historical scan results)
- /map
- /collisions-latest (latest key-collision data)
- /collision-keys (collision keys ordered by usage count)
- /takeout

#### Disclaimer

This section uses third-party tools and data sources:

- Natural Earth country boundaries (`apps/frontend/static/ne_50m_admin_0_countries.json`): https://github.com/martynafford/natural-earth-geojson
- DNS scanning tool (`zdns`): https://github.com/zmap/zdns
- MCC/MNC enrichment sources: [mcc-mnc.com](https://mcc-mnc.com/) and [Wikipedia mobile network code pages](https://en.wikipedia.org/wiki/Mobile_network_codes)

Please follow the upstream project license and terms when using or redistributing it.


## Extracting Configurations for Other Devices

Depending on the device, the following approaches were used to extract the VoWiFi configuration data:

| Provider | VoWiFi configuration through | Download & Parse                              |
| -------- | ---------------------------- | --------------------------------------------- |
| Apple    | IPCC Files                   | https://github.com/mrlnc/ipcc-downloader      |
| Oppo     | MBN Files                    | https://github.com/sbaresearch/mbn-mcfg-tools |
| Xiaomi   | MBN Files                    | https://github.com/sbaresearch/mbn-mcfg-tools |
| Samsung  | XML Files                    | Handset path: /system/etc/epdg_apns_conf.xml  |

### Apple

To extract VoWiFi configurations from IPCC files the following steps are necessary.

Download IPCC files using  [ipcc-downloader](https://github.com/mrlnc/ipcc-downloader).

``` bash
./download_ipccs.py -d # May take some time
cd data
for i in $(find . | grep plist); do plistutil -i $i -o $i.xml; done
```

The IPCC URLs (`ipcc_urls.txt`) and the unpacked carrier configurations are stored in the `data` folder.

### Samsung

1. Extract AP (.tar.md5) file

2. lz4: unpack super.img.lz4 to super.img [`lz4 super.img.lz4`]

3. simg2img: unpack super.img to super.img.raw [`simg2img super.img super.img.raw`]

4. lpunpack: extract system image from super.img.raw [`python3 lpunpack.py --partition=system super.img.raw extracted`]

5. Mount extracted/system and go to /system/etc/

The `system/etc/epdg_apns_conf.xml` file contains ePDG endpoints and the corresponding cipher configurations.


### Xiaomi + Oppo (Qualcomm-generic)

1. Extract ROM, go to images folder
2. Mount NON-HLOS.bin
3. MBN MCFG files are located at /image/modem_pr/mcfg
4. Use [mbn-mcfg-tools](https://github.com/sbaresearch/mbn-mcfg-tools) to further process MBN files


## License

This project is licensed under GPLv3.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)