# advisory_cpe_generator

Generates one **CSAF 2.0** document per vendor and CVE (`stormshield_cve_2025_11955.json`,
`paloalto_cve_2024_0012.json`, `cisco_cve_2018_0171.json`) from the vendors' security
advisories, with a **CPE 2.3** identifier on every product version that can be identified.

Only standard CSAF 2.0 fields are written; nothing is invented. A CPE either comes from
the vendor's data, from a mapping you maintain, or from the NVD CPE dictionary. When none
of these identifies the product, the product is written without a CPE and listed in
`cpe_review.csv`.

| Vendor | Source | CPE in the source |
|---|---|---|
| Stormshield | https://advisories.stormshield.eu (HTML pages) | No |
| Cisco | openVuln API, then each advisory's CSAF document | Sometimes (`product_identification_helper`) |
| Palo Alto Networks | https://security.paloaltonetworks.com/api (`/json`, `/json/{ID}`): CVE JSON 5 records | Yes on recent records (`cpes`) |

## Installation

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
git clone https://github.com/ellipse2v/cpeMiniLLMLevenshtein ../cpeMiniLLMLevenshtein   # NVD dictionary
cp config.example.json config.json
```

## Usage

```bash
python -m advisory_cpe_generator --config config.json                      # enabled connectors
python -m advisory_cpe_generator --config config.json --vendor paloalto --since 7
python -m advisory_cpe_generator --config config.json --vendor stormshield --max 5
python -m advisory_cpe_generator --config config.json --rebuild            # no network, e.g. after editing cpe_mapping.csv
python -m advisory_cpe_generator --config config.json --vendor cisco --file downloaded_csaf/*.json
```

`--file` parses local files instead of fetching: Cisco CSAF documents or Palo Alto CVE JSON 5
records. (A saved Stormshield page lacks the product list, which is on the home page, so its
CVEs are skipped.)

Cisco needs openVuln API credentials in the environment (never in a file of the repository):

```bash
export CISCO_CLIENT_ID=... CISCO_CLIENT_SECRET=...
```

## Output

```
output/
├── stormshield/
│   ├── stormshield_cve_2025_11955.json
│   ├── index.txt          # CSAF provider index (section 7.1.13)
│   └── changes.csv        # CSAF provider change list (section 7.1.14), newest first
├── paloalto/ ...
├── cisco/ ...
└── .cache/<vendor>/<advisory>.json   # parsed advisories, used to rebuild without network
```

- One file per (vendor, CVE). When a vendor publishes several advisories for the same CVE,
  they are merged into one document; each advisory is a reference.
- The file name is the CSAF `tracking.id` (CSAF 2.0 section 5.1).
- A document is rewritten only when its content changes: `tracking.version` is then
  incremented and a `revision_history` entry added. Unchanged documents keep their dates.
- Publisher: `category: translator` by default (CSAF's category for a party that converts
  advisories it did not author); the vendor advisory is in `references`.

### What goes where in the CSAF document

| Data | CSAF field |
|---|---|
| Product, version | `product_tree`: vendor → product_name → `product_version` |
| Version range | `product_version_range` named with a [vers](https://github.com/package-url/vers-spec) expression, e.g. `vers:generic/>=11.2.0\|<11.2.4-h1`. No CPE: a wildcard CPE would mark every version as affected |
| CPE | `product_identification_helper.cpe` |
| Affected / fixed / not affected | `vulnerabilities[].product_status` |
| CVSS v2, v3.0, v3.1 | `vulnerabilities[].scores` (only when the source gives the vector) |
| CVSS v4 | a note: CSAF 2.0 has no CVSS v4 field |
| Workaround, fix, mitigation | `vulnerabilities[].remediations` |

## CPE resolution

For every product version, in this order:

1. **CPE from the source** (Palo Alto `cpes`, CSAF `product_identification_helper.cpe`), kept
   if it is a valid CPE 2.3 string.
2. **`cpe_mapping.csv`**: `vendor,product,cpe_part,cpe_vendor,cpe_product`, for names the
   dictionary does not match exactly (e.g. *GlobalProtect App* → `paloaltonetworks:globalprotect`).
3. **NVD dictionary, exact name**: the product name, with and without the vendor prefix and a
   trailing "Software", must equal an NVD product of the same vendor, and only one
   (*Cisco IOS XE Software* → `o:cisco:ios_xe`, *Stormshield Network Security* →
   `a:stormshield:stormshield_network_security`). Uses cpeMiniLLMLevenshtein's NVD cache and
   `cpe_aliases.csv` (vendor renames). The dictionary CPE is used when NVD lists the version,
   otherwise the version is substituted in the product's CPE.
4. **Semantic matcher** (`use_semantic_matcher: true`, needs sentence-transformers):
   cpeMiniLLMLevenshtein's `CPEMatcher`, accepted at `min_score` (0.65) or above.
5. Otherwise no CPE, and a line in `cpe_review.csv`.

With `expand_ranges`, a range of a product identified in the NVD dictionary (and for which
the source gave no CPE) is expanded into the versions NVD lists in that range, each with its
own CPE.

Loading the NVD dictionary takes ~25 s and ~850 MB, only when a product needs it.

## config.json

Every key is optional (defaults in `advisory_cpe_generator/config.py`, example in
`config.example.json`). Proxy: the global `proxy` block applies to every connector and a
connector's own `proxy` block overrides it key by key:

```json
{
  "proxy": {"http": "http://proxy.local:3128", "https": "http://proxy.local:3128", "no_proxy": ""},
  "connectors": {"cisco": {"proxy": {"https": "http://other-proxy:8080"}}}
}
```

Relative paths are relative to the directory of config.json.

## Tests

```bash
pytest
```

The tests run on real data, offline: a Stormshield advisory page, two Palo Alto CVE records
(from CVEProject/cvelistV5) and the OASIS Cisco CSAF example. Every generated document is
validated against the CSAF 2.0 JSON schema (with the FIRST CVSS schemas).

## Not verified yet

These parts were written from the documentation without access to the live service:

- Palo Alto `/json` list: its field names. The parser accepts the usual ones (`ID`, `id`,
  `cveId`, `updated`, ...). `PAN-SA-*` bulletins that are not CVE records are skipped.
- Cisco openVuln: advisories are expected to carry a `csafUrl`.
- Stormshield: the page layout of other advisories than the one in `tests/fixtures`.

## License

Apache License 2.0. `tests/schemas/cvss-v*.json`: Copyright (c) FIRST.ORG, Inc. (BSD-style
license in each file). `tests/schemas/csaf_json_schema.json` and
`tests/fixtures/cisco-sa-20180328-smi2.json`: OASIS CSAF TC.
