import csv
from pathlib import Path

FILES = [
    ("data/apache_selected_6.csv", 1, "CVE-TEST-2026-0001",
     "2.4.59", "2024-04-04"),
    ("data/openssl_selected_7.csv", 2, "CVE-TEST-2026-0002",
     "3.0.15", "2024-09-03"),
    ("data/nginx_selected_7.csv", 3, "CVE-TEST-2026-0003",
     "1.26.1", "2024-05-29"),
]

VENDORS = {
    1: ("Apache Software Foundation", "https://httpd.apache.org/"),
    2: ("OpenSSL Project", "https://www.openssl.org/"),
    3: ("F5, Inc.", "https://www.f5.com/"),
}

PRODUCTS = {
    1: "Apache HTTP Server",
    2: "OpenSSL",
    3: "NGINX Open Source",
}

def sql(value):
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"

records = []
anchors = {}
cwe_ids = set()

for filename, product_id, old_id, version, release_date in FILES:
    with open(filename, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    expected = {1: 6, 2: 7, 3: 7}[product_id]
    if len(rows) != expected:
        raise ValueError(f"{filename}: expected {expected}, got {len(rows)}")

    for row in rows:
        cve_id = row["cve_id"].strip()
        description = row["description"].strip()
        published_date = row["published_date"].strip()
        cvss_score = row["cvss_score"].strip()

        if not all([cve_id, description, published_date, cvss_score]):
            raise ValueError(f"Missing required field: {cve_id}")

        cwes = [
            x.strip() for x in (row.get("cwe_ids") or "").split(";")
            if x.strip()
        ]

        raw_refs = row.get("references") or row.get("reference_url") or ""
        refs = list(dict.fromkeys(
            x.strip() for x in raw_refs.split(";") if x.strip()
        ))

        record = {
            "cve_id": cve_id,
            "description": description,
            "published_date": published_date,
            "cvss_score": cvss_score,
            "cwes": cwes,
            "refs": refs,
            "product_id": product_id,
            "version": version,
        }
        records.append(record)
        cwe_ids.update(cwes)

    anchors[product_id] = rows[0]["cve_id"].strip()

if len(records) != 20:
    raise ValueError(f"Expected 20 records, got {len(records)}")

if len({r["cve_id"] for r in records}) != 20:
    raise ValueError("Duplicate CVE IDs detected")

lines = [
    "-- Generated from the three NVD-selected CSV files.",
    "-- Review before execution. This script is intended for one-time migration.",
    "BEGIN;",
    "",
    "-- Remove old synthetic relationships before replacing the CVE records.",
    "DELETE FROM CVE_REFERENCE;",
    "DELETE FROM CVE_CWE;",
    "DELETE FROM CVE_PRODUCT_VERSION;",
    "DELETE FROM CWE;",
    "",
    "-- Replace synthetic vendor and product labels.",
]

for vendor_id, (name, website) in VENDORS.items():
    lines.append(
        f"UPDATE VENDOR SET name = {sql(name)}, website = {sql(website)} "
        f"WHERE vendor_id = {vendor_id};"
    )

for product_id, name in PRODUCTS.items():
    lines.append(
        f"UPDATE PRODUCT SET name = {sql(name)} "
        f"WHERE product_id = {product_id};"
    )

lines += [
    "",
    "-- Update installed product versions; dependent asset mappings cascade.",
]

for product_id, old_id, version, release_date in [
    (1, "1.0", "2.4.59", "2024-04-04"),
    (2, "3.0", "3.0.15", "2024-09-03"),
    (3, "5.0", "1.26.1", "2024-05-29"),
]:
    lines.append(
        f"UPDATE PRODUCT_VERSION SET version_number = {sql(version)}, "
        f"release_date = {sql(release_date)} "
        f"WHERE product_id = {product_id} "
        f"AND version_number = {sql(old_id)};"
    )

lines += [
    "",
    "-- Remove unused synthetic product versions.",
    "DELETE FROM PRODUCT_VERSION WHERE",
    "    (product_id = 1 AND version_number = '1.1') OR",
    "    (product_id = 2 AND version_number = '3.1') OR",
    "    (product_id = 3 AND version_number = '5.1');",
    "",
    "-- Replace the three synthetic CVEs with real CVEs.",
]

by_id = {r["cve_id"]: r for r in records}

for product_id, old_id in [
    (1, "CVE-TEST-2026-0001"),
    (2, "CVE-TEST-2026-0002"),
    (3, "CVE-TEST-2026-0003"),
]:
    r = by_id[anchors[product_id]]
    lines.append(
        "UPDATE CVE SET "
        f"cve_id = {sql(r['cve_id'])}, "
        f"description = {sql(r['description'])}, "
        f"published_date = {sql(r['published_date'])}, "
        f"cvss_score = {r['cvss_score']} "
        f"WHERE cve_id = {sql(old_id)};"
    )

lines += [
    "",
    "-- Insert the remaining 17 CVE records.",
]

for r in records:
    if r["cve_id"] in anchors.values():
        continue
    lines.append(
        "INSERT INTO CVE (cve_id, description, published_date, cvss_score) "
        f"VALUES ({sql(r['cve_id'])}, {sql(r['description'])}, "
        f"{sql(r['published_date'])}, {r['cvss_score']});"
    )

lines += [
    "",
    "-- Add CWE classifications. Names are identifiers; descriptions link",
    "-- to the authoritative MITRE CWE definitions.",
]

for cwe in sorted(cwe_ids):
    number = cwe.replace("CWE-", "")
    lines.append(
        "INSERT INTO CWE (cwe_id, name, description) VALUES "
        f"({sql(cwe)}, {sql(cwe)}, "
        f"{sql('NVD weakness classification. Official definition: https://cwe.mitre.org/data/definitions/' + number + '.html')});"
    )

lines += ["", "-- Link CVEs to CWE classifications."]

for r in records:
    for cwe in r["cwes"]:
        lines.append(
            "INSERT INTO CVE_CWE (cve_id, cwe_id) VALUES "
            f"({sql(r['cve_id'])}, {sql(cwe)});"
        )

lines += ["", "-- Store the NVD and vendor reference URLs."]

for r in records:
    for ref in r["refs"]:
        lines.append(
            "INSERT INTO CVE_REFERENCE (cve_id, reference_url) VALUES "
            f"({sql(r['cve_id'])}, {sql(ref)}) "
            "ON CONFLICT DO NOTHING;"
        )

lines += ["", "-- Map each CVE to its verified affected product version."]

for r in records:
    lines.append(
        "INSERT INTO CVE_PRODUCT_VERSION "
        "(cve_id, product_id, version_number) VALUES "
        f"({sql(r['cve_id'])}, {r['product_id']}, {sql(r['version'])});"
    )

lines += [
    "",
    "COMMIT;",
    "",
]

output = Path("data/real_cve_import.sql")
output.write_text("\n".join(lines), encoding="utf-8")

print(f"Generated: {output}")
print(f"CVEs: {len(records)}")
print(f"Unique CWE IDs: {len(cwe_ids)}")
print(f"Reference links: {sum(len(r['refs']) for r in records)}")
print("Anchor replacements:")
for product_id, cve_id in anchors.items():
    print(f"  Product {product_id}: {cve_id}")
