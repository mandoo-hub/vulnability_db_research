import requests
import json
import glob
import os
from datetime import datetime
import sqlite3

DB_PATH = "/mnt/vuln_db/vulnability.db"
OSV_URL = "https://api.osv.dev/v1/query"

RESULT_DIR = "/mnt/vuln_db/result"

def save_result(results):
    
    os.makedirs(
        RESULT_DIR,
        exist_ok=True
    )
    
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )
    
    result_path = os.path.join(
        RESULT_DIR,
        f"vulnerability_result_{timestamp}.json"
    )
    
    with open(
        result_path,
        "w",
        encoding="utf-8"
    ) as f:
        
        json.dump(
            results,
            f,
            indent=4,
            ensure_ascii=False
        )
    
    return result_path

def query_osv(ecosystem, name, version):

    payload = {
        "package": {
            "ecosystem": ecosystem,
            "name": name
        },
        "version": version
    }

    print("\n[DEBUG] OSV Request")
    print(json.dumps(payload, indent=2))

    response = requests.post(
        OSV_URL,
        json=payload,
        timeout=30
    )

    if response.status_code != 200:

        print(
            f"[OSV ERROR] "
            f"{ecosystem} "
            f"{name} "
            f"{version}"
        )

    print(
        "[DEBUG] HTTP Status: "
        f"{response.status_code}"
    )

    # print(
    #    "[DEBUG] Raw Response: {response.text[:1000]}"
    # )

    response.raise_for_status()

    return response.json()

def extract_cves(osv_result):

    results = []

    for vuln in osv_result.get("vulns", []):

        osv_id = vuln.get("id")

        # OSV ID 자체가 CVE인 경우
        if osv_id and osv_id.startswith("CVE-"):
            results.append(osv_id)

        for alias in vuln.get("aliases", []):

            if alias.startswith("CVE-"):
                results.append(alias)

        for upstream in vuln.get("upstream", []):
            if upstream.startswith("CVE-"):
                results.append(upstream)

    return list(set(results))


def get_cve_info(cve_id):

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        print(
            f"[DEBUG][SQLITE] "
            f"DB={DB_PATH},, CVE={cve_id}"
        )
        
        cur.execute("""
            SELECT
                cve_id,
                cvss_score,
                cvss_severity,
                cvss_version,
                cvss_vector,
                epss_score,
                epss_percentile,
                kev
            FROM vulnerabilities
            WHERE cve_id = ? 
        """, (cve_id,))

        row = cur.fetchone()

        conn.close()

        if row is None:
            return None

        return {
            "cve_id": row[0],
            "cvss_score": row[1],
            "cvss_severity": row[2],
            "cvss_version": row[3],
            "cvss_vector": row[4],
            "epss_score": row[5],
            "epss_percentile": row[6],
            "kev": row[7]
        }
    except sqlite3.Error as e:
        
        print(
            f"[DEBUG][SQLITE ERROR] "
            f"{type(e).__name__}: {e}"
        )
        
        return None


pattern = "/mnt/vuln_db/collect/inventory_*_*.json"

matching_files = glob.glob(pattern)

if not matching_files:
    print("패턴에 일치하는 파일이 없습니다.")
    exit()


inventory_path = max(matching_files, key=os.path.getmtime)
print(f"Target File: {inventory_path}")

with open(
    inventory_path,
    "r",
    encoding="utf-8"
) as f:
    inventory = json.load(f)

# Host 패키지
# for package in inventory.get(
#     "packages",
#     []
# ):

#     ecosystem = package.get(
#         "ecosystem"
#     )

#     name = package.get(
#         "name"
#     )

#     version = package.get(
#         "version"
#     )

#     if not all([
#         ecosystem,
#         name,
#         version
#     ]):
#         continue

#     print(
#         f"[HOST]"
#         f"{ecosystem}",
#         f"{name}",
#         f"{version}"
#     )

#     try:

#         osv_result = query_osv(
#             ecosystem,
#             name,
#             version
#         )

#         cves = extract_cves(
#             osv_result
#         )

#         if cves:
#             print(f" [+] CVE 발견:{cves}")

#         else:
#             print(" [-] CVE 없음")

#     except Exception as e:
#         print(f" [ERROR] {e}")

# Docker 내부 패키지

total_packages = 0
not_found_count = 0
found_count = 0
error_count = 0

vulnerability_results = []

for container in inventory.get(
    "containers",
    []
):

    container_id = container.get(
        "container_id"
    )

    for package in container.get(
        "packages",
        []
    ):

        ecosystem = package.get(
            "ecosystem"
        )

        name = package.get(
            "name"
        )

        version = package.get(
            "version"
        )
        
        if not all([
            ecosystem,
            name,
            version
        ]):
            continue

        # Debian 패키지는 source package 기준으로 OSV 조회
        if ecosystem.startswith("Debian:"):
            
            query_name = (
                package.get("source_name")
                or name
            )
            
            query_version = (
                package.get("source_version")
                or version
            )
        
        else:
            
            query_name = name
            query_version = version

        total_packages += 1

        print(
            f"[DEBUG][INPUT]"
            f"[DOCKER: {container_id}] "
            f"{ecosystem} "
            f"{name}@{version} "
            f"-> QUERY: "
            f"{query_name}@{query_version}"
        )

        try:

            osv_result = query_osv(
                ecosystem,
                query_name,
                query_version
            )
            

            cves = extract_cves(
                osv_result
            )

            print(
                f"[DEBUG][CVE] "
                f"{ecosystem} "
                f"{query_name}@{query_version} "
                f"-> {cves} "
            )

            if cves:
                found_count += 1

                print(
                    f" [+] CVE 발견:"
                    f"{ecosystem} {name} {version}"
                )
                
                for cve in cves:

                    print(
                        f"[DEBUG][DB QUERY] "
                        f"Searching {cve}"
                    )

                    cve_info = get_cve_info(
                        cve
                    )

                    print(
                        f"[DEBUG][DB RESULT] "
                        f"{cve} -> {cve_info}"
                    )

                    if cve_info:

                        print(
                            f" CVE : {cve_info['cve_id']}"
                        )

                        print(
                            f" CVSS : "
                            f"{cve_info['cvss_score']}"
                        )

                        print(
                            f" Severity : "
                            f"{cve_info['cvss_severity']}"
                        )

                        print(
                            f" EPSS : "
                            f"{cve_info['epss_score']}"
                        )

                        print(
                            f" KEV : "
                            f"{cve_info['kev']}"
                        )
                        
                        vulnerability_results.append({
                            "target": "docker",
                            "container_id": container_id,
                            
                            "ecosystem": ecosystem,
                            "package": name,
                            "version": version,
                            
                            "cve_id": cve_info["cve_id"],
                            
                            "cvss_score": cve_info["cvss_score"],
                            "cvss_severity": cve_info["cvss_severity"],
                            "cvss_version": cve_info["cvss_version"],
                            "cvss_vector": cve_info["cvss_vector"],
                            
                            "epss_score": cve_info["epss_score"],
                            "epss_percentile": cve_info["epss_percentile"],
                            
                            "kev": cve_info["kev"]
                        })

            else:
                not_found_count += 1
                # print(
                #    " [-] CVE 없음"
                # )

        except Exception as e:
            error_count += 1
            print(
                f" [ERROR] {e}"
            )

if __name__ == "__main__":
    result_path = save_result(
        vulnerability_results
    )
    
    print(
        f"[+] Result saved: {result_path}"
    )
    
    print("=" * 50)
    print("[점검 결과 요약]")
    print("=" * 50)
    print(f" Total Checked : {total_packages}개")
    print(f" Vulnerable : {found_count}개")
    print(f" Clean : {not_found_count}개")
    print(f" Errors : {error_count}개")
    print("=" * 50)
