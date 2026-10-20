import time
import sqlite3
import requests
from datetime import datetime, timezone

DB_PATH = "vulnability.db"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cvss(metrics):

    # 우선순위: CVSS 4.0 → 3.1 → 3.0 → 2.0
    candidates = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0")
    ]

    for key, version in candidates:

        metric_list = metrics.get(key, [])

        if not metric_list:
            continue

        metric = metric_list[0]

        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")

        severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
        )

        return {
            "score": score,
            "severity": severity,
            "version": version,
            "vector": vector
        }

    return {
        "score": None,
        "severity": None,
        "version": None,
        "vector": None
    }


def load_nvd_incremental():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    start_index = 0
    page_size = 2000

    # 최초 증분 기준
    cur.execute("""
            SELECT last_sync
            FROM sync_state
            WHERE source = 'nvd'
    """)
    
    row = cur.fetchone()
    
    if row:
        last_sync = row[0]
    else:
        last_sync = "2026-10-20T06:00:00.000Z"
    
    # 이번 실행 시작 시각
    sync_end = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )
    
    print("[+] 이전 동기화:", last_sync)
    print("[+] 이번 동기화 기준", sync_end)
    
    while True:

        params = {
            "lastModStartDate": last_sync,
            "lastModEndDate": sync_end,
            "startIndex": start_index,
            "resultsPerPage": page_size
        }

        response = requests.get(
            NVD_URL,
            params=params,
            timeout=120
        )
        
        print("[+] URL:", response.url)
        print("[+] STATUS:", response.status_code)
        print("[+] CONTENT-TYPE:", response.headers.get("Content-Type"))
        print("[+] BODY:", response.text[:500])

        response.raise_for_status()
        
        data = response.json()

        vulnerabilities = (
            data.get(
                "vulnerabilities",
                []
            )
        )

        if not vulnerabilities:
            break

        for item in vulnerabilities:

            cve = item["cve"]

            cve_id = cve["id"]

            metrics = (
                cve.get(
                    "metrics",
                    {}
                )
            )
            cvss = extract_cvss(
                metrics
            )

            # 영어 설명 추출
            description = None

            for desc in cve.get(
                "descriptions",
                []
            ):
                if desc.get("lang") == "en":

                    description = (
                        desc.get(
                            "value"
                        )
                    )

                    break
            cur.execute("""
            INSERT INTO vulnerabilities (
                
                cve_id,
                
                cvss_score,
                cvss_severity,
                cvss_version,
                cvss_vector,
                
                description,
                
                published,
                last_modified
            )
            
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            
            ON CONFLICT(cve_id)
            
            DO UPDATE SET
                
                cvss_score = 
                    excluded.cvss_score,
                    
                cvss_severity = 
                    excluded.cvss_severity,
                
                cvss_version = 
                    excluded.cvss_version,
                
                cvss_vector = 
                    excluded.cvss_vector,
                    
                description = 
                    excluded.description,
                    
                published = 
                    excluded.published,
                    
                last_modified = 
                    excluded.last_modified
            """, (

                cve_id,

                cvss["score"],
                cvss["severity"],
                cvss["version"],
                cvss["vector"],

                description,

                cve.get("published"),
                cve.get("lastModified")
            ))
        
        conn.commit()

        start_index += len(
            vulnerabilities
        )

        total = data.get(
            "totalResults",
            0
        )

        print(
            f"[+] NVD 증분 업데이트"
            f"{start_index}/{total}"
        )

        if start_index >= total:
            break

        # NVD API 과부하 방지
        time.sleep(6)
    
    # 전체 증분 업데이트가 성공했을 때만 Last_sync 갱신
    
    cur.execute("""
        INSERT INTO sync_state (
            source,
            last_sync,
            last_error,
            status,
            retry_count
        )
        
        VALUES (
            'nvd',
            ?,
            NULL,
            'success',
            0
        )
        
        ON CONFLICT(source)
        
        DO UPDATE SET
            last_sync = excluded.last_sync,
            last_error = NULL,
            status = 'success',
            retry_count = 0
    """, (
        sync_end,
    ))
    
    conn.commit()

    conn.close()

    print("[+] NVD 증분 업데이트 완료")
    print("[+] last_sync:", sync_end)


if __name__ == "__main__":
    load_nvd_incremental()
