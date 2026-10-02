import gzip
import csv
import sqlite3

DB_PATH = "vulnability.db"

def load_epss():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    with gzip.open(
        "data/epss.csv.gz",
        "rt",
        encoding="utf-8"
    ) as f:
        
         # EPSS CSV 첫 줄에는 보통 metadata 주석이 존재할 수 있음
         lines = (
             line for line in f
             if not line.startswith("#")
         )
         
         reader = csv.DictReader(lines)
         
         for row in reader:
             
             cve = row["cve"]
             epss = float(row["epss"])
             percentile = float(row["percentile"])
             
             cur.execute("""
                         INSERT INTO vulnerabilities (
                             cve_id,
                             epss_score,
                             epss_percentile
                         )
                         vALUES (?, ?, ?)
                         
                         ON CONFLICT(cve_id)
                         DO UPDATE SET
                             epss_score = excluded.epss_score,
                             epss_percentile = excluded.epss_percentile
                        """, (
                            cve,
                            epss,
                            percentile
                        ))
             
    conn.commit()
    conn.close()
             
    print("[+] EPSS load 완료")
             
if __name__ == "__main__":
    load_epss()