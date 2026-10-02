import sqlite3

DB_PATH = "vulnability.db"


def create_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        
        cvss_score REAL,
        cvss_severity TEXT,
        cvss_version TEXT,
        cvss_vector TEXT,
        
        epss_score REAL,
        epss_percentile REAL,
        epss_data TEXT,
        
        kev INTEGER DEFAULT 0,
        kev_date_added TEXT,
        kev_due_date TEXT,
        ransomeware_use TEXT,
        
        vendor TEXT,
        porduct TEXT,
        vulnerability_name TEXT,
        
        description TEXT,
        
        published TEXT,
        last_modified TEXT
        )
        """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_database()
    print("파일 생성 완료")