import json
import sqlite3

DB_PATH = "vulnability.db"

def load_kev():
    
    conn = sqlite3.connect(DB_PATH )
    cur = conn.cursor()
    
    #
    # 먼저 기존 KEV flag 초기화
    #
    
    cur.execute("""
    UPDATE vulnerabilities
    SET kev = 0
    """)
    
    with open(
        "data/kev.json",
        "r",
        encoding="utf-8"
    ) as f:
        
        data = json.load(f)
        
    vulnerabilities = data["vulnerabilities"]
    
    for item in vulnerabilities:
        
        cve = item["cveID"]
        
        cur.execute("""
        INSERT INTO vulnerabilities (
            
            cve_id,
            
            kev,
            kev_date_added,
            kev_due_date,
            
            ransomware_use,
            
            vendor,
            product,
            vulnerability_name
            
        )
        
        VALUES (?, 1, ?, ?, ?, ?, ?, ?)
        
        ON CONFLICT(cve_id)
        DO UPDATE SET
        
            kev = 1,
            
            kev_date_added = 
                excluded.kev_date_added,
                
            kev_due_date =
                excluded.kev_due_date,
            
            ransomware_use = 
                excluded.ransomware_use,
                
            vendor = 
                excluded.vendor,
            
            product = 
                excluded.product,
            
            vulnerability_name = 
                excluded.vulnerability_name
        """, (
            
            cve,
            
            item.get("dataAdded"),
            item.get("dueDate"),
            
            item.get(
                "knownRansomwareCampaignUse"
            ),
            
            item.get("vendorProject"),
            item.get("product"),
            item.get(
                "vulnerabilityName"
            )
        ))
        
    conn.commit()
    conn.close()

    print("[+] KEV Load 완료")

if __name__ == "__main__":
    load_kev()    