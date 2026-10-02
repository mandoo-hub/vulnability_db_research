import requests

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

def download_kev():
    
    response = requests.get(
        KEV_URL,
        timeout=60
    )
    
    response.raise_for_status()
    
    with open(
        "data/kev.json", "wb"
    ) as f:
        
        f.write(response.content)
        
        print("[+] kev download 완료")

if __name__ == "__main__":
    download_kev()
    
    