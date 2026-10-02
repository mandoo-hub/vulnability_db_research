import requests

EPSS_URL =  "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

def download_epss():
    response = requests.get(EPSS_URL, timeout=60)
    response.raise_for_status()
    
    with open("data/epss.csv.gz", "wb") as f:
        f.write(response.content)
        
    print("[+] EPSS Download 완료")
    

if __name__ == "__main__":
    download_epss()