# 🛡️ Vulnerability Intelligence & CVE Mapping Pipeline

> NVD, EPSS, CISA KEV 등 외부 취약점 정보를 SQLite 기반 로컬 Vulnerability Database로 주기적으로 수집하고,  
> **`collect/collect.py`를 통해 내부 소프트웨어 및 라이브러리 정보를 식별한 뒤 `extract/cve_extract.py`를 이용하여 CVE와 매핑하는 프로젝트입니다.**

---

## 📌 Project Overview

운영환경의 취약점을 분석하기 위해서는 단순히 설치된 소프트웨어 목록을 수집하는 것만으로는 충분하지 않습니다.

실제 취약점 분석을 위해서는 다음과 같은 정보가 함께 필요합니다.

- 설치된 소프트웨어 및 라이브러리
- 패키지 및 버전 정보
- CVE 식별정보
- CVSS 기반 기술적 위험도
- EPSS 기반 악용 가능성
- CISA KEV 기반 실제 악용 여부

본 프로젝트에서는 외부 취약점 데이터를 매번 API로 조회하는 대신, **NVD, EPSS, CISA KEV 데이터를 SQLite에 사전 구축하고 주기적으로 갱신**합니다.

이후 대상 시스템에서 수집한 내부 라이브러리 및 패키지 정보를 CVE와 연결하여 취약점 분석에 활용합니다.

전체 분석 과정은 다음과 같습니다.

```text
External Vulnerability Sources
        │
        ├── NVD
        │    └── CVE / CVSS
        │
        ├── FIRST EPSS
        │    └── Exploitation Probability
        │
        └── CISA KEV
             └── Known Exploited Vulnerabilities
                    │
                    ▼
             SQLite Database
             vulnerability.db
                    │
                    ▼
           Internal Environment
                    │
                    ▼
          collect/collect.py
                    │
                    ├── Packages
                    ├── Libraries
                    ├── Versions
                    └── Software Metadata
                    │
                    ▼
          extract/cve_extract.py
                    │
                    ▼
               CVE Mapping
                    │
                    ▼
        Vulnerability Enrichment
                    │
                    ├── CVSS
                    ├── EPSS
                    └── KEV
                    │
                    ▼
          Vulnerability Analysis
```

---

## 🗄️ 1. Vulnerability Database

외부 취약점 데이터를 매번 실시간으로 조회하는 대신, 로컬 SQLite에 취약점 정보를 통합하여 관리합니다.

기본 데이터베이스는 다음과 같습니다.

```text
vulnability.db
```

주요 테이블은 다음과 같습니다.

```text
vulnerabilities
```

각 CVE는 `cve_id`를 Primary Key로 관리합니다.

예시:

```sql
CREATE TABLE vulnerabilities (
    cve_id TEXT PRIMARY KEY,

    cvss_score REAL,
    cvss_severity TEXT,
    cvss_version TEXT,
    cvss_vector TEXT,

    epss_score REAL,
    epss_percentile REAL,

    kev INTEGER DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    ransomware_use TEXT,

    vendor TEXT,
    product TEXT,
    vulnerability_name TEXT,

    description TEXT,

    published TEXT,
    last_modified TEXT
);
```

하나의 CVE에 대해 다음과 같은 정보를 통합 조회할 수 있습니다.

```text
CVE
 │
 ├── CVSS
 │    ├── Score
 │    ├── Severity
 │    ├── Version
 │    └── Vector
 │
 ├── EPSS
 │    ├── Score
 │    └── Percentile
 │
 ├── CISA KEV
 │    ├── KEV 여부
 │    ├── Date Added
 │    ├── Due Date
 │    └── Ransomware Use
 │
 └── Metadata
      ├── Vendor
      ├── Product
      ├── Description
      ├── Published
      └── Last Modified
```

---

## 🔎 2. NVD / CVSS Collection

NVD CVE API를 이용하여 CVE 및 CVSS 정보를 수집합니다.

사용 API:

```text
https://services.nvd.nist.gov/rest/json/cves/2.0
```

수집하는 주요 정보는 다음과 같습니다.

```text
CVE ID
CVSS Score
CVSS Severity
CVSS Version
CVSS Vector
Description
Published Date
Last Modified Date
```

CVSS는 다음 우선순위로 추출합니다.

```text
CVSS 4.0
   ↓
CVSS 3.1
   ↓
CVSS 3.0
   ↓
CVSS 2.0
```

예시:

```json
{
  "cve_id": "CVE-2021-44228",
  "cvss_score": 10.0,
  "cvss_severity": "CRITICAL",
  "cvss_version": "3.1",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
}
```

---

## 🔄 3. NVD Incremental Update

최초 SQLite 구축 이후에는 전체 CVE를 매번 다시 수집하지 않습니다.

NVD API의 다음 파라미터를 사용하여 **마지막 정상 동기화 이후 변경된 CVE만 증분 업데이트**합니다.

```text
lastModStartDate
lastModEndDate
```

전체 흐름은 다음과 같습니다.

```text
sync_state
    │
    ▼
Previous last_sync
    │
    ▼
lastModStartDate
    │
    ├──────────────┐
    │              │
    │        Current UTC Time
    │              │
    │              ▼
    │       lastModEndDate
    │              │
    └───────┬──────┘
            ▼
         NVD API
            │
            ▼
 Modified / New CVEs
            │
            ▼
      SQLite UPSERT
            │
            ▼
   Successful Completion
            │
            ▼
   Update sync_state
```

동기화 상태는 별도 테이블에서 관리합니다.

예시:

```sql
CREATE TABLE sync_state (
    source TEXT PRIMARY KEY,
    last_sync TEXT,
    last_error TEXT,
    status TEXT,
    retry_count INTEGER DEFAULT 0
);
```

예시 데이터:

```text
source | last_sync                    | status
-------|------------------------------|--------
nvd    | 2026-10-20T06:06:54.000Z    | success
```

다음 실행에서는 저장된 `last_sync`를 자동으로 읽습니다.

```text
Previous Sync
2026-10-20T06:06:54.000Z

        ↓

Next Execution
2026-10-25T03:10:21.000Z

        ↓

Update Range
2026-10-20T06:06:54.000Z
        ~
2026-10-25T03:10:21.000Z
```

따라서 날짜를 코드에 직접 수정하지 않고 반복적으로 증분 업데이트할 수 있습니다.

---

## 📈 4. EPSS Collection

EPSS는 FIRST에서 제공하는 최신 데이터를 이용합니다.

EPSS는 CVE가 실제 환경에서 악용될 가능성을 확률 기반으로 나타내는 지표입니다.

수집 데이터:

```text
CVE ID
EPSS Score
EPSS Percentile
```

전체 처리 구조는 다음과 같습니다.

```text
FIRST EPSS
    │
    ▼
epss_scores-current.csv.gz
    │
    ▼
Decompression
    │
    ▼
CSV Parsing
    │
    ▼
CVE ID Matching
    │
    ▼
SQLite UPSERT
```

예시:

```text
CVE-2021-44228

EPSS Score      : 0.94
EPSS Percentile : 0.99
```

SQLite에서는 `cve_id`를 기준으로 기존 CVE 정보를 갱신합니다.

```sql
ON CONFLICT(cve_id)
DO UPDATE SET
    epss_score = excluded.epss_score,
    epss_percentile = excluded.epss_percentile;
```

EPSS는 지속적으로 값이 변경될 수 있기 때문에 최신 EPSS 파일을 기준으로 주기적으로 갱신합니다.

---

## 🚨 5. CISA KEV Collection

CISA의 Known Exploited Vulnerabilities Catalog를 이용하여 실제 악용이 확인된 CVE를 식별합니다.

수집 정보는 다음과 같습니다.

```text
CVE ID
KEV Flag
Date Added
Due Date
Known Ransomware Campaign Use
Vendor
Product
Vulnerability Name
```

전체 흐름은 다음과 같습니다.

```text
CISA KEV
    │
    ▼
known_exploited_vulnerabilities.json
    │
    ▼
JSON Parsing
    │
    ▼
Existing KEV Flag Reset
    │
    ▼
Current KEV Mapping
    │
    ▼
kev = 1
```

KEV에 포함된 CVE는 다음과 같이 식별할 수 있습니다.

```text
kev = 1
```

KEV 목록은 최신 Catalog 기준으로 다시 반영합니다.

```text
Previous KEV State
      │
      ▼
   kev = 0
      │
      ▼
Latest CISA KEV
      │
      ▼
Matching CVEs
      │
      ▼
   kev = 1
```

이를 통해 KEV 목록의 추가 또는 변경 상태를 최신 데이터에 맞춰 유지합니다.

---

## 🔗 6. Integrated Vulnerability Intelligence

CVSS, EPSS, KEV는 서로 다른 취약점 특성을 나타냅니다.

| Metric | Description |
|---|---|
| CVSS | 취약점의 기술적 심각도 |
| EPSS | 실제 악용 가능성 |
| KEV | 실제 악용이 확인된 취약점 여부 |

따라서 하나의 CVE에 대해 다음과 같이 통합적으로 분석할 수 있습니다.

```text
                 CVE
                  │
        ┌─────────┼─────────┐
        │         │         │
        ▼         ▼         ▼
      CVSS      EPSS       KEV
        │         │         │
        ▼         ▼         ▼
    Severity   Exploit   Confirmed
              Probability Exploitation
```

예를 들어:

```text
CVE              : CVE-2021-44228
CVSS             : 10.0
Severity         : CRITICAL
EPSS             : 0.94
EPSS Percentile  : 0.99
KEV              : 1
```

와 같은 형태로 위험정보를 통합할 수 있습니다.

---

## 🔍 7. Internal Software Collection

대상 시스템의 소프트웨어 및 라이브러리 정보는 다음 디렉터리에서 수집합니다.

```text
collect/
└── collect.py
```

`collect.py`에서는 내부 시스템에서 식별할 수 있는 소프트웨어 구성요소 정보를 수집합니다.

주요 수집 대상:

```text
Installed Packages
Libraries
Package Version
Architecture
Software Metadata
```

전체 흐름은 다음과 같습니다.

```text
Target System
     │
     ▼
collect.py
     │
     ├── Package Discovery
     ├── Library Discovery
     ├── Version Collection
     └── Metadata Collection
     │
     ▼
Software Inventory
```

수집된 데이터는 CVE 매핑 단계의 입력 데이터로 사용됩니다.

예시:

```json
{
  "name": "openssl",
  "version": "3.0.2",
  "architecture": "amd64"
}
```

또는:

```text
apache2
openssl
libssl
curl
nginx
python3
...
```

와 같이 현재 환경에 존재하는 소프트웨어 구성요소를 식별할 수 있습니다.

---

## 🧩 8. CVE Extraction & Mapping

수집된 내부 Software Inventory는 다음 스크립트에서 CVE 정보와 연결합니다.

```text
extract/
└── cve_extract.py
```

전체 흐름은 다음과 같습니다.

```text
collect.py
    │
    ▼
Software Inventory
    │
    ├── Name
    ├── Version
    └── Metadata
    │
    ▼
cve_extract.py
    │
    ▼
CVE Identification
    │
    ▼
vulnability.db
    │
    ├── CVSS
    ├── EPSS
    ├── KEV
    └── Description
    │
    ▼
Enriched Vulnerability Result
```

즉 CVE를 식별한 이후 SQLite를 이용하여 해당 CVE의 위험정보를 추가합니다.

예시:

```text
Component     : openssl
Version       : 3.0.2

CVE           : CVE-XXXX-XXXX
CVSS Score    : 9.8
Severity      : CRITICAL
EPSS Score    : 0.87
KEV           : 1
Description   : ...
```

이를 통해 단순 CVE 식별에서 끝나지 않고 취약점의 위험도를 함께 분석할 수 있습니다.

---

## 🔎 9. Vulnerability Query

SQLite에 구축된 취약점 정보는 직접 SQL을 이용하여 조회할 수 있습니다.

특정 CVE 조회:

```sql
SELECT *
FROM vulnerabilities
WHERE cve_id = 'CVE-2021-44228';
```

주요 위험정보만 조회:

```sql
SELECT
    cve_id,
    cvss_score,
    cvss_severity,
    epss_score,
    epss_percentile,
    kev,
    ransomware_use
FROM vulnerabilities
WHERE cve_id = 'CVE-2021-44228';
```

KEV 취약점 조회:

```sql
SELECT
    cve_id,
    cvss_score,
    epss_score,
    vendor,
    product
FROM vulnerabilities
WHERE kev = 1;
```

높은 EPSS Score를 가진 CVE 조회:

```sql
SELECT
    cve_id,
    cvss_score,
    epss_score,
    kev
FROM vulnerabilities
WHERE epss_score IS NOT NULL
ORDER BY epss_score DESC
LIMIT 20;
```

---

## 🛠️ 10. Tech Stack & Architecture

- **Language:** Python 3
- **Database:** SQLite
- **CVE / CVSS:** NIST NVD CVE API 2.0
- **Exploitation Probability:** FIRST EPSS
- **Known Exploitation:** CISA KEV
- **HTTP Client:** Python `requests`
- **Data Parsing:** JSON, CSV, GZIP
- **Software Collection:** Python-based Local Inventory
- **Data Mapping:** CVE-based SQLite Mapping
- **Data Format:** SQLite, JSON, CSV

전체 Architecture는 다음과 같습니다.

```text
┌───────────────────────────────┐
│ External Vulnerability Data   │
│                               │
│ NVD     EPSS     CISA KEV     │
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│ Vulnerability Data Collection │
│                               │
│ cvss_sqlite.py                │
│ epss_sqlite.py                │
│ kev_sqlite.py                 │
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│       vulnerability.db        │
│                               │
│ CVE / CVSS / EPSS / KEV      │
└──────────────┬────────────────┘
               │
               │
               │          ┌──────────────────────┐
               │          │   Target System      │
               │          └──────────┬───────────┘
               │                     │
               │                     ▼
               │              collect/collect.py
               │                     │
               │                     ▼
               │              Software Inventory
               │                     │
               └──────────┬──────────┘
                          ▼
                 extract/cve_extract.py
                          │
                          ▼
                     CVE Mapping
                          │
                          ▼
                 Vulnerability Result
```

---

## 📂 Project Structure

```text
.
├── collect/
│   └── collect.py                 # 내부 패키지 및 라이브러리 수집
│
├── extract/
│   └── cve_extract.py             # 수집 결과 기반 CVE 추출 및 매핑
│
├── data/
│   ├── epss.csv.gz                # 최신 EPSS 원본 데이터
│   └── kev.json                    # CISA KEV 원본 데이터
│
├── build_vuln_db.py               # SQLite 초기 Database 생성
├── cvss_sqlite.py                 # NVD / CVSS 수집 및 증분 업데이트
├── epss_sqlite.py                 # EPSS SQLite 갱신
├── kev_sqlite.py                  # CISA KEV SQLite 갱신
├── tmp_epss.py                    # EPSS 원본 데이터 다운로드
├── tmp_kev.py                     # KEV 원본 데이터 다운로드
│
├── vulnability.db                 # Vulnerability Intelligence Database
│
├── README.md
└── requirements.txt
```

---

## 🚀 Quick Start

### Step 1. SQLite Database 생성

```bash
python3 build_vuln_db.py
```

생성 결과:

```text
vulnability.db
```

---

### Step 2. NVD / CVSS 수집 및 업데이트

```bash
python3 cvss_sqlite.py
```

최초 구축 이후에는 `sync_state`의 마지막 성공 시각을 이용하여 변경된 CVE만 증분 업데이트합니다.

예시:

```text
[+] 이전 동기화: 2026-10-20T06:06:54.000Z
[+] 이번 동기화 기준: 2026-10-21T03:15:21.000Z
[+] NVD 증분 업데이트 2000/3248
[+] NVD 증분 업데이트 3248/3248
[+] NVD 증분 업데이트 완료
```

---

### Step 3. EPSS 다운로드

```bash
python3 tmp_epss.py
```

생성 결과:

```text
data/epss.csv.gz
```

SQLite 반영:

```bash
python3 epss_sqlite.py
```

---

### Step 4. CISA KEV 다운로드

```bash
python3 tmp_kev.py
```

생성 결과:

```text
data/kev.json
```

SQLite 반영:

```bash
python3 kev_sqlite.py
```

---

### Step 5. 내부 소프트웨어 및 라이브러리 수집

```bash
python3 collect/collect.py
```

수집 대상 시스템의 패키지, 라이브러리, 버전 및 관련 정보를 식별합니다.

---

### Step 6. CVE Extraction & Mapping

```bash
python3 extract/cve_extract.py
```

수집된 내부 구성요소와 CVE를 연결하고 SQLite에 저장된 CVSS, EPSS, KEV 정보를 추가합니다.

---

## 🔄 Periodic Update Flow

취약점 정보는 지속적으로 변경되기 때문에 SQLite를 주기적으로 갱신할 수 있습니다.

권장 흐름은 다음과 같습니다.

```text
Periodic Update
      │
      ├── NVD
      │     └── Incremental Update
      │
      ├── EPSS
      │     └── Latest Dataset Refresh
      │
      └── CISA KEV
            └── Latest Catalog Refresh
```

NVD의 경우:

```text
Last Successful Sync
        │
        ▼
Modified CVEs Only
        │
        ▼
SQLite UPSERT
        │
        ▼
Update last_sync
```

EPSS 및 KEV는 최신 Dataset을 기준으로 갱신합니다.

이를 통해 전체 데이터베이스를 매번 새로 구축하지 않고 지속적으로 최신 취약점 정보를 유지할 수 있습니다.

---

## 📊 Vulnerability Enrichment Result

최종 분석 결과에서는 내부 구성요소와 취약점 Intelligence를 함께 확인할 수 있습니다.

예시:

| Component | Version | CVE | CVSS | EPSS | KEV |
|---|---|---|---:|---:|---:|
| openssl | 3.0.2 | CVE-XXXX-XXXX | 9.8 | 0.91 | 1 |
| curl | 7.x | CVE-XXXX-XXXX | 8.1 | 0.63 | 0 |
| apache2 | 2.4.x | CVE-XXXX-XXXX | 7.5 | 0.42 | 0 |

이를 통해 단순 CVE 개수뿐만 아니라 각 취약점의 기술적 심각도와 실제 악용 가능성을 함께 분석할 수 있습니다.

---

## 🔍 Risk Interpretation

본 프로젝트에서는 취약점을 다음 세 관점으로 구분하여 분석합니다.

### CVSS

```text
"해당 취약점 자체가 얼마나 심각한가?"
```

기술적 Impact 및 Exploitability를 기반으로 취약점의 심각도를 나타냅니다.

### EPSS

```text
"해당 취약점이 실제로 악용될 가능성은 얼마나 높은가?"
```

취약점이 향후 실제 공격에 활용될 가능성을 확률 기반으로 나타냅니다.

### CISA KEV

```text
"해당 취약점이 실제 공격에서 악용된 사실이 있는가?"
```

실제 악용 사실이 확인된 취약점을 식별합니다.

따라서 다음과 같이 상호 보완적으로 활용할 수 있습니다.

```text
Technical Severity
       │
       ▼
     CVSS
       │
       ├────────────┐
       │            │
       ▼            ▼
     EPSS          KEV
       │            │
       ▼            ▼
Exploitability   Confirmed
 Probability     Exploitation
```

---

## ⚠️ Current Limitations

현재 구현은 내부 소프트웨어 및 라이브러리를 식별한 뒤 CVE 정보를 매핑하기 위한 기본 Vulnerability Intelligence Pipeline을 구현한 단계입니다.

CVE가 특정 패키지와 연결되었다고 해서 해당 시스템이 반드시 실제 취약한 상태라고 단정할 수는 없습니다.

실제 취약 여부를 판단하기 위해서는 다음 정보가 추가적으로 고려되어야 합니다.

- Package Version
- Distribution Version
- Vendor Patch
- Security Backport
- Package Build Revision
- Runtime Configuration
- Feature Enablement
- 실제 취약 코드 사용 여부

특히 Ubuntu, Debian, RHEL 등의 Linux 배포판에서는 상위 버전으로 변경하지 않고 보안 패치를 Backport하는 경우가 있기 때문에 단순 Version String 비교만으로 취약 여부를 판단할 경우 False Positive가 발생할 수 있습니다.

또한 CVSS, EPSS, KEV는 서로 다른 목적의 지표이므로 하나의 값만을 기준으로 취약점 조치 우선순위를 결정하는 것은 적절하지 않을 수 있습니다.

---

## 🚧 Future Work

향후 다음 기능을 확장할 예정입니다.

- CPE 기반 Software ↔ CVE 정규화
- PURL 기반 Component 식별
- OSV 데이터 연계
- Linux Distribution Security Advisory 연계
- Ubuntu USN / Debian DSA / Red Hat RHSA 연계
- Backport Patch 판별
- CVSS + EPSS + KEV 기반 Risk Prioritization
- 자동 Scheduler 기반 Vulnerability DB 갱신
- Software Inventory 자동 재수집
- CVE Mapping 결과 JSON / CSV Export
- SBOM / OBOM 연계
- Dependency Graph 기반 취약점 영향범위 분석
- Patch Impact Score 연계
- Graph-based Vulnerability Analysis
- Vulnerability Dashboard 구축

향후 SBOM 및 Dependency Graph 분석과 결합하면 다음과 같은 구조로 확장할 수 있습니다.

```text
Vulnerability Intelligence
           │
           ▼
    CVE Risk Information
           │
           │
Software Inventory
           │
           ▼
       CVE Mapping
           │
           ▼
Dependency Graph
           │
           ▼
Structural Impact Analysis
           │
           ▼
Patch Prioritization
```

---

## 📚 Research Purpose

본 프로젝트의 목적은 CVSS, EPSS, KEV 등 외부 취약점 정보를 단순히 수집하는 것에 있지 않습니다.

외부 Vulnerability Intelligence를 로컬 SQLite에 지속적으로 축적하고, 실제 시스템에서 식별한 소프트웨어 구성요소와 연결함으로써 다음 질문에 대응하는 것을 목표로 합니다.

> **"현재 운영환경에 어떤 취약점이 존재할 가능성이 있으며, 해당 취약점의 기술적 위험도와 실제 악용 가능성은 어느 정도인가?"**

기존 단순 Software Inventory가 다음 질문을 다룬다면,

> **"현재 시스템에 어떤 소프트웨어가 설치되어 있는가?"**

본 프로젝트에서는 이를 다음 단계로 확장합니다.

```text
Software Inventory
        │
        ▼
CVE Identification
        │
        ▼
Vulnerability Intelligence
        │
        ├── CVSS
        ├── EPSS
        └── KEV
        │
        ▼
Risk Context
```

이를 통해 반복적인 취약점 점검 과정에서 외부 API에 대한 의존성을 줄이고, 로컬 Vulnerability Database를 활용하여 빠르게 취약점 정보를 매핑할 수 있는 분석 기반을 구축하는 것을 목표로 합니다.

또한 향후 SBOM, Dependency Graph 및 Patch Impact 분석과 결합하여 단순 취약점 식별을 넘어 **취약점 위험도와 소프트웨어 구조적 영향도를 함께 고려하는 분석 체계**로 확장하는 것을 목표로 합니다.
