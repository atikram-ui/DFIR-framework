import sqlite3, requests, json, time, os, re
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "dfir.db")
KEYS_PATH = os.path.join(BASE_DIR, "config", "api_keys.json")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def load_api_keys():
    if not os.path.exists(KEYS_PATH):
        return {"abuseipdb_key": "", "virustotal_key": ""}
    with open(KEYS_PATH) as f:
        keys = json.load(f)
    for k, v in keys.items():
        if "YOUR_" in str(v) or str(v).strip() == "":
            keys[k] = ""
    return keys

def is_valid_ip(v):
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v))

def is_valid_domain(v):
    return bool(re.match(r'^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', v))

def ensure_ti_table():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS ti_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_value TEXT NOT NULL,
        ioc_type TEXT NOT NULL,
        source TEXT NOT NULL,
        abuse_score INTEGER DEFAULT 0,
        total_reports INTEGER DEFAULT 0,
        country_code TEXT DEFAULT "",
        domain TEXT DEFAULT "",
        vt_malicious INTEGER DEFAULT 0,
        vt_suspicious INTEGER DEFAULT 0,
        vt_harmless INTEGER DEFAULT 0,
        vt_undetected INTEGER DEFAULT 0,
        threat_label TEXT DEFAULT "UNKNOWN",
        severity TEXT DEFAULT "LOW",
        raw_response TEXT DEFAULT "",
        enriched_at TEXT NOT NULL,
        UNIQUE(ioc_value, source)
    )''')
    conn.commit()
    conn.close()
    print("[+] ti_results table ready.")

def calculate_severity(abuse_score=0, vt_malicious=0):
    if abuse_score >= 75 or vt_malicious >= 10:
        return "CRITICAL"
    elif abuse_score >= 40 or vt_malicious >= 5:
        return "HIGH"
    elif abuse_score >= 15 or vt_malicious >= 1:
        return "MEDIUM"
    return "LOW"

def mock_abuseipdb(ip):
    bad = {
        "192.168.1.100": (85, 42, "CN", "malicious-host.cn"),
        "10.0.0.50":     (60, 15, "RU", "suspicious.ru"),
        "172.16.0.1":    (20,  3, "US", "isp.net"),
    }
    if ip in bad:
        s, r, c, d = bad[ip]
    else:
        import random
        s, r, c, d = random.randint(0,10), random.randint(0,2), "US", "unknown.net"
    return {"abuse_score": s, "total_reports": r, "country_code": c, "domain": d, "raw": "{}"}

def mock_virustotal(value):
    bad = ["192.168.1.100", "malware.cn", "10.0.0.50", "evil-c2.ru"]
    if value in bad:
        return {"vt_malicious": 12, "vt_suspicious": 3, "vt_harmless": 1,
                "vt_undetected": 20, "threat_label": "trojan.generic", "raw": "{}"}
    return {"vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 50,
            "vt_undetected": 5, "threat_label": "clean", "raw": "{}"}

def query_abuseipdb(ip, api_key):
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {"abuse_score": d.get("abuseConfidenceScore", 0),
                    "total_reports": d.get("totalReports", 0),
                    "country_code": d.get("countryCode", ""),
                    "domain": d.get("domain", ""),
                    "raw": json.dumps(d)}
    except Exception as e:
        print(f"    [!] AbuseIPDB error: {e}")
    return None

def query_virustotal_ip(ip, api_key):
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10
        )
        if resp.status_code == 200:
            s = resp.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            return {"vt_malicious": s.get("malicious",0),
                    "vt_suspicious": s.get("suspicious",0),
                    "vt_harmless": s.get("harmless",0),
                    "vt_undetected": s.get("undetected",0),
                    "threat_label": "malicious" if s.get("malicious",0) > 0 else "clean",
                    "raw": json.dumps(s)}
    except Exception as e:
        print(f"    [!] VT error: {e}")
    return None

def query_virustotal_domain(domain, api_key):
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=10
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data",{}).get("attributes",{})
            s = attrs.get("last_analysis_stats",{})
            return {"vt_malicious": s.get("malicious",0),
                    "vt_suspicious": s.get("suspicious",0),
                    "vt_harmless": s.get("harmless",0),
                    "vt_undetected": s.get("undetected",0),
                    "threat_label": attrs.get("popular_threat_classification",{}).get("suggested_threat_label","unknown"),
                    "raw": json.dumps(s)}
    except Exception as e:
        print(f"    [!] VT domain error: {e}")
    return None

def store_ti_result(ioc_value, ioc_type, source, abuse_data, vt_data):
    a  = abuse_data or {}
    v  = vt_data   or {}
    sev = calculate_severity(a.get("abuse_score",0), v.get("vt_malicious",0))
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        conn.execute('''INSERT INTO ti_results
            (ioc_value,ioc_type,source,abuse_score,total_reports,country_code,
             domain,vt_malicious,vt_suspicious,vt_harmless,vt_undetected,
             threat_label,severity,raw_response,enriched_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ioc_value,source) DO UPDATE SET
            abuse_score=excluded.abuse_score, vt_malicious=excluded.vt_malicious,
            threat_label=excluded.threat_label, severity=excluded.severity,
            enriched_at=excluded.enriched_at''',
            (ioc_value, ioc_type, source,
             a.get("abuse_score",0), a.get("total_reports",0),
             a.get("country_code",""), a.get("domain",""),
             v.get("vt_malicious",0), v.get("vt_suspicious",0),
             v.get("vt_harmless",0), v.get("vt_undetected",0),
             v.get("threat_label","UNKNOWN"), sev,
             json.dumps({"a": a.get("raw","{}"), "v": v.get("raw","{}")}), ts))
        conn.commit()
    except Exception as e:
        print(f"    [!] DB error: {e}")
    finally:
        conn.close()
    return sev

def create_ti_alert(ioc_value, severity, source, abuse_score, vt_malicious):
    if severity not in ("MEDIUM","HIGH","CRITICAL"):
        return
    msg = (f"[TI] {ioc_value} flagged {severity} | "
           f"AbuseIPDB={abuse_score}% | VT={vt_malicious} detections")
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO alerts (timestamp,alert_type,source,description,severity) VALUES (?,?,?,?,?)',
            (ts, "THREAT_INTEL", ioc_value, msg, severity))
        conn.commit()
        print(f"    [ALERT] {severity} alert created for {ioc_value}")
    except Exception as e:
        print(f"    [!] Alert error: {e}")
    finally:
        conn.close()

def print_ti_summary():
    conn  = get_db()
    rows  = conn.execute('''SELECT ioc_value,ioc_type,abuse_score,vt_malicious,
                            threat_label,severity FROM ti_results
                            ORDER BY CASE severity
                            WHEN "CRITICAL" THEN 1 WHEN "HIGH" THEN 2
                            WHEN "MEDIUM" THEN 3 ELSE 4 END''').fetchall()
    stats = conn.execute('''SELECT severity, COUNT(*) as cnt FROM ti_results
                            GROUP BY severity ORDER BY cnt DESC''').fetchall()
    conn.close()
    if not rows:
        print("[!] No TI results yet.")
        return
    print("\n" + "="*68)
    print(f"{'IOC VALUE':<22} {'TYPE':<8} {'ABUSE%':<8} {'VT_MAL':<8} {'LABEL':<16} SEVERITY")
    print("-"*68)
    for r in rows:
        print(f"{r['ioc_value']:<22} {r['ioc_type']:<8} {r['abuse_score']:<8} "
              f"{r['vt_malicious']:<8} {str(r['threat_label'])[:14]:<16} {r['severity']}")
    print("="*68)
    print("\nSeverity Breakdown:")
    for s in stats:
        bar = chr(9608) * min(s['cnt'] * 4, 32)
        print(f"  {s['severity']:<10} {bar} ({s['cnt']})")

def enrich_all_iocs(mock_mode=False):
    ensure_ti_table()
    keys      = load_api_keys()
    abuse_key = keys.get("abuseipdb_key","")
    vt_key    = keys.get("virustotal_key","")
    if not abuse_key and not vt_key:
        mock_mode = True
        print("[*] No API keys — MOCK mode.\n")
    else:
        print(f"[*] Keys loaded | AbuseIPDB={'SET' if abuse_key else 'MISSING'} | VT={'SET' if vt_key else 'MISSING'}\n")
    conn = get_db()
    rows = conn.execute("SELECT DISTINCT value, type, source FROM iocs").fetchall()
    conn.close()
    if not rows:
        print("[!] No IOCs found. Run Phase 8 first.")
        return
    print(f"[*] Enriching {len(rows)} IOC(s)...\n")
    enriched = skipped = 0
    for row in rows:
        val  = row["value"]
        typ  = row["type"]
        src  = row["source"]
        if typ == "ip" and not is_valid_ip(val):
            skipped += 1; continue
        if typ == "domain" and not is_valid_domain(val):
            skipped += 1; continue
        if typ not in ("ip","domain"):
            skipped += 1; continue
        print(f"  -> [{typ.upper()}] {val}")
        abuse_data = None
        if typ == "ip":
            if mock_mode or not abuse_key:
                abuse_data = mock_abuseipdb(val)
            else:
                abuse_data = query_abuseipdb(val, abuse_key)
                time.sleep(0.5)
            if abuse_data:
                print(f"     AbuseIPDB: score={abuse_data['abuse_score']}%  country={abuse_data['country_code']}")
        vt_data = None
        if mock_mode or not vt_key:
            vt_data = mock_virustotal(val)
        else:
            vt_data = query_virustotal_ip(val, vt_key) if typ=="ip" else query_virustotal_domain(val, vt_key)
            time.sleep(15)
        if vt_data:
            print(f"     VirusTotal: malicious={vt_data['vt_malicious']}  label={vt_data['threat_label']}")
        sev  = store_ti_result(val, typ, src, abuse_data, vt_data)
        a_sc = abuse_data["abuse_score"]  if abuse_data else 0
        v_sc = vt_data["vt_malicious"]    if vt_data    else 0
        create_ti_alert(val, sev, src, a_sc, v_sc)
        print(f"     Severity -> {sev}\n")
        enriched += 1
    print("-"*55)
    print(f"[+] Done: {enriched} enriched | {skipped} skipped")
    print_ti_summary()
