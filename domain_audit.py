import streamlit as st
import pandas as pd
import dns.resolver
import requests
import ssl
import socket
import concurrent.futures
import time
import random
import re
import os
import json
import sqlite3
from datetime import datetime
from OpenSSL import crypto
import urllib3

# 關閉 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 設定頁面標題
st.set_page_config(page_title="Andy的全能網管工具 (陸軍 v14優化版)", layout="wide")

# ==========================================
#  載入設定檔 (特徵庫)
# ==========================================
def load_config():
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        st.error("找不到 config.json，請確認檔案存在。")
        st.stop()

sys_config = load_config()
CDN_SIGS = sys_config.get("cdn_sigs", {})
CLOUD_SIGS = sys_config.get("cloud_sigs", {})

# 全域 IP 快取，減少重複打 GeoIP API
ip_geo_cache = {}

# ==========================================
#  資料庫 (SQLite) 核心模組 (優化：支援批次寫入)
# ==========================================
DB_FILE = "audit_data.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS domain_audit (
            domain TEXT PRIMARY KEY,
            cdn_provider TEXT, cloud_hosting TEXT, multi_ip TEXT, cname TEXT, ips TEXT,
            country TEXT, city TEXT, isp TEXT, tls_1_3 TEXT, protocol TEXT, issuer TEXT,
            ssl_days TEXT, global_ping TEXT, simple_ping TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_reverse (
            input_ip TEXT, domain TEXT, current_resolved_ip TEXT, ip_match TEXT, http_status TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (input_ip, domain)
        )
    ''')
    conn.commit()
    conn.close()

def get_existing_domains():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("SELECT domain FROM domain_audit")
        return set([r[0] for r in c.fetchall()])
    except: return set()
    finally: conn.close()

# 優化：批次寫入 Domain 結果
def save_domain_results_batch(data_list):
    if not data_list: return
    conn = sqlite3.connect(DB_FILE, timeout=30)
    c = conn.cursor()
    try:
        records = [
            (d['Domain'], d['CDN Provider'], d['Cloud/Hosting'], d['Multi-IP'],
             d['CNAME'], d['IPs'], d['Country'], d['City'], d['ISP'],
             d['TLS 1.3'], d['Protocol'], d['Issuer'], str(d['SSL Days']),
             d['Global Ping'], d['Simple Ping']) for d in data_list
        ]
        c.executemany('''
            INSERT OR REPLACE INTO domain_audit (
                domain, cdn_provider, cloud_hosting, multi_ip, cname, ips, 
                country, city, isp, tls_1_3, protocol, issuer, ssl_days, 
                global_ping, simple_ping
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', records)
        conn.commit()
    except Exception as e: print(f"DB Error: {e}")
    finally: conn.close()

def get_all_domain_results():
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query("SELECT * FROM domain_audit", conn)
        df = df.rename(columns={
            "domain": "Domain", "cdn_provider": "CDN Provider", "cloud_hosting": "Cloud/Hosting",
            "multi_ip": "Multi-IP", "cname": "CNAME", "ips": "IPs", "country": "Country", 
            "city": "City", "isp": "ISP", "tls_1_3": "TLS 1.3", "protocol": "Protocol", 
            "issuer": "Issuer", "ssl_days": "SSL Days", "global_ping": "Global Ping", 
            "simple_ping": "Simple Ping"
        })
        if "updated_at" in df.columns: df = df.drop(columns=["updated_at"])
        return df
    finally: conn.close()

# 優化：批次寫入 IP 結果
def save_ip_results_batch(data_list):
    if not data_list: return
    conn = sqlite3.connect(DB_FILE, timeout=30)
    c = conn.cursor()
    try:
        records = [
            (d['Input_IP'], d['Domain'], d['Current_Resolved_IP'], d['IP_Match'], d['HTTP_Status']) 
            for d in data_list
        ]
        c.executemany('''
            INSERT OR REPLACE INTO ip_reverse (
                input_ip, domain, current_resolved_ip, ip_match, http_status
            ) VALUES (?, ?, ?, ?, ?)
        ''', records)
        conn.commit()
    except Exception as e: print(f"DB Error: {e}")
    finally: conn.close()

def get_all_ip_results():
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query("SELECT * FROM ip_reverse", conn)
        df = df.rename(columns={
            "input_ip": "Input_IP", "domain": "Domain", 
            "current_resolved_ip": "Current_Resolved_IP", 
            "ip_match": "IP_Match", "http_status": "HTTP_Status"
        })
        if "updated_at" in df.columns: df = df.drop(columns=["updated_at"])
        return df
    finally: conn.close()

def clear_database():
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
        except PermissionError:
            pass # 避免檔案鎖定時崩潰
    init_db()

init_db()

# ==========================================
#  共用輔助函式
# ==========================================

def get_dns_resolver():
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1'] 
    resolver.timeout = 5
    resolver.lifetime = 5
    return resolver

def parse_input_raw(raw_text):
    processed_text = re.sub(r'(\.[a-z]{2,5})(www\.|http)', r'\1\n\2', raw_text, flags=re.IGNORECASE)
    processed_text = processed_text.replace('https://', '\nhttps://').replace('http://', '\nhttp://')
    processed_text = processed_text.replace('未找到', '\n未找到\n')
    tokens = re.split(r'[\s,;]+', processed_text)
    final_items = []
    for token in tokens:
        token = token.strip()
        if not token: continue 
        clean = token.replace('https://', '').replace('http://', '')
        clean = clean.split('/')[0].split('?')[0].split(':')[0]
        clean = re.sub(r'^[^a-zA-Z0-9\u4e00-\u9fa5\.]+|[^a-zA-Z0-9\u4e00-\u9fa5]+$', '', clean)
        if clean: final_items.append(clean)
    return list(dict.fromkeys(final_items)) # 移除重複輸入

# ==========================================
#  核心檢測邏輯 
# ==========================================

def detect_providers(cname_record, isp_name):
    cname = cname_record.lower()
    isp = isp_name.lower() 
    cdns = []
    clouds = []
    
    # 判斷 CDN
    for provider, keywords in CDN_SIGS.items():
        if any(kw in cname for kw in keywords) or any(kw in isp for kw in keywords):
            if f"⚡ {provider}" not in cdns:
                cdns.append(f"⚡ {provider}")

    # 判斷 Cloud
    for provider, keywords in CLOUD_SIGS.items():
        # 防呆機制
        if provider == "AWS" and any("CloudFront" in c for c in cdns): continue
        if provider == "Azure" and any("FrontDoor" in c for c in cdns): continue
        if provider == "Alibaba Cloud" and any("Alibaba CDN" in c for c in cdns): continue
        if provider == "Tencent Cloud" and any("Tencent CDN" in c for c in cdns): continue
            
        if any(kw in cname for kw in keywords) or any(kw in isp for kw in keywords):
            if f"☁️ {provider}" not in clouds:
                clouds.append(f"☁️ {provider}")

    return " + ".join(cdns) if cdns else "-", " + ".join(clouds) if clouds else "-"

def run_globalping_api(domain):
    url = "https://api.globalping.io/v1/measurements"
    headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    payload = {"limit": 2, "locations": [], "target": domain, "type": "http", "measurementOptions": {"protocol": "HTTPS"}}
    for attempt in range(3):
        try:
            time.sleep(random.uniform(2.0, 4.0) + attempt)
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            if resp.status_code == 202:
                ms_id = resp.json()['id']
                for _ in range(10):
                    time.sleep(1)
                    res_resp = requests.get(f"{url}/{ms_id}", headers=headers, timeout=5)
                    if res_resp.status_code == 200:
                        data = res_resp.json()
                        if data['status'] == 'finished':
                            results = data['results']
                            success_count = sum(1 for r in results if r['result']['status'] == 'finished' and str(r['result']['rawOutput']).startswith('HTTP'))
                            return f"{success_count}/{len(results)} OK"
                return "Timeout"
            elif resp.status_code == 429:
                time.sleep(5) 
                continue
            elif resp.status_code == 400: return "Invalid Domain"
            else:
                if attempt == 2: return f"Err {resp.status_code}"
        except requests.exceptions.RequestException:
            time.sleep(1)
    return "Too Busy"

def run_simple_ping(domain):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        resp = requests.get(f"https://{domain}", timeout=5, headers=headers, verify=False)
        return f"✅ {resp.status_code}"
    except requests.exceptions.Timeout:
        return "⏳ Timeout"
    except requests.exceptions.ConnectionError:
        try:
            resp = requests.get(f"http://{domain}", timeout=5, headers=headers)
            return f"⚠️ {resp.status_code} (HTTP)"
        except: return "❌ Fail"
    except Exception:
        return "❌ Error"

def process_domain_audit(args):
    index, domain, config = args
    result = {
        "Domain": domain, "CDN Provider": "-", "Cloud/Hosting": "-", "Multi-IP": "-",
        "CNAME": "-", "IPs": "-", "Country": "-", "City": "-", "ISP": "-",
        "TLS 1.3": "-", "Protocol": "-", "Issuer": "-", "SSL Days": "-", 
        "Global Ping": "-", "Simple Ping": "-"
    }
    if "未找到" in domain:
        result["IPs"] = "❌ Source Not Found"
        return (index, result)
    if '.' not in domain or len(domain) < 3:
        result["IPs"] = "❌ Format Error"
        return (index, result)

    try:
        if config['dns']:
            resolver = get_dns_resolver()
            try:
                cname_ans = resolver.resolve(domain, 'CNAME')
                result["CNAME"] = str(cname_ans[0].target).rstrip('.')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            ip_list = []
            try:
                a_ans = resolver.resolve(domain, 'A')
                ip_list = [str(r.address) for r in a_ans]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                try:
                    ais = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
                    ip_list = list(set([ai[4][0] for ai in ais]))
                except socket.gaierror:
                    pass

            if ip_list:
                result["IPs"] = ", ".join(ip_list)
                if len(ip_list) > 1: result["Multi-IP"] = f"✅ Yes ({len(ip_list)})"
                
                if config['geoip']:
                    first_ip = ip_list[0]
                    if not first_ip.endswith('.'):
                        # 快取機制：如果這個 IP 查過了，就直接拿來用
                        if first_ip in ip_geo_cache:
                            resp = ip_geo_cache[first_ip]
                        else:
                            resp = {}
                            for attempt in range(3):
                                try:
                                    time.sleep(random.uniform(0.5, 1.0))
                                    resp = requests.get(f"http://ip-api.com/json/{first_ip}?fields=country,city,isp,org,status", timeout=5).json()
                                    if resp.get("status") == "success":
                                        ip_geo_cache[first_ip] = resp
                                        break
                                except: time.sleep(1)
                        
                        if resp.get("status") == "success":
                            result["Country"] = resp.get("country", "-")
                            result["City"] = resp.get("city", "-")
                            isp_val = resp.get("isp", "")
                            org_val = resp.get("org", "")
                            if isp_val and org_val and isp_val != org_val:
                                result["ISP"] = f"{isp_val} ({org_val})"
                            else:
                                result["ISP"] = org_val or isp_val or "-"

                cdn, cloud = detect_providers(result["CNAME"], result["ISP"])
                result["CDN Provider"] = cdn
                result["Cloud/Hosting"] = cloud
            else: result["IPs"] = "No Record"

        if config['ssl']:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = None
            try:
                sock = socket.create_connection((domain, 443), timeout=5)
                conn = ctx.wrap_socket(sock, server_hostname=domain)
                result["Protocol"] = conn.version()
                result["TLS 1.3"] = "✅ Yes" if conn.version() == 'TLSv1.3' else "❌ No"
                
                cert_data = conn.getpeercert(binary_form=True)
                if cert_data:
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
                    issuer_obj = cert.get_issuer()
                    result["Issuer"] = issuer_obj.O if issuer_obj.O else (issuer_obj.CN if issuer_obj.CN else "Unknown")
                    not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    result["SSL Days"] = (not_after - datetime.now()).days
            except socket.timeout:
                result["Protocol"] = "Timeout"
            except ssl.SSLError:
                result["Protocol"] = "SSL Error"
            except Exception:
                result["Protocol"] = "Connect Fail"
            finally:
                if conn: conn.close()

        if config['global_ping']: result["Global Ping"] = run_globalping_api(domain)
        if config['simple_ping']: result["Simple Ping"] = run_simple_ping(domain)

    except Exception as e: result["IPs"] = f"Error: {str(e)}"
    return (index, result)

def check_single_domain_status(domain, target_ip):
    resolver = get_dns_resolver()
    status_result = {"Domain": domain, "Current_Resolved_IP": "-", "IP_Match": "-", "HTTP_Status": "-"}
    current_ips = []
    try:
        a_ans = resolver.resolve(domain, 'A')
        current_ips = [str(r.address) for r in a_ans]
        status_result["Current_Resolved_IP"] = ", ".join(current_ips)
    except: status_result["Current_Resolved_IP"] = "No DNS Record"
    
    if current_ips:
        if target_ip in current_ips: status_result["IP_Match"] = "✅ Yes"
        else: status_result["IP_Match"] = "❌ No"
        headers = {"User-Agent": "Mozilla/5.0"}
        try:
            resp = requests.get(f"https://{domain}", timeout=5, headers=headers, verify=False)
            status_result["HTTP_Status"] = f"✅ {resp.status_code}"
        except:
            try:
                resp = requests.get(f"http://{domain}", timeout=5, headers=headers)
                status_result["HTTP_Status"] = f"⚠️ {resp.status_code} (HTTP)"
            except: status_result["HTTP_Status"] = "❌ Unreachable"
    else: status_result["HTTP_Status"] = "❌ DNS Fail"
    return status_result

def process_ip_vt_lookup(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
    headers = {"x-apikey": api_key}
    try:
        params = {"limit": 40}
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data:
                domains = list(set([item['attributes']['host_name'] for item in data['data']]))
                return "Success", domains
            return "Success", []
        elif resp.status_code == 429: return "RateLimit", []
        elif resp.status_code == 401: return "AuthError", []
        else: return f"Error {resp.status_code}", []
    except Exception as e: return f"Exception: {str(e)}", []


# ==========================================
#  UI 主程式
# ==========================================

# 初始化 Session State 以保留輸入
if "domain_input" not in st.session_state:
    st.session_state.domain_input = ""

with st.sidebar:
    st.header("🗄️ 資料庫管理")
    st.caption("所有資料均存於本地 SQLite，關閉程式不會遺失。")
    if st.button("🗑️ 清空資料庫 (重來)", type="secondary"):
        clear_database()
        st.toast("資料庫已清空！")
        time.sleep(1)
        st.rerun()
    st.divider()
    st.subheader("📥 匯出資料")
    df_domains = get_all_domain_results()
    if not df_domains.empty:
        st.download_button(f"📄 下載域名報告 ({len(df_domains)}筆)", df_domains.to_csv(index=False).encode('utf-8-sig'), "domain_audit_db.csv", "text/csv")
    else: st.write("域名資料庫為空")
    df_ips = get_all_ip_results()
    if not df_ips.empty:
        st.download_button(f"📄 下載 IP 反查報告 ({len(df_ips)}筆)", df_ips.to_csv(index=False).encode('utf-8-sig'), "ip_reverse_db.csv", "text/csv")
    else: st.write("IP 反查資料庫為空")

tab1, tab2 = st.tabs(["🌐 域名檢測", "🔍 IP 反查域名 (VT)"])

# --- 分頁 1: 域名檢測 ---
with tab1:
    st.header("Andy 的批量域名體檢工具 - 陸軍 v14 優化版")
    col1, col2 = st.columns([1, 3])
    with col1:
        st.subheader("1. 檢測項目")
        check_dns = st.checkbox("DNS 解析 (基礎)", value=True)
        check_geoip = st.checkbox("GeoIP 查詢 (國家/ISP)", value=True)
        check_ssl = st.checkbox("SSL & TLS 憑證", value=True)
        
        st.subheader("2. 連線測試")
        check_simple_ping = st.checkbox("Simple Ping (本機)", value=True)
        check_global_ping = st.checkbox("Global Ping (全球)", value=True)
        
        st.divider()
        st.subheader("3. 掃描速度")
        workers = st.slider("併發執行緒", 1, 10, 3)
        st.info("💡 優化版支援更高併發，但若 GeoIP 頻繁超限，建議維持 3-5。")

    with col2:
        raw_input = st.text_area("輸入域名 (會自動跳過已掃描項目)", height=150, value=st.session_state.domain_input)
        if st.button("🚀 開始掃描域名", type="primary"):
            st.session_state.domain_input = raw_input # 儲存當前輸入
            full_list = parse_input_raw(raw_input)
            existing_domains = get_existing_domains()
            domain_list = [d for d in full_list if d not in existing_domains]
            skipped_count = len(full_list) - len(domain_list)
            
            if not domain_list:
                if skipped_count > 0: st.success(f"🎉 所有 {skipped_count} 筆域名都已經在資料庫中了！")
                else: st.warning("請輸入域名")
            else:
                if skipped_count > 0: st.info(f"⏩ 已自動跳過 {skipped_count} 筆重複資料，本次將掃描 {len(domain_list)} 筆。")
                config = {'dns': check_dns, 'geoip': check_geoip, 'ssl': check_ssl, 'global_ping': check_global_ping, 'simple_ping': check_simple_ping}
                indexed_domains = list(enumerate(domain_list))
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # 優化：先收集所有結果，最後再一次批次寫入資料庫
                final_results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(process_domain_audit, (idx, dom, config)): idx for idx, dom in indexed_domains}
                    completed = 0
                    for future in concurrent.futures.as_completed(futures):
                        idx, data = future.result()
                        final_results.append(data)
                        completed += 1
                        progress_bar.progress(completed / len(domain_list))
                        status_text.text(f"已處理: {completed}/{len(domain_list)}...")
                
                status_text.text("📦 正在將資料批次寫入資料庫...")
                save_domain_results_batch(final_results)
                
                status_text.success("✅ 掃描完成！資料已寫入。")
                st.balloons()
                time.sleep(1)
                st.rerun()

    # 優化：直接在網頁下方顯示當前資料庫內容，不用一直下載 CSV
    if not df_domains.empty:
        st.divider()
        st.subheader("📊 檢測結果預覽")
        st.dataframe(df_domains, use_container_width=True, height=400)


# --- 分頁 2: IP 反查 ---
with tab2:
    st.header("IP 反查與存活驗證 (DB 自動存檔)")
    api_key = st.text_input("請輸入 VirusTotal API Key", type="password")
    ip_input = st.text_area("輸入 IP 清單", height=150, placeholder="8.8.8.8")
    
    if st.button("🔎 開始反查 IP", type="primary"):
        if not api_key: st.error("請輸入 API Key！")
        else:
            ip_list = parse_input_raw(ip_input)
            if not ip_list: st.warning("請輸入 IP")
            else:
                vt_counter = 0
                status_log = st.empty()
                
                for i, ip in enumerate(ip_list):
                    status_log.markdown(f"**[{i+1}/{len(ip_list)}] 正在查詢 VT:** `{ip}` ...")
                    status, domains = process_ip_vt_lookup(ip, api_key)
                    rows_to_save = []
                    
                    if status == "Success":
                        if not domains: 
                            rows_to_save.append({"Input_IP": ip, "Domain": "(no data)", "Current_Resolved_IP": "-", "IP_Match": "-", "HTTP_Status": "-"})
                        else:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                                verify_futures = {executor.submit(check_single_domain_status, dom, ip): dom for dom in domains}
                                for future in concurrent.futures.as_completed(verify_futures):
                                    v_res = future.result()
                                    rows_to_save.append({
                                        "Input_IP": ip, "Domain": v_res["Domain"],
                                        "Current_Resolved_IP": v_res["Current_Resolved_IP"], "IP_Match": v_res["IP_Match"], "HTTP_Status": v_res["HTTP_Status"]
                                    })
                    else: 
                        rows_to_save.append({"Input_IP": ip, "Domain": f"Error: {status}", "Current_Resolved_IP": "-", "IP_Match": "-", "HTTP_Status": "-"})
                    
                    # 優化：批次寫入 IP 反查結果
                    save_ip_results_batch(rows_to_save)
                    
                    vt_counter += 1
                    if i < len(ip_list) - 1:
                        if vt_counter % 4 == 0:
                            for sec in range(60, 0, -1):
                                status_log.warning(f"⏳ VT Rate Limit 冷卻中... 剩餘 {sec} 秒")
                                time.sleep(1)
                        else: 
                            time.sleep(15)
                
                status_log.success("✅ 查詢完成！資料已存入 DB。")
                st.balloons()
                time.sleep(1)
                st.rerun()
                
    if not df_ips.empty:
        st.divider()
        st.subheader("📊 IP 反查結果預覽")
        st.dataframe(df_ips, use_container_width=True, height=400)
