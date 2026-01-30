import streamlit as st
import pandas as pd
import dns.resolver
import socket
import smtplib
import re
from email_validator import validate_email, EmailNotValidError
from concurrent.futures import ThreadPoolExecutor

# --- PAGE SETUP ---
st.set_page_config(page_title="Mailmeter Pro - Max Accuracy", layout="wide", page_icon="📧")
socket.setdefaulttimeout(10)

# --- THE BRUTE FORCE DICTIONARY ---
# This list covers 99% of global and private host selectors
ULTIMATE_SELECTORS = [
    'selector1', 'selector2', 'google', 'default', 'mail', 'k1', 'k2', 'k3', 
    'sig1', 's1', 's2', 'smtp', 'zoho', 'mandrill', 'm1', 'm2', 'picasso', 
    'amazonses', 'sendgrid', 'hubspot', 'mailgun', 'dkim', 'ms', 'onms',
    'hostinger', 'hostinger1', 'hostinger2', 'cp01', 'cp02', 'key1', 'key2'
]

def get_dns_data(domain):
    """Accurate DNS Audit using Brute-Force Selector Dictionary."""
    res = {
        "mx": "FAIL", "spf": "FAIL", "dkim": "FAIL", 
        "dmarc": "FAIL", "server": "Unknown", "dkim_report": "No Selector Match"
    }
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    try:
        # 1. MX & Server Identification
        try:
            mx_query = resolver.resolve(domain, "MX")
            res["mx"] = "PASS"
            primary_mx = str(mx_query[0].exchange).lower()
            if "google" in primary_mx: res["server"] = "Google Workspace"
            elif "outlook" in primary_mx or "microsoft" in primary_mx: res["server"] = "Microsoft 365"
            else: res["server"] = "Private SMTP"
        except: res["mx"] = "FAIL"

        # 2. SPF & DMARC Checks
        try:
            txt_records = resolver.resolve(domain, "TXT")
            if any("v=spf1" in str(r) for r in txt_records): res["spf"] = "PASS"
        except: pass
        try:
            resolver.resolve(f"_dmarc.{domain}", "TXT")
            res["dmarc"] = "PASS"
        except: pass

        # 3. DKIM Brute-Force Scan
        for selector in ULTIMATE_SELECTORS:
            try:
                path = f"{selector}._domainkey.{domain}"
                resolver.resolve(path, "TXT")
                res["dkim"] = f"PASS ({selector})"
                res["dkim_report"] = f"Match Found: {selector}"
                return res 
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.resolver.Timeout:
                res["dkim_report"] = "DNS Timeout"
                break
    except Exception as e:
        res["dkim_report"] = f"Scan Error: {str(e)[:15]}"
    return res

def check_smtp(email, domain, server):
    if any(x in server for x in ["Google", "Microsoft"]): return "PROTECTED"
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange)
        with smtplib.SMTP(mx_host, timeout=3) as smtp:
            smtp.helo(socket.gethostname())
            smtp.mail('verify@test.com')
            code, _ = smtp.rcpt(email)
            return "AVAILABLE" if code == 250 else "NOT_FOUND"
    except: return "UNVERIFIABLE"

def process_row(email):
    email = str(email).strip()
    try:
        valid = validate_email(email, check_deliverability=False)
        dom = valid.domain
        dns_data = get_dns_data(dom)
        smtp_stat = check_smtp(email, dom, dns_data["server"])
        
        score = 0
        if dns_data["mx"] == "PASS": score += 20
        if dns_data["spf"] == "PASS": score += 10
        if "PASS" in dns_data["dkim"]: score += 10
        if dns_data["dmarc"] == "PASS": score += 10
        if smtp_stat == "AVAILABLE": score += 50
        elif smtp_stat == "PROTECTED": score += 40 
        if re.match(r'^\d+', email.split('@')[0]): score -= 30
        
        return [
            email, dns_data["spf"], smtp_stat, dns_data["dkim"], 
            dns_data["dmarc"], dns_data["mx"], "Valid Format", 
            dns_data["server"], dns_data["dkim_report"], max(0, score)
        ]
    except Exception:
        return [email, "FAIL", "INVALID", "FAIL", "FAIL", "FAIL", "Syntax Error", "N/A", "Check Format", 0]

def color_score(val):
    if val >= 70: return 'background-color: #d4edda; color: #155724'
    elif val > 0: return 'background-color: #fff3cd; color: #856404'
    else: return 'background-color: #f8d7da; color: #721c24'

# --- UI INTERFACE ---
st.title("📧 Mailmeter Pro: Ultimate Accuracy Audit")
uploaded_file = st.file_uploader("Upload CSV", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    emails = df.iloc[:, 0].dropna().astype(str).tolist()
    
    if st.button("🚀 Run Deep Audit", type="primary"):
        with st.spinner("Analyzing DNS and Brute-Forcing Selectors..."):
            with ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(process_row, emails))
        
        cols = ["EMAIL", "SPF", "SMTP", "DKIM", "DMARC", "MX", "STATUS", "SERVER", "DKIM_REPORT", "SCORE"]
        res_df = pd.DataFrame(results, columns=cols)
        
        st.success(f"✅ Audit Complete!")
        st.dataframe(res_df.style.applymap(color_score, subset=['SCORE']), use_container_width=True)

        st.divider()
        st.download_button("📥 Download Full Report", res_df.to_csv(index=False), "full_report.csv", "text/csv")
