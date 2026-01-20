import streamlit as st
import pandas as pd
import dns.resolver
import socket
import smtplib
import re
from email_validator import validate_email
from concurrent.futures import ThreadPoolExecutor

# --- PAGE SETUP ---
st.set_page_config(page_title="Mailmeter Pro", layout="wide")

def get_dns_data(domain):
    """Detailed DNS Audit for SPF, DKIM, DMARC, and MX."""
    res = {"mx": "FAIL", "spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL", "server": "Unknown"}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2; resolver.lifetime = 2
        
        # MX & Server
        mx_query = resolver.resolve(domain, "MX")
        res["mx"] = "PASS"
        primary_mx = str(mx_query[0].exchange).lower()
        if "google" in primary_mx: res["server"] = "Google Workspace"
        elif "outlook" in primary_mx: res["server"] = "Microsoft 365"
        else: res["server"] = "Private SMTP"

        # SPF
        txt = resolver.resolve(domain, "TXT")
        for r in txt:
            if "v=spf1" in str(r): res["spf"] = "PASS"

        # DMARC
        try: resolver.resolve(f"_dmarc.{domain}", "TXT"); res["dmarc"] = "PASS"
        except: pass

        # DKIM
        for s in ['google', 'default', 'mail']:
            try: resolver.resolve(f"{s}._domainkey.{domain}", "TXT"); res["dkim"] = "PASS"; break
            except: continue
    except: pass
    return res

def check_smtp(email, domain, server):
    """SMTP Deliverability Handshake."""
    if any(x in server for x in ["Google", "Microsoft"]): return "PROTECTED"
    try:
        mx_host = str(dns.resolver.resolve(domain, 'MX')[0].exchange)
        with smtplib.SMTP(mx_host, timeout=3) as smtp:
            smtp.helo(); smtp.mail('verify@test.com')
            code, _ = smtp.rcpt(email)
            return "AVAILABLE" if code == 250 else "NOT_FOUND"
    except: return "UNVERIFIABLE"

def process_row(email):
    email = str(email).strip()
    try:
        valid = validate_email(email)
        dom = valid.domain
        dns_data = get_dns_data(dom)
        smtp_stat = check_smtp(email, dom, dns_data["server"])
        
        # --- SCORING ---
        score = 0
        if dns_data["mx"] == "PASS": score += 20
        if dns_data["spf"] == "PASS": score += 10
        if dns_data["dkim"] == "PASS": score += 10
        if dns_data["dmarc"] == "PASS": score += 10
        if smtp_stat in ["AVAILABLE", "PROTECTED"]: score += 50
        
        # --- RETURN ALL 9 COLUMNS ---
        return [
            email, dns_data["spf"], smtp_stat, dns_data["dkim"], 
            dns_data["dmarc"], dns_data["mx"], "Valid Format", 
            dns_data["server"], max(0, score)
        ]
    except:
        return [email, "FAIL", "INVALID", "FAIL", "FAIL", "FAIL", "Syntax Error", "N/A", 0]

# --- UI INTERFACE ---
st.title("📧 Mailmeter Full Audit Dashboard")

uploaded_file = st.file_uploader("Upload CSV", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    emails = df.iloc[:, 0].tolist()
    
    if st.button("Start 9-Point Audit"):
        with st.spinner("Processing..."):
            with ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(process_row, emails))
        
        # --- UPDATE THIS HEADER LIST ---
        cols = ["EMAIL", "SPF", "SMTP", "DKIM", "DMARC", "MX", "VALIDATION STATUS", "SERVER", "SCORE"]
        res_df = pd.DataFrame(results, columns=cols)
        
        # Split logic
        valid_df = res_df[res_df["SCORE"] > 50]
        risky_df = res_df[(res_df["SCORE"] <= 50) & (res_df["SCORE"] > 0)]
        
        st.success(f"Audit Complete. Removed {len(res_df[res_df['SCORE']==0])} dead emails.")

        c1, c2 = st.columns(2)
        with c1:
            st.download_button("📥 Download Valid List", valid_df.to_csv(index=False), "valid.csv")
        with c2:
            st.download_button("📥 Download Risky List", risky_df.to_csv(index=False), "risky.csv")
            
        st.dataframe(res_df, use_container_width=True)