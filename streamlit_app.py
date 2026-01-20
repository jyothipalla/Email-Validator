import streamlit as st
import pandas as pd
import dns.resolver
import socket
import smtplib
import re
from email_validator import validate_email, EmailNotValidError
from concurrent.futures import ThreadPoolExecutor

# --- PAGE SETUP ---
st.set_page_config(page_title="Mailmeter Pro", layout="wide", page_icon="📧")

def get_dns_data(domain):
    """Detailed DNS Audit for SPF, DKIM, DMARC, and MX."""
    res = {"mx": "FAIL", "spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL", "server": "Unknown"}
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
            elif "outlook" in primary_mx: res["server"] = "Microsoft 365"
            else: res["server"] = "Private SMTP"
        except:
            res["mx"] = "FAIL"

        # 2. SPF Check
        try:
            txt_records = resolver.resolve(domain, "TXT")
            for r in txt_records:
                if "v=spf1" in str(r):
                    res["spf"] = "PASS"
                    break
        except:
            pass

        # 3. DMARC Check
        try:
            resolver.resolve(f"_dmarc.{domain}", "TXT")
            res["dmarc"] = "PASS"
        except:
            pass

        # 4. DKIM (Common Selectors)
        for selector in ['google', 'default', 'mail', 'k1', 'sig1']:
            try:
                resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                res["dkim"] = "PASS"
                break
            except:
                continue
    except Exception:
        pass
    return res

def check_smtp(email, domain, server):
    """SMTP Deliverability Handshake."""
    # Major providers block public SMTP scraping; we mark them as PROTECTED
    if any(x in server for x in ["Google", "Microsoft"]): 
        return "PROTECTED"
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange)
        with smtplib.SMTP(mx_host, timeout=3) as smtp:
            smtp.helo(socket.gethostname())
            smtp.mail('verify@test.com')
            code, _ = smtp.rcpt(email)
            return "AVAILABLE" if code == 250 else "NOT_FOUND"
    except:
        return "UNVERIFIABLE"

def process_row(email):
    email = str(email).strip()
    try:
        # Syntax Validation
        valid = validate_email(email, check_deliverability=False)
        dom = valid.domain
        
        # DNS & SMTP Audit
        dns_data = get_dns_data(dom)
        smtp_stat = check_smtp(email, dom, dns_data["server"])
        
        # --- SCORING LOGIC ---
        score = 0
        if dns_data["mx"] == "PASS": score += 20
        if dns_data["spf"] == "PASS": score += 10
        if dns_data["dkim"] == "PASS": score += 10
        if dns_data["dmarc"] == "PASS": score += 10
        
        if smtp_stat == "AVAILABLE": score += 50
        elif smtp_stat == "PROTECTED": score += 40 # Slightly lower as we can't be 100% sure
        
        return [
            email, dns_data["spf"], smtp_stat, dns_data["dkim"], 
            dns_data["dmarc"], dns_data["mx"], "Valid Format", 
            dns_data["server"], max(0, score)
        ]
    except EmailNotValidError:
        return [email, "FAIL", "INVALID", "FAIL", "FAIL", "FAIL", "Syntax Error", "N/A", 0]
    except Exception:
        return [email, "ERROR", "UNKNOWN", "ERROR", "ERROR", "ERROR", "Internal Error", "N/A", 0]

# --- UI INTERFACE ---
st.title("📧 Mailmeter Full Audit Dashboard")
st.markdown("Upload a CSV file with email addresses in the **first column** to run a 9-point deliverability check.")

uploaded_file = st.file_uploader("Upload CSV", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    emails = df.iloc[:, 0].dropna().tolist()
    
    if st.button("Start 9-Point Audit"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        with st.spinner("Analyzing deliverability..."):
            # Using threads to speed up network-bound DNS/SMTP requests
            results = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(process_row, emails))
        
        cols = ["EMAIL", "SPF", "SMTP", "DKIM", "DMARC", "MX", "VALIDATION STATUS", "SERVER", "SCORE"]
        res_df = pd.DataFrame(results, columns=cols)
        
        # Logic for categorization
        valid_df = res_df[res_df["SCORE"] >= 70]
        risky_df = res_df[(res_df["SCORE"] < 70) & (res_df["SCORE"] > 0)]
        dead_count = len(res_df[res_df['SCORE'] == 0])

        # Results Overview
        st.success(f"Audit Complete! Processed {len(res_df)} emails.")
        
        col_m1, col_m2, col_m3 = st.columns(3)
        col_m1.metric("Valid Emails", len(valid_df))
        col_m2.metric("Risky Emails", len(risky_df))
        col_m3.metric("Dead/Invalid", dead_count)

        # Download Buttons
        c1, c2 = st.columns(2)
        with c1:
            st.download_button("📥 Download Valid List (High Score)", valid_df.to_csv(index=False), "valid_emails.csv", "text/csv")
        with c2:
            st.download_button("📥 Download Risky List (Review Required)", risky_df.to_csv(index=False), "risky_emails.csv", "text/csv")
            
        st.divider()
        st.subheader("Detailed Audit Results")
        st.dataframe(res_df.style.background_gradient(subset=['SCORE'], cmap='RdYlGn'), use_container_width=True)
