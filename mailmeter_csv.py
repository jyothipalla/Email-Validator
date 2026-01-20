import csv
import dns.resolver
import socket
import smtplib
import re
import os
from email_validator import validate_email, EmailNotValidError
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION ---
INPUT_FILE = "BOOK1.csv"
VALID_OUT = "Valid_Emails.csv"
RISKY_OUT = "Risky_Emails.csv"

# Global timeout for network checks
socket.setdefaulttimeout(10)

def get_dns_data(domain):
    """Checks MX, SPF, DKIM, and DMARC."""
    res = {"mx": "FAIL", "spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL", "server": "Unknown"}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # MX & Server Provider
        try:
            mx_query = resolver.resolve(domain, "MX")
            res["mx"] = "PASS"
            primary_mx = str(mx_query[0].exchange).lower()
            if "google" in primary_mx: res["server"] = "Google Workspace"
            elif "outlook" in primary_mx: res["server"] = "Microsoft 365"
            else: res["server"] = "Private SMTP"
        except: pass

        # SPF
        try:
            txt = resolver.resolve(domain, "TXT")
            for r in txt:
                if "v=spf1" in str(r): res["spf"] = "PASS"
        except: pass

        # DMARC
        try:
            resolver.resolve(f"_dmarc.{domain}", "TXT")
            res["dmarc"] = "PASS"
        except: pass

        # DKIM (Common selectors)
        for s in ['google', 'default', 'mail', 'k1']:
            try:
                resolver.resolve(f"{s}._domainkey.{domain}", "TXT")
                res["dkim"] = "PASS"
                break
            except: continue
    except: pass
    return res

def check_smtp(email, domain, server_type):
    """Checks SMTP availability (Handshake)."""
    if "Google" in server_type or "Microsoft" in server_type:
        return "PROTECTED"
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mail_server = str(mx_records[0].exchange)
        with smtplib.SMTP(mail_server, timeout=3) as smtp:
            smtp.helo()
            smtp.mail('verify@test.com')
            code, _ = smtp.rcpt(email)
            return "AVAILABLE" if code == 250 else "NOT_FOUND"
    except:
        return "UNVERIFIABLE"

def process_row(row):
    if not row or not row[0]: return None
    email = row[0].strip()
    
    # Defaults
    status = "Invalid Syntax"
    score = 0

    try:
        # 1. Validation Status
        valid = validate_email(email)
        domain = valid.domain
        status = "Valid Format"
        
        # 2. DNS Checks
        dns_data = get_dns_data(domain)
        
        # 3. SMTP Check
        smtp_status = check_smtp(email, domain, dns_data["server"])
        
        # --- SCORING LOGIC ---
        if dns_data["mx"] == "PASS": score += 20
        if dns_data["spf"] == "PASS": score += 10
        if dns_data["dkim"] == "PASS": score += 10
        if dns_data["dmarc"] == "PASS": score += 10
        if smtp_status in ["AVAILABLE", "PROTECTED"]: score += 50
        
        # Penalty for numbers in name
        if re.match(r'^\d+', email.split('@')[0]): score -= 30

        # --- FINAL 9-COLUMN RETURN ---
        return [
            email,              # EMAIL
            dns_data["spf"],    # SPF
            smtp_status,        # SMTP
            dns_data["dkim"],   # DKIM
            dns_data["dmarc"],  # DMARC
            dns_data["mx"],     # MX
            status,             # VALIDATION STATUS
            dns_data["server"], # SERVER
            max(0, score)       # DELIVERABILITY SCORE
        ]

    except Exception:
        return [email, "FAIL", "INVALID", "FAIL", "FAIL", "FAIL", "Syntax Error", "N/A", 0]

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found in {os.getcwd()}")
        return

    # Read Data
    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        reader = list(csv.reader(f))
        if len(reader) < 2: return
        header_in = reader[0]
        rows = reader[1:]

    print(f"Auditing {len(rows)} emails... Please wait.")

    # Process Rows
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(process_row, rows))

    # --- SEGMENTATION LOGIC ---
    # 1. Score > 50 (Valid)
    valid_data = [r for r in results if r is not None and r[-1] > 50]
    # 2. Score 1 to 50 (Risky)
    risky_data = [r for r in results if r is not None and 0 < r[-1] <= 50]
    # 3. Score 0 (Deleted/Filtered out)
    deleted_count = len([r for r in results if r is not None and r[-1] == 0])

    # Final Output Header
    full_header = ["EMAIL", "SPF", "SMTP", "DKIM", "DMARC", "MX", "STATUS", "SERVER", "SCORE"]

    # Write Valid File
    with open(VALID_OUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(full_header)
        writer.writerows(valid_data)

    # Write Risky File
    with open(RISKY_OUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(full_header)
        writer.writerows(risky_data)

    print("-" * 30)
    print(f"SUCCESS: Files Generated Successfully")
    print(f"✅ Valid (>50): {len(valid_data)} saved to {VALID_OUT}")
    print(f"⚠️ Risky (1-50): {len(risky_data)} saved to {RISKY_OUT}")
    print(f"🗑️ Deleted (0): {deleted_count} junk emails removed.")
    print("-" * 30)

if __name__ == "__main__":
    main()