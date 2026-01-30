import pandas as pd
import dns.resolver
import os
import time
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION ---
INPUT_FILE = "BOOK1.csv"
OUTPUT_FILE = "DKIM_FINAL_REPORT.csv"

# These are the "keys" used to find DKIM. 
# Added 'selector1' and 'selector2' at the top for Microsoft 365.
SELECTORS = [
    'selector1', 'selector2', 'google', 's1', 's2', 
    'default', 'mail', 'k1', 'picasso', 'mandrill'
]

def get_dkim_data(email):
    """
    Looks up DKIM records and returns a dictionary.
    This structure ensures every row has the same columns.
    """
    domain = str(email).split('@')[-1].strip()
    result = {
        "EMAIL": email,
        "DKIM_STATUS": "FAIL",
        "DKIM_REPORT": "No Selector Match", # This is your missing column
        "SCAN_TIME": time.strftime("%H:%M:%S")
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for s in SELECTORS:
        try:
            path = f"{s}._domainkey.{domain}"
            query = resolver.resolve(path, "TXT")
            for rdata in query:
                record = rdata.to_text()
                if "v=DKIM1" in record or "p=" in record:
                    result["DKIM_STATUS"] = f"PASS ({s})"
                    result["DKIM_REPORT"] = "Record Found Successfully"
                    return result
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue 
        except Exception as e:
            result["DKIM_REPORT"] = f"Error: {type(e).__name__}"
            break
            
    return result

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found!")
        return

    print("Step 1: Loading emails...")
    df_in = pd.read_csv(INPUT_FILE)
    email_list = df_in.iloc[:, 0].dropna().tolist()

    print(f"Step 2: Scanning {len(email_list)} emails for DKIM...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        audit_results = list(executor.map(get_dkim_data, email_list))

    print("Step 3: Forcing column generation...")
    df_out = pd.DataFrame(audit_results)

    # REORDERING: This forces DKIM_REPORT to be the third column so you can't miss it
    df_out = df_out[["EMAIL", "DKIM_STATUS", "DKIM_REPORT", "SCAN_TIME"]]

    # Save to a completely new file
    df_out.to_csv(OUTPUT_FILE, index=False)
    
    print("-" * 30)
    print(f"SUCCESS! New report created: {OUTPUT_FILE}")
    print(f"Location: {os.path.abspath(OUTPUT_FILE)}")
    print("-" * 30)

if __name__ == "__main__":
    main()
