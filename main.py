from SQLi_scan import SQli_check
from XSS_scan import XSS_check
from LFi_scan import LFI_check
from IDOR_scan import IDOR_check
import sys
import json

if __name__ == "__main__":

  if len(sys.argv) != 2:
      print("Usage: python or python3 main.py <url>")
      sys.exit(1)

  url = sys.argv[1]
  print(f"Starting scan on {url}")

  sqli_scanner = SQli_check(url)
  sqli_result = sqli_scanner.scan_website(url)
  
  xss_scanner = XSS_check(url)
  xss_result = xss_scanner.check_xss(url)
  
  lfi_scanner = LFI_check(url)
  lfi_result = lfi_scanner.check_lfi(url)

  idor_scanner = IDOR_check(url)
  idor_result = idor_scanner.check_idor(url)

  # Save result to file report.json
  report = {
      "target": url,
      "SQLi vulnerabilities": sqli_result,
      "XSS vulnerabilities": xss_result,
      "LFI vulnerabilities" : lfi_result,
      "IDOR vulnerabilities" : idor_result
  }
  
  with open("report.json", "w") as f:
      json.dump(report, f, indent=4)

  print("[v] Scan completed, report generated")