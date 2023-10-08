import SQLi_scan
import XSS_scan
import LFi_scan
import sys
import json

if __name__ == "__main__":

  if len(sys.argv) != 2:
      print("Usage: python main.py <url>")
      sys.exit(1)

  url = sys.argv[1]
  print(f"Starting scan on {url}")
  
  sqli_result = SQLi_scan.check_sqli(url)  
  xss_result = XSS_scan.check_xss(url)
  lfi_result = LFi_scan.check_lfi(url)


  # Save result to file report.json
  report = {
      "target": url,
      "SQLi vulnerabilities": sqli_result,
      "XSS vulnerabilities": xss_result,
      "LFI vulnerabilities" : lfi_result
  }
  
  with open("report.json", "w") as f:
      json.dump(report, f, indent=4)

  print("[v] Scan completed, report generated")