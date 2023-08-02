import argparse
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="URL to scan", required=True)
    args = parser.parse_args()

    print("Starting scan for URL: ", args.url)
    
    results = scan_website(args.url)
    
    print("Scan completed! Found {} vulnerabilities.".format(len(results)))
    for r in results:
        print(r)
        
def scan_website(url):
    results = []
    
    # Crawl website 
    urls = crawl(url)
    
    # Scan URLs
    for u in urls:
        response = requests.get(u)
        
        if check_sqli(u, response):
            results.append({'url': u, 'vuln': 'SQL Injection'})
            
        if check_xss(u, response):
            results.append({'url': u, 'vuln': 'Cross Site Scripting'})
            
        if check_lfi(u):
            results.append({'url': u, 'vuln': 'Local File Inclusion'})
            
    return results
        
def crawl(url):
    urls = []
    response = requests.get(url)
    parsed = BeautifulSoup(response.text, 'html.parser')
    
    for link in parsed.find_all('a'):
        path = link.get('href')
        if path and path.startswith('/'):
            path = urljoin(url, path)
            urls.append(path)
    return urls

# Hàm kiểm tra SQL injection
def check_sqli(url, response):
  # Kiểm tra xem có chứa các từ khóa như union, select, insert, update, delete,...
  if re.search('union|select|insert|update|delete',response.text,re.I):
    return True
  
  # Kiểm tra dấu hiệu lỗi database
  error_msgs = ['Warning','Error','SQL','Failed','Rejected']
  for msg in error_msgs:
    if msg in response.text:
      return True
      
  # Kiểm tra thời gian response
  if response.elapsed.total_seconds() > 1:
    return True
  
  return False

# Hàm kiểm tra XSS
def check_xss(url, response):
  # Chèn Javascript alert vào URL
  xss_url = url + "<script>alert('XSS')</script>"
  xss_response = requests.get(xss_url)
  
  # Nếu có alert, là có lỗ hổng XSS
  if "<script>alert('XSS')" in xss_response.text:
    return True
  
  return False
  
# Hàm kiểm tra LFI  
def check_lfi(url):
  # Thử truy cập đến file /etc/passwd
  lfi_url = url + "../etc/passwd"
  lfi_response = requests.get(lfi_url)
  
  # Nếu trả về nội dung file passwd là có LFI
  if "root:" in lfi_response.text and "nobody:" in lfi_response.text:
    return True
  
  return False
    
if __name__ == "__main__":
   main()