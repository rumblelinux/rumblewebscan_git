import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup


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
  test_urls = [f"{url}' OR '1'='1", f"{url}' AND '1'='2"]
  
  for test_url in test_urls:
    response = requests.get(test_url)  
    if check_error(response):
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


# Hàm kiểm tra XSS
def check_xss(url, response):

  soup = BeautifulSoup(response.content, 'html.parser')

  # Tìm các input, form để test XSS
  inputs = soup.find_all('input')
  forms = soup.find_all('form')

  test_payload = "<script>alert(1)</script>"

  # Test XSS trên input fields
  for input in inputs:
    input['value'] = test_payload

  # Test XSS trên forms
  for form in forms:
    form.findAll('input', {'name': True})[0]['value'] = test_payload

  # Kiểm tra xem có script reflect lại không
  if test_payload in str(soup):
    print("Reflected XSS detected by BeautifulSoup")
    return True
  
  print("BeautifulSoup XSS test negative")
  return False


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
    return True
  
  return False
  