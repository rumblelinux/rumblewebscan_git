import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse, urljoin
import sys
import re 
import urllib.parse


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.5938.92"

# login_payload = {
#     "username": "admin",
#     "password": "password",
#     "Login": "Login",
# }
# # change URL to the login page of your DVWA login URL
# login_url = "http://192.168.168.105/dvwa/login.php"

# # login
# r = s.get(login_url)
# token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
# login_payload['user_token'] = token
# s.post(login_url, data=login_payload)


# ---------------------------------------------------------------
#DEF SCAN WEBSITE
forms = []
def scan_website(url):
  soup = bs(s.get(url).content, "html.parser")
  results = {
    "sqli": [] ,
    "xss": []
  }
  urls = urlparse(url)
  global forms
  forms = bs(s.get(url).content, "html.parser").find_all("form")

  # Scan SQLi
  if check_sqli(url):
    results["sqli"].append({
      "url": url,
      "details": "[+] SQL Injection detected"
    })
  
  # Scan XSS
  if check_xss(url):
    results["xss"].append({
      "url": url,
      "details": "[+] Cross Site Scripting detected"
    })

  return results


# -----------------------------------------------------

# Hàm kiểm tra lỗ hổng SQLi
def is_vulnerable_sqli(response):
  # Kiểm tra các lỗi chung
  errors = {
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
  }

  for error in errors:
    if error in response.content.decode().lower():
      return True
  
  return False

# ---------

# ---------------------------------
# Hàm lấy tất cả form trong trang
def get_all_forms(url):
  soup = bs(s.get(url).content, "html.parser")
  return soup.find_all("form")

# Hàm lấy chi tiết form 
def get_form_details(form):
  # Code phân tích form
  details = {}
  # get the form action (target url)
  try:
      action = form.attrs.get("action").lower()
  except:
      action = None

  # get the form method (POST, GET, etc.)
  method = form.attrs.get("method", "get").lower()

  # get all the input details such as type and name
  inputs = []
  for input_tag in form.find_all("input"):
      input_type = input_tag.attrs.get("type", "text")
      input_name = input_tag.attrs.get("name")
      input_value = input_tag.attrs.get("value", "")
      inputs.append({"type": input_type, "name": input_name, "value": input_value})

  # put everything to the resulting dictionary
  details["action"] = action
  details["method"] = method
  details["inputs"] = inputs
  return details



# -------------------------------------------------------------
def check_sqli(url):
  
  with open('sqli_payload.txt') as f:
    sqli_payloads = f.read().splitlines()
    print("\n[+] Checking SQLi")

  for payload in sqli_payloads:
    encoded_payload = urllib.parse.quote(payload)
    new_url = f"{url}?id={encoded_payload}"
    print("[!] Trying", new_url)

    # make the HTTP request
    res = s.get(new_url)
    if is_vulnerable_sqli(res):
        # SQL Injection detected on the URL itself, 
        # no need to preceed for extracting forms and submitting them
        print("[+] SQL Injection vulnerability detected, link:", new_url)
        return True


  # test on HTML forms
  forms = get_all_forms(url)
  print(f"[+] Detected {len(forms)} forms on {url}")
  
  for form in forms:
      form_details = get_form_details(form)
      for payload in sqli_payloads:

          # the data body we want to submit
          data = {}

          for input_tag in form_details["inputs"]:
              if input_tag["value"] or input_tag["type"] == "hidden":
                  # any input form that has some value or hidden,
                  # just use it in the form body
                  try:
                      data[input_tag["name"]] = input_tag["value"] + payload
                  except:
                      pass
              elif input_tag["type"] != "submit":
                  # all others except submit, use some junk data with special character
                  data[input_tag["name"]] = f"test{payload}"

          # join the url with the action (form request URL)
          url = urljoin(url, form_details["action"])
          if form_details["method"] == "post":
              res = s.post(url, data=data)
          elif form_details["method"] == "get":
              res = s.get(url, params=data)

          curr_url = url
          results = {
              "sqli": []
            }

          if is_vulnerable_sqli(res):
            # dùng curr_url thay vì new_url
            results["sqli"].append({
              "url": curr_url,  
              "details": "[+] SQLi vulnerability detected"
            }) 

            return True
  
  print("[+] Check SQLi done")
  return False




# ---------------------------------------------------------------------
# Đọc các payload XSS từ file
# CHeck XSS

def check_xss(url):

  # Đọc các payload XSS từ file
  with open('xss_payload.txt') as f:
    xss_payloads = f.read().splitlines()

  print("\n[+] Checking XSS")

  # Kiểm tra trực tiếp trên URL
  for payload in xss_payloads:
    # Mã hóa payload để sử dụng trong URL 
    encoded_payload = urllib.parse.quote(payload) 
    new_url = f"{url}?q={encoded_payload}"

    print("[!] Trying", new_url)
    res = s.get(new_url)

    if payload in res.text:
      print("[+] XSS vulnerability detected, link:", new_url)
      return True

  # Kiểm tra trên các form
  forms = get_all_forms(url)
  print(f"[+] Detected {len(forms)} forms on {url}")

  for form in forms:
    form_details = get_form_details(form)

    for payload in xss_payloads:
      data = {}

      for input_tag in form_details["inputs"]:
        if input_tag["value"] or input_tag["type"] == "hidden":
          try:
            data[input_tag["name"]] = input_tag["value"] + payload
          except:
            pass
        elif input_tag["type"] != "submit":
          data[input_tag["name"]] = payload
      
      url = urljoin(url, form_details["action"])
      if form_details["method"] == "post":
        res = s.post(url, data=data)
      elif form_details["method"] == "get":
        res = s.get(url, params=data)

      if payload in res.text:
        print("[+] XSS vulnerability detected, link:", url)
        return True

  print("[+] Check XSS done")

  return False