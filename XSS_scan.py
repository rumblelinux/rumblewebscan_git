import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse, urljoin
import sys
import re 
import urllib.parse


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.5938.92"

class XSS_check:
 
  def __init__(self, url):
     self.url = url
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
      "xss": []
    }
    urls = urlparse(url)
    global forms
    forms = bs(s.get(url).content, "html.parser").find_all("form")

    # Scan XSS
    if self.check_xss(url):
      results["xss"].append({
        "url": url,
        "details": "[+] Cross Site Scripting detected"
      })

    return results



  # ---------------------------------
  # Get all form from page
  def get_all_forms(self, url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

  # Get form details
  def get_form_details(self, form):
    details = {}
    # Get the form action (target url)
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

  # ---------------------------------------------------------------------
  # Read payload from payload file
  # CHeck XSS

  def check_xss(self, url):
    with open('xss_payload.txt') as f:
      xss_payloads = f.read().splitlines()

    print("\n[+] Checking XSS")

    # Check on URL
    for payload in xss_payloads:
      encoded_payload = urllib.parse.quote(payload) 
      new_url = f"{url}?q={encoded_payload}"

      print("[!] Trying", new_url)
      res = s.get(new_url)

      if payload in res.text:
        print("[+] XSS vulnerability detected, link:", new_url)
        return True

    # Check all form
    forms = self.get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}, form found: {forms}\n")

    for form in forms:
      form_details = self.get_form_details(form)

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