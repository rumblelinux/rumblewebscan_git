import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse, urljoin
import sys
import re 
import urllib.parse

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.5938.92"

class LFI_check:

  def __init__(self, url):
     self.url = url
  # ---------------------------------------------------------------
  #DEF SCAN WEBSITE
  forms = []
  def scan_website(url):
    results = {
      "lif": []
    }
    urls = urlparse(url)
    global forms
    forms = bs(s.get(url).content, "html.parser").find_all("form")

    # Scan LFI
    if self.check_lfi(url):
      results["lfi"].append({
        "url": url,
        "details": "[+] Local File Injection detected"
      })

    return results

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

  # Scan LFi function
  def check_lfi(self, url):
    with open('lfi_payloads.txt') as f:
      lfi_payloads = f.read().splitlines()
    
    print("\n[+] Checking LFI")

    for payload in lfi_payloads:
      encoded_payload = urllib.parse.quote(payload)
      new_url = f"{url}?page={encoded_payload}"

      print("[!] Trying", new_url)
      res = s.get(new_url)

      if re.search(rb"root:x:0:0", res.content):
        print("[+] LFI vulnerability detected, link:", new_url)
        return True

    # Check from all form
    forms = self.get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
      form_details = self.get_form_details(form)

      for payload in lfi_payloads:
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

        if re.search(rb"root:x:0:0", res.content):
          print("[+] LFI vulnerability detected, link:", url)
          return True

    print("[+] Check LFI done")    

    return False