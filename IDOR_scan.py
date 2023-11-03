import requests
from bs4 import BeautifulSoup
import re
import random

class IDOR_check:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/117.0.5938.92"
        }

    def scan_website(self, url):
        results = {
            "idor": [] 
        }

        if self.check_idor(url):
            results["sqli"].append({
                "url": url,
                "details": "[+] IDOR detected"
            })
            return True, results
        return False, results
    
    def extract_urls(self):
        response = self.session.get(self.url)
        soup = BeautifulSoup(response.content, 'html.parser')
        urls = []
        for url in soup.find_all('a'):
            url = url.get('href')
            if url:
                urls.append(url)
        return urls

    def generate_random_id(self):
        return str(random.randint(1, 9999))

    # Code for compare two responses HTML
    def compare_responses(self, resp1, resp2):
        html1 = resp1.content
        html2 = resp2.content

        if html1 != html2:
            return False

        return False
    
    def check_unauthorized_access(self, response):
        # Check status code
        if response.status_code == 401 or response.status_code == 403:
            return True
        
        # Check HTML for error messages 
        errors = ["Access denied", "Unauthorized", "Permission denied"]

        for error in errors:
            if error in response.text:
                return True

        return False

    def check_idor(self, url):
        urls = self.extract_urls()
        
        for url in urls:
            if re.search(r'user_id=(\d+)', url):
                original_id = re.search(r'user_id=(\d+)', url).group(1)  
                original_url = url 
            
            
                test_id = self.generate_random_id()
                test_url = re.sub(r'user_id=\d+', 'user_id=' + test_id, url)
                test_resp = self.session.get(test_url)
                original_resp = self.session.get(original_url)

                if self.compare_responses(original_resp, test_resp):
                    print("[!] IDOR detected on url:", test_url)
                    return True
                
                if self.check_unauthorized_access(test_resp):
                    print("[!] IDOR detected on url:", test_url)
                    return True
                
        return False
        
