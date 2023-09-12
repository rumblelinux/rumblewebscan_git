import random

# Danh sách user agent
user_agents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
]

# Danh sách proxy 
proxies = [
  '123.45.67.89:8080',
  '98.76.54.123:80',  
]

# Hàm lấy ngẫu nhiên user agent
def get_random_user_agent():
  return random.choice(user_agents)

# Hàm lấy ngẫu nhiên proxy  
def get_random_proxy():
  return random.choice(proxies)