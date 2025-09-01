# /b/locked [_snakeCTF 2025 Quals_]

**Category**: Web

## Description

Time to prove you're not just another... new user.

## Solution

The challenge involved a web application that required users to solve 10 captchas in 10 seconds to access a protected area. The core vulnerability exploited was a race condition in the captcha solving mechanism.

### First step

Upon analysing the challenge, it was observed that solving a captcha involved sending a POST request to the `/api/solve` endpoint with the `captchaId` and `solution`. Successful resolution would result in a `Set-Cookie` header containing a `solvedCaptchas` cookie. The objective was to accumulate a sufficient number of these cookies to access the `/protected` endpoint.

### Second step

A race condition was identified in the server's handling of captcha solutions. When multiple concurrent requests were sent to `/api/solve` with the same `captchaId` and `solution`, the server would, under certain circumstances, issue multiple `solvedCaptchas` cookies for a single valid solution. This behaviour allowed for the rapid accumulation of the required cookies.

To exploit this race condition, multiple threads were initiated, each sending a POST request to `/api/solve` with the given captcha ID and solution. The `Set-Cookie` headers from successful responses were then parsed, and the `solvedCaptchas` values were extracted and stored.

Here is a snippet of code demonstrating the race condition exploitation:

```python
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
```

### Third step

Once a sufficient number of `solvedCaptchas` were collected (in this case, 10), these values were concatenated into a single `Cookie` header. This crafted cookie was then used to make a GET request to the `/protected` endpoint. The server, upon receiving the cookie with the accumulated solved captcha tokens, granted access to the protected area, revealing the flag.

## Alternative Solution

It's worth noting that the same race condition exploitation technique works on the `/protected` endpoint directly. Since the vulnerability lies in the captcha solving mechanism rather than the specific endpoint being accessed, players could alternatively target `/protected` instead of the main challenge flow. This is an intended behavior and not an unintended solution - the race condition is the core vulnerability regardless of which protected endpoint is accessed.