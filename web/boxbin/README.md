# Boxbin [_snakeCTF 2025 Quals_]

**Category**: Web
**Author**: macedonga

## Description

🎵 You're on Boxbin, you're on Boxbin... 🎵 Welcome to Boxbin, the totally-not-suspicious platform for sharing your hatred against any kind of box!

### Hints

- Our GraphQL endpoint is super chatty - maybe too chatty. It loves talking about itself!
- Who needs proper authorization when you can just... upgrade yourself? Modern problems require modern solutions!
- Settings are just suggestions anyway. What's the worst that could happen if you inject a little extra JSON seasoning?

## Solution

The challenge requires chaining two vulnerabilities to escalate privileges from a regular user to an administrator, thereby gaining access to a hidden post containing the flag. The solution can be divided into three main steps.

### Step 1: Discovery and Broken Access Control

Upon initial analysis, it is determined that the application's backend is powered by a GraphQL API located at `/api/graphql`. Introspection is enabled on this endpoint, which allows the entire API schema to be queried.

By performing an introspection query, a mutation named `adminUserUpgrade(upgradeId: ID!)` is discovered. It is noted that this mutation is not used by the client-side application under normal circumstances. Further testing reveals that this mutation lacks any authorisation checks. It can be called by any authenticated user.

An account is created, and a login is performed to acquire a JWT authentication token. With this token, the `adminUserUpgrade` mutation is called. This action grants the user an "upgraded" status, which makes a previously hidden "Settings" page accessible on the user's profile.

### Step 2: Server-Side Object Injection

The newly accessible Settings page is analysed. It is found that the "Save All Settings" functionality uses the `updateSettings(settings: String!)` mutation. The `settings` argument accepts a JSON string.

It is determined that the backend logic for this mutation is vulnerable to Server-Side Object Injection. The provided JSON string is parsed and its properties are recursively merged into a shared, global object on the server. No sanitization is performed on the keys.

The authorisation logic for administrative functions is found to be based on a check for `isAdmin: true` within this shared object. A payload can therefore be crafted to inject this property.

The required payload is:
```json
{"isAdmin": true}
```

This payload is stringified and sent via the `updateSettings` mutation. The server merges this into the shared state object. As a result, the current user's session, and all subsequent sessions, are treated as having administrative privileges.

### Step 3: Retrieving the Flag

With administrative privileges now active, the "Admin" link becomes visible in the site's header, leading to the `/admin` dashboard.

On the dashboard, a list of "Hidden Posts" is available. The post titled "The Box To End All Boxes" is selected. The content of this post contains the flag.

[The solver script can be found here.](./attachments/solve.py)