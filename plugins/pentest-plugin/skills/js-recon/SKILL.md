---
name: js-recon
description: Analyzes JavaScript source code for pentesting recon. Use when user uploads a .js file, asks to "recon JS", "analyze JS for pentest", "find API endpoints in JS", "check for hardcoded secrets", "find auth logic", "trace encryption flow", "check client-side auth", or "analyze client-side JS". Runs automated pattern-matching script then performs deep Claude reasoning on findings to identify exploitable vulnerabilities.
allowed-tools: "Bash(python3:*) Bash(pip3:*) Bash(curl:*) Bash(wget:*)"
metadata:
  version: 2.0.0
  author: js-recon-skill
  category: security
---

# JS Recon Skill — Client-Side JavaScript Penetration Testing

You are a senior penetration tester performing recon on JavaScript source files.
Extract maximum intelligence to support attack phases: endpoint discovery, auth bypass, secret extraction, privilege escalation.

---

## Pre-flight: Install Dependencies (once)

```bash
pip3 install jsbeautifier 2>/dev/null || true
```

---

## Step 1 — Obtain the JS File(s)

### Option A: User uploaded a file
The file is at the path shown in the upload. Copy it to a working directory:
```bash
HASH=$(echo "$TARGET_URL_OR_NAME" | md5sum | cut -c1-8)
cp "<uploaded_path>" "/tmp/jsrecon_${HASH}.js"
```

### Option B: Fetch from URL (direct)
```bash
TARGET="https://example.com/static/app.bundle.js"
HASH=$(echo "$TARGET" | md5sum | cut -c1-8)
curl -sL "$TARGET" -o "/tmp/jsrecon_${HASH}.js"
```

### Option C: Fetch via Burp MCP
Ask the user: *"Should I pull JS files from Burp proxy history for this domain?"*
If yes, use Burp MCP to list captured JS URLs, then fetch each:
```bash
# For each JS URL from Burp history:
HASH=$(echo "$JS_URL" | md5sum | cut -c1-8)
curl -sL "$JS_URL" -o "/tmp/jsrecon_${HASH}.js"
```
Use content hash in the filename — **never overwrite `/tmp/target.js`** when processing multiple files.

---

## Step 2 — Detect Minification / Obfuscation First

Before scanning, check the file:
```bash
FILE="/tmp/jsrecon_<hash>.js"
wc -l "$FILE"          # If lines < 5 and size > 50KB → minified
head -c 200 "$FILE"    # Look for _0x patterns → obfuscated
```

**Decision tree:**
- File is **minified** (1-3 lines, large size) → Add `--beautify` flag
- File has **`_0x` variable names** → Heavy obfuscation detected, note in report
- File is **readable** → Scan as-is

---

## Step 3 — Run the Scanner Script

```bash
# Single file
python3 scripts/recon_js.py --file "$FILE" --output markdown

# Single file + beautify minified JS
python3 scripts/recon_js.py --file "$FILE" --beautify --output markdown

# Multiple files (Burp session with several JS chunks)
python3 scripts/recon_js.py \
  --file /tmp/jsrecon_aabb1122.js \
  --file /tmp/jsrecon_ccdd3344.js \
  --output markdown

# Pipe content directly
cat "$FILE" | python3 scripts/recon_js.py --stdin --beautify
```

---

## Step 4 — Deep Analysis (Claude Reasoning)

After script output, perform the following analysis manually.

### 4A. API Endpoint Classification

Categorize every found endpoint:

| Category | Examples | Risk |
|---|---|---|
| Public API | `/api/v1/products` | Low |
| Auth endpoints | `/api/auth/login`, `/api/token/refresh` | Medium |
| Internal / not in UI | `/api/internal/*`, `/api/debug/*` | High |
| Admin | `/api/admin/*`, `/admin/*` | Critical |
| Mobile-only | `/m/api/*`, `/mobile/*` | Medium |

- Flag endpoints that **do not appear on the visible UI** — these are priority targets
- If `/v2/` exists → test `/v1/` for deprecated, less-secured endpoints
- Cross-reference with wordlist:
  ```bash
  cat references/api-wordlist.txt | while read path; do
    echo "Testing: $BASE_URL$path"
  done
  ```

### 4B. Auth Flow Reconstruction

Map the complete auth flow from the script findings:

```
[User submits credentials]
       ↓
[Login endpoint called] ← note the URL
       ↓
[Response received] ← check: is response encrypted? see 4C
       ↓
[Token extracted from response.token / response.data.accessToken / etc]
       ↓
[Token stored in: localStorage / sessionStorage / cookie] ← note location
       ↓
[Token attached to requests via: Authorization header / custom header / cookie]
       ↓
[Refresh flow: refresh_token → /auth/refresh → new token]
```

**Client-Side Auth Check Assessment (bypass candidates):**
For every match in `Client-Side Auth Check` category:
- Identify: Is the access control decision made in JS? (e.g. `if (!isAdmin) return`)
- If YES → this is a **client-side enforcement only** → can be bypassed by:
  - Modifying JS in DevTools (Sources → overrides)
  - Intercepting and modifying the response that sets `isAdmin`
  - Directly calling the protected API endpoint regardless of UI guard

**Auth Response Bypass Analysis:**
If `Response Auth Processing` patterns found, analyze:
- Does the app check `response.success === true` client-side?
- Can attacker intercept via Burp and change `false` → `true`?
- Does `response.role` control what UI is shown? → IDOR / privilege escalation risk

### 4C. Encryption Flow Analysis

For every match in `Crypto / Encryption Flows`:

1. **Identify what is being encrypted:**
   - Request body before sending? (pre-request encryption)
   - Specific fields only? (partial encryption)
   - Response being decrypted? (encrypted API response)

2. **Extract the algorithm + mode:**
   - CryptoJS.AES → AES (default: CBC mode)
   - crypto.subtle.encrypt with `{name: "AES-GCM"}` → AES-GCM
   - JSEncrypt / NodeRSA → RSA

3. **Locate the key and IV:**
   - If found in secrets section → hardcoded, extractable
   - If loaded from server → check network requests for key delivery endpoint
   - If derived from user input → note the derivation function (PBKDF2, bcrypt, etc.)

4. **If key is hardcoded and plaintext** → provide decrypt snippet:

   ```js
   // CryptoJS AES-CBC — paste in browser console or Node.js
   const CryptoJS = require('crypto-js');
   const key = CryptoJS.enc.Utf8.parse('<KEY_FROM_SOURCE>');
   const iv  = CryptoJS.enc.Utf8.parse('<IV_FROM_SOURCE>');
   const decrypted = CryptoJS.AES.decrypt('<CIPHERTEXT_FROM_BURP>', key, {
     iv: iv,
     mode: CryptoJS.mode.CBC,
     padding: CryptoJS.pad.Pkcs7
   });
   console.log(decrypted.toString(CryptoJS.enc.Utf8));
   ```

   ```js
   // WebCrypto AES-GCM — browser console
   const keyData = new Uint8Array([<KEY_BYTES>]);
   const key = await crypto.subtle.importKey('raw', keyData, 'AES-GCM', false, ['decrypt']);
   const decrypted = await crypto.subtle.decrypt(
     { name: 'AES-GCM', iv: new Uint8Array([<IV_BYTES>]) },
     key,
     <CIPHERTEXT_ARRAYBUFFER>
   );
   console.log(new TextDecoder().decode(decrypted));
   ```

5. **If key is obfuscated / dynamic** → issue breakpoint guide:
   ```
   ⚠️ Key cannot be extracted statically.
   Set breakpoint at line X where encrypt() is called.
   In browser DevTools Console when paused:
     console.log(typeof key === 'string' ? key : btoa(String.fromCharCode(...new Uint8Array(key))))
   ```

### 4D. Secrets Assessment & Exploitability

For each secret found, assess exploitability:

| Secret Type | Exploitability Assessment |
|---|---|
| Firebase apiKey | Test DB read/write: check Security Rules. Try `GET /[project].firebaseio.com/.json` |
| AWS Access Key | Run `aws sts get-caller-identity` → get account ID, then check IAM permissions |
| JWT Secret | Forge token: `jwt.sign({role:'admin'}, secret)` — test in Burp |
| AES Key + IV | Decrypt captured ciphertext from Burp (use snippet from 4C) |
| Stripe sk_live | Full payment access — critical, report immediately |
| Hardcoded password | Try credential stuffing on login endpoint |

For high-entropy strings that were decoded → treat as confirmed secrets.
For high-entropy strings not decoded → note them for manual browser DevTools extraction.

### 4E. Admin / Hidden Functionality

- List all admin routes with HTTP methods to test
- Note feature flags that can be toggled client-side (e.g. `featureFlags.adminPanel = true` in console)
- Debug endpoints active in production → information disclosure risk
- `process.env.NODE_ENV === 'development'` check present → test if debug routes active in prod

### 4F. GraphQL Recon

If GraphQL patterns found:
1. Test introspection:
   ```http
   POST /graphql
   {"query": "{ __schema { types { name fields { name } } } }"}
   ```
2. List all types from gql template literals found in source
3. Flag fields not exposed in UI (internalNotes, adminFlag, etc.) → check if accessible via direct query
4. Note unauthenticated queries → IDOR candidates

### 4G. Object Structure & IDOR Analysis

For each interesting object found:
- Fields like `userId`, `orderId`, `paymentId` → test IDOR by changing IDs in Burp
- Fields like `internalNotes`, `adminFlag`, `isHidden` → check if returned in API response even when UI doesn't show them
- Fields like `accessLevel`, `permissions`, `scopes` → check if client can send these and server accepts

---

## Step 5 — Output: Structured Report

Always output in this exact format:

```
## JS Recon Report — [filename]

### 🎯 Executive Summary
[3-5 sentences: most critical findings and immediate next steps]

### 🔌 API Endpoints
[Categorized table: public / internal / admin / debug / mobile]
[Flag endpoints not visible in UI]

### 🔑 Auth Flow
[Text diagram of full auth flow]
[Client-side bypass candidates with method]
[Token storage location + XSS/CSRF risk]

### 🔐 Encryption Analysis
[Algorithm identified]
[Key/IV location: hardcoded / dynamic / obfuscated]
[Decrypt snippet if applicable]
[Breakpoint guide if key is obfuscated]

### 🚨 Secrets Found
[Each secret: type, value preview, exploitability rating: Critical/High/Medium/Low]

### 👤 Admin / Hidden Functionality
[Routes and features, exploit method]

### 📡 GraphQL
[Schema overview, introspection status, hidden fields]

### 🏗️ Object Structures (IDOR candidates)
[Objects with interesting fields, test method]

### ⚡ Prioritized Next Steps
1. [Highest risk item — specific action to take in Burp]
2. ...
```

---

## Limitations — Be Explicit With User

Always state at the end of the report:

```
### ⚠️ Static Analysis Limitations
- Obfuscated variables: X keys could not be extracted statically
  → Use browser breakpoints (see Breakpoint Guide above)
- Dynamic keys: keys derived at runtime from server/user input cannot be recovered statically
- Minified flow: auth logic may be more complex than detected — verify in DevTools
- This analysis covers: [list of scanned files]
- This analysis does NOT cover: network traffic, server-side logic, runtime behavior
```

---

## Integration with Burp MCP

When Burp MCP is connected:
1. Ask: *"Do you want me to pull JS files directly from Burp proxy history?"*
2. Filter for `.js` files in proxy history
3. Save each with hash-based filename: `/tmp/jsrecon_<hash>.js`
4. After finding endpoints, offer: *"Should I add these endpoints to Burp's active scope?"*
5. After finding secrets, offer: *"Should I create Burp match-and-replace rules for the auth headers?"*
