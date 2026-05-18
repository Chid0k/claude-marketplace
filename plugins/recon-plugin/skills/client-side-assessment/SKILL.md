---
name: client-side-assessment
description: Perform client-side assessment vulnerability scans on web applications to identify potential security weaknesses and vulnerabilities.
disable-model-invocation: true
---

# Webpage Content Review & Browser Storage Security Auditor

## Overview
This skill guides performing automated information security testing and evaluation on the client-side interface of web applications. The focus of this skill is detecting information leaks in source code/static files and evaluating the secure configuration of browser storage mechanisms.

## Prerequisites & Tools Coordination
- **Playwright MCP**: Preferred for direct interaction with the actual web application, full JavaScript rendering, user behavior simulation, and direct access to browser APIs.

- **Burp MCP**: Used to analyze Request/Response packets, raw HTTP headers from browsing history, or intercept data.

---

## Procedural Workflow

### Step 1: Data Collection & Interface Rendering
1. Upon receiving a URL from User Input, use **Playwright MCP** to open the browser and navigate to the target.

2. Ensure the application is configured to wait for complete JavaScript rendering (e.g., use the `networkidle` state or wait for important selectors).

3. Collect the entire HTML DOM content, static JavaScript files (.js), and the loaded directory structure.

### Step 2: Analysis of HTML/JS Source Code and Static Files (Information Leakage)

Use regular expressions (Regex) or manually traverse the collected source code to search for:
1. **Comments:** Scan all the comment tag in HTML and `/* */`, `//` in JS.

2. **Metadata & Framework Information:** Check the `<meta>` tags (e.g., `generator`, `version`, `author`) to identify the CMS, Web Framework, or Server Core version.

3. **Hardcoded Sensitive Information in JS:**

- Search for API Keys, JWTs, Credentials, AWS Access Keys, Firebase Config, or Private Keys.

- Search for sensitive keywords: `password`, `pass`, `admin`, `token`, `secret`, `key`, `sql`, `query`, `db_`, `config`, `vlan`, `staging`, `test-env`.

2. **Metadata & Framework Information:**

- Examine the `<meta>` tags (e.g., `generator`, `version`, `author`) to identify the CMS, Web Framework, or Server Core version.
- Read response headers (e.g., `X-Powered-By`, `Server`) to gather information about the underlying technologies and versions used by the application.

4. **Hardcoded Sensitive Information in JS:**

- Search for API Keys, JWTs, Credentials, AWS Access Keys, Firebase Config, or Private Keys. 4. **Debug Information:**

- Find functions like `console.log()`, `console.dir()`, `alert()`, or code blocks with the variable `debug = true` that are printing system/user information to the console.

5. **Leaked Paths & Links:**

- Extract all hidden URLs and endpoints within the JS source code.

- Search for links to internal environments, `staging`, `test`, `dev` environments, or configuration backup files with extensions `.bak`, `.old`, `.txt`, `.json`, `.sql`.

6. **Functionality Analysis:**

- Identify functions that handle sensitive operations or stranger functionality (e.g., `login()`, `submitPayment()`, `updateProfile()`, `encodingRequest()`, ...) and analyze their code for potential vulnerabilities (e.g., lack of input validation, insecure API calls).

- Check for any client-side logic that could be manipulated by an attacker (e.g., price manipulation, role escalation) and whether there are any client-side checks that should be enforced on the server side.

- Look for any use of `eval()`, `setTimeout()`, or `setInterval()` with dynamic content, which could indicate potential XSS vulnerabilities.

- Analyze the use of third-party libraries and frameworks for known vulnerabilities or outdated versions that may have security issues.

### Step 3: Input Point & Endpoint Structure Analysis
1. **Hidden Inputs:** Search for `<input type="hidden">` tags in HTML forms to identify any hidden logic control parameters (such as `role`, `price`, `user_id`) that users can manipulate.

2. **HTTP Headers & URL Parameters:** - List all parameters in the URL (Query Parameters).

- Use Burp MCP or Playwright Network Event to analyze Custom HTTP Headers, Cookies, and Cookie security attributes (`Secure`, `HttpOnly`, `SameSite`).

3. **Communication Method:** Determine which protocol the application uses (REST API, SOAP XML, or WebSockets real-time connection channel) to guide corresponding testing.

### Step 4: Check Browser Storage Mechanism
Use **Playwright MCP** to execute JavaScript code (`page.evaluate()`) to directly check:
1. **LocalStorage & SessionStorage:**

- Extract all key-value pairs from memory.

- Check if identifiers (Session Tokens, Access Tokens), personal information (PII - email, phone number, balance), and configuration information are stored as unencrypted *cleartext*.

2. **XSS Leakage Potential:** Assess whether the data in Storage is loosely configured. (If the application is vulnerable to XSS, an attacker can obtain all this data via `atob(localStorage.getItem(...))`).

3. **IndexedDB & WebSQL:** Query local databases in the browser to find sensitive data stored long-term without protection mechanisms.

4. **Data Integrity:**

- Manually change values ​​in Storage (e.g., change `is_admin=false` to `true`, change `price=1000` to `1`).

- Reload the page or perform the next action to see if the application handles client-side data trust without server-side validation.

5. **Data Deletion Mechanism:** Check if `SessionStorage` and sensitive data are completely cleared/destroyed after the user logs out or closes the browser tab.

---

## Best Practices & Output Format

Upon completion of the analysis, the output should be organized into a clearly structured report with the following sections:

### 1. Target Summary
- **URL/Application:** [Website link or system identifier]

- **Detection Technology:** [Framework, CMS, JS Library, REST/WebSockets connection protocol...]

### 2. List of Discovered API Endpoints in JS
List all APs in detail.