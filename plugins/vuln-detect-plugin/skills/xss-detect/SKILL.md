---
name: xss-detect
description: Finding Cross-Site Scripting vulnerabilities in web applications.
---

# Overview
This skill focuses on detecting Cross-Site Scripting (XSS) vulnerabilities in web applications. XSS is a common security flaw that allows attackers to inject malicious HTML tag/JS scripts into web pages viewed by other users. This skill will cover various techniques and tools for identifying and exploiting XSS vulnerabilities.

### Prerequisites & Tools

- **Playwright MCP**: Used to execute JavaScript and verify XSS vulnerabilities. 

- **Burp MCP**: Used to analyze Request/Response packets, raw HTTP headers from browsing history, or intercept data.

# Mindset

- **Context is KEY**: Always consider the context in which user input is being processed. Different contexts (HTML, JavaScript, CSS, etc.) require different payloads and encoding techniques.

- **Break and Escape**: Understand how to break out of different contexts and escape them properly to inject malicious code.

- **Data-flow tracking**: Find where user input is being reflected in the application and how it is being processed. This will help you identify potential injection points.

- **Don't trust client-side validation**: Always validate and sanitize user input on the server-side as well.

- **HTML injection is also a vulnerability.** Even if the application properly encodes user input to prevent script execution, it may still be vulnerable to HTML injection, which can be used for phishing attacks or defacement.


# Approach 

### Classification

Cross-Site Scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS allows attackers to inject malicious code into a website, which is then executed in the browser of anyone who visits the site. This can allow attackers to steal sensitive information, such as user login credentials, or to perform other malicious actions.

There are 3 main types of XSS attacks:

- Reflected XSS: In a reflected XSS attack, the malicious code is embedded in a link that is sent to the victim. When the victim clicks on the link, the code is executed in their browser. For example, an attacker could create a link that contains malicious JavaScript, and send it to the victim in an email. When the victim clicks on the link, the JavaScript code is executed in their browser, allowing the attacker to perform various actions, such as stealing their login credentials.

- Stored XSS: In a stored XSS attack, the malicious code is stored on the server, and is executed every time the vulnerable page is accessed. For example, an attacker could inject malicious code into a comment on a blog post. When other users view the blog post, the malicious code is executed in their browsers, allowing the attacker to perform various actions.

- DOM-based XSS: is a type of XSS attack that occurs when a vulnerable web application modifies the DOM (Document Object Model) in the user's browser. This can happen, for example, when a user input is used to update the page's HTML or JavaScript code in some way. In a DOM-based XSS attack, the malicious code is not sent to the server, but is instead executed directly in the user's browser. This can make it difficult to detect and prevent these types of attacks, because the server does not have any record of the malicious code.


### Black-box Testing

1. **Identify Input Points**: Find all the places where data is being inputted include from users and hidden fields, URL parameters, HTTP headers, etc.

2. **Trial and Error**: try specific characters (e.g., `<`, `>`, `"`, `'`, `/`, `;`, ...) to see if they are being reflected in the response. Is it being encoded or not?, Is it being reflected in the HTML, JavaScript, or other contexts?, Is it being decoded or not?, etc. Alway to ask yourself: "What is the context of the reflected input?".

3. **Craft Payloads**: Based on the context, craft payloads that can break out of the current context and execute JavaScript. For example, if the input is reflected in an HTML context, you might try `<script>alert(1)</script>`. If it's reflected in a JavaScript context, you might try `";alert(1);//`. If it's reflected in a URL parameter, you might try `"><script>alert(1)</script>`.

### White-box Testing

1. **Source Code Analysis**: Review the source code to identify where user input is being processed and reflected back to the user. Look for functions that handle user input and see if they are properly sanitizing and encoding the data.

2. **Data Flow Analysis**: Track the flow of user input through the application to see where it is being reflected and how it is being processed. This can help you identify potential injection points that may not be obvious from a black-box perspective.


# Methodology

Always following the OWASP Testing Guide for XSS:
- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting
- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection


## Step 1: Identify Potential Injection Points

**Identify sources** - URL/query/hash/referrer, postMessage, storage, WebSocket, server JSON

- Analyze the application's Input fields, URL parameters, form data (key and value), cookies, and HTTP headers to identify potential injection include hidden fields, URL parameters, HTTP headers, etc.

- Including but not limited to: URL, JavaScript, CSS, SVG, MathML, JSON, XML, etc.


**Trace to sinks** - Map data flow from source to sink

- Identify where the input is being reflected in the response. This can be done by searching for the input value in the response body.

- Input and output can be located at different APIs, using input signatures and output signatures can help you identify potential injection points. For example, if you input a string that contains `home_search_function with <script>alert(1)</script>`, you can search for `home_search_function` in the response to see if it is being reflected and in which context.

- Using `Playwright MCP` to render the page and analyze the DOM can help you identify where the input is being reflected and how it is being processed. This can be especially useful for identifying DOM-based XSS vulnerabilities.

## Step 2: Craft Payloads

**Classify context** - HTML node, attribute, URL, script block, event handler, JS eval-like, CSS, SVG

- Based on the context of the reflected input, craft payloads that can break out of the current context and execute JavaScript.
  - Example payloads:
    ```
      // Basic payload
      <script>alert('XSS')</script>
      <scr<script>ipt>alert('XSS')</scr<script>ipt>

      // Img payload
      <img src=x onerror=alert('XSS');>
      <img src=x onerror=alert('XSS')//

      // Svg payload
      <svg id=alert(1) onload=eval(id)>
      <svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)

      // Div payload
      <div onpointerover="alert(45)">MOVE HERE</div>
      <div onpointerdown="alert(45)">MOVE HERE</div>

      // HTML5 tags
      <textarea autofocus onfocus=alert(1)>
      <keygen autofocus onfocus=alert(1)>
      <video/poster/onerror=alert(1)>

      // JS Context
      -(confirm)(document.domain)//
      ; alert(1);//
    ```
  - All payload must be followed by instruction in `./assets/0-XSS Original.md` to make sure the payload is executed.

**Assess defenses** - Output encoding, sanitizer, CSP, Trusted Types, DOMPurify config

- If input be escaped or encoded, try to find ways to bypass the encoding or escaping. 
  - Example encoding bypass payloads:
    ```
      // Bypass Case Sensitive
      <sCrIpt>alert(1)</ScRipt>
      <ScrIPt>alert(1)</ScRipT>

      // Bypass Tag Blacklist
      <script x>
      <script x>alert('XSS')<script y>

      // Bypass Space Filter
      <img/src='1'/onerror=alert(0)>

      // Bypass onxxxx Blacklist
      <object onafterscriptexecute=confirm(0)>
      <object onbeforescriptexecute=confirm(0)>
    ```
  - All payload must be followed by instruction in `./assets/0-Filter Bypass.md` to make sure the payload is executed.

**Multi-channel** - Test across REST, GraphQL, WebSocket, SSE, service workers

## Step 3: Verify the Vulnerability

- **Playwright MCP**: Use Playwright to execute the payload and verify if the XSS vulnerability is present. This can be done by checking if the alert box is triggered or if the malicious script is executed.

# Examples of SQL Injection Vulnerabilities

## Reflected XSS
```
Request GET /search?q=anything HTTP/1.1
Response <p class="search-result">You searched for: anything</p>

Request GET /search?q=<script>alert(1)</script> HTTP/1.1
Response <p class="search-result">You searched for: <script>alert(1)</script></p>

```

## Stored XSS
```
// Identifing data flow and injection point
Request POST /comment HTTP/1.1
Body comment=This is a comment

// Identifying the data input being reflected in the response
Request GET /comments HTTP/1.1
Response <p class="comment">This is a comment</p>

// creating a payload and verifying the vulnerability
Request POST /comment HTTP/1.1
Body comment=<script>alert(1)</script>

// Verifying the vulnerability
Request GET /comments HTTP/1.1
Response <p class="comment"><script>alert(1)</script></p>
```

## DOM-based XSS
```
Request GET /searchMessage?search=hello HTTP/1.1
Response <span id="searchMessage">hello</span> 
          // sink is innerHTML, so the input is being reflected in the response without proper encoding
          ...
          // source in the JavaScript code
          function doSearchQuery(query) {
            document.getElementById('searchMessage').innerHTML = query;
          }
          var query = (new URLSearchParams(window.location.search)).get('search');
          if(query) {
            doSearchQuery(query);
          }

// creating a payload and verifying the vulnerability
Request GET /searchMessage?search=<script>alert(1)</script> HTTP/1.1
Response <span id="searchMessage"><script>alert(1)</script></span> 
          // the payload is executed in the browser, indicating a DOM-based XSS vulnerability 
```

## Special Contexts

Including but not limited to: URL, JavaScript, CSS, SVG, MathML, JSON, XML, etc.

### Email

- Most clients strip scripts but allow CSS/remote content
- Use CSS/URL tricks only if relevant; avoid assuming JS execution

### PDF and Docs

- PDF engines may execute JS in annotations or links
- Test `javascript:` in links and submit actions

### File Uploads

- SVG/HTML uploads served with `text/html` or `image/svg+xml` can execute inline
- Verify content-type and `Content-Disposition: attachment`
- Mixed MIME and sniffing bypasses; ensure `X-Content-Type-Options: nosniff`

# Tips & Tricks

## Attack Vectors

- Don't limit yourself to just input fields. XSS vulnerabilities can be found in various places such as URL parameters, HTTP headers, cookies, file uploads, etc. Always consider all possible attack vectors when testing for XSS vulnerabilities.

- Always consider the context of the reflected input. Different contexts (HTML, JavaScript, CSS, etc.) require different payloads and encoding techniques.


## Bypass WAF techniques

- If you suspect that a WAF is in place, try to identify the WAF and research its known bypass techniques. Some common WAFs include ModSecurity, Cloudflare, Incapsula, Akamai, etc.

- All type of payloads to bypass WAF must be followed by instruction in `./assets/3-Common WAF Bypass.md` to make sure the payload is executed.

- Example WAF bypass techniques include:
  - Cloudflare
    ```js
    <svg/onrandom=random onload=confirm(1)>
    <video onnull=null onmouseover=confirm(1)>
    ```
  - Akamai WAF
    ```js
    ?"></script><base%20c%3D=href%3Dhttps:\mysite>
    ```

- If you are able to bypass the WAF, try to identify the specific rules that are being triggered and craft payloads that can bypass those rules

- Try to find blog posts, research papers, or other resources that discuss bypass techniques for the specific WAF you are dealing with. This can provide valuable insights and ideas for crafting effective payloads.

## False positives

- Reflected content safely encoded in the exact context
- Trusted Types enforced on sinks; DOMPurify in strict mode with URI allowlists
- Scriptable contexts disabled (no HTML pass-through, safe URL schemes enforced)

## Framework-Specific

### React

- Primary sink: `dangerouslySetInnerHTML`
- Secondary: setting event handlers or URLs from untrusted input
- Bypass patterns: unsanitized HTML through libraries; custom renderers using innerHTML

### Vue

- Sinks: `v-html` and dynamic attribute bindings
- SSR hydration mismatches can re-interpret content

### Angular

- Legacy expression injection (pre-1.6)
- `$sce` trust APIs misused to whitelist attacker content

### Svelte

- Sinks: `{@html}` and dynamic attributes

### Markdown/Richtext

- Renderers often allow HTML passthrough; plugins may re-enable raw HTML
- Sanitize post-render; forbid inline HTML or restrict to safe whitelist

## Pro tips

1. Start with context classification, not payload brute force
2. Use DOM instrumentation to log sink usage; it reveals unexpected flows
3. Keep a small, curated payload set per context and iterate with encodings
4. Validate defenses by configuration inspection and negative tests
5. Treat SVG/MathML as first-class active content; test separately
6. Re-run tests under different transports and render paths (SSR vs CSR vs hydration)

# References

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting