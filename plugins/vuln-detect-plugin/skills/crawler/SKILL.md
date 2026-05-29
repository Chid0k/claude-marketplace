---
name: crawler
description: Crawling web applications to identify potential vulnerabilities.
---

# Overview

The crawler skill is designed to identify application entry points. Enumerating the application and its attack surface is a key precursor before any thorough testing can be undertaken, as it allows the tester to identify likely areas of weakness. This aims to help identify and map out areas within the application that should be investigated once enumeration and mapping have been completed.

## Prerequisites & Tools Coordination

- **Assistant Agent**: Always using this skill with the Assistant Agent to coordinate and manage the crawling process, ensuring that all interactions are captured and analyzed effectively.
- **Playwright**: A Node.js library for automating browser interactions, used to navigate and interact with web applications during crawling.
- **Burp MCP**: Used to analyze Request/Response packets, raw HTTP headers from browsing history, or intercept data.

## Target 

- Identify possible entry and injection points through request and response analysis.
- Understand the application structure and logic, including hidden endpoints, parameters, and functionalities that may be vulnerable to attacks.

---
# Mindset

When operating as an AI pentester or bug bounty hunter, you must adopt the following mindset rules:

1. **Gathering all information**: Collect as much information as possible about the target application before initiating any testing.
  - Interact with the application as a normal user would, exploring all functionalities and features to understand how the application works and where potential vulnerabilities may lie.
  - Must be using the Playwright with proxy set to Burp MCP to capture all interactions and analyze them for potential vulnerabilities.

2. **Method and protocol analysis**: Pay attention to the HTTP methods used (GET, POST, PUT, DELETE, etc.) and the parameters passed in requests.
  - Identify all parameters are being used, how they are being processed, and whether they are reflected in responses or stored in the application.
  - Using Options or Trace or Custom HTTP methods to identify HTTP method support and potential misconfigurations.

3. **Spreadsheet**: Export all findings into a spreadsheet for further analysis and to keep track of potential vulnerabilities and areas of interest. 
  - Export Markdown files: `entry_point.md`
  - Columns: `Number`, `URL`, `Method`, `Parameters` (include hidden or custom), `Methods Supported`, `Authentication Required`, `Functionality`, `Notes`
  - Example:

  | Number | URL | Method | Parameters | Methods Supported | Authentication Required | Functionality | Notes |
| :---: | :--- | :---: | :--- | :---: | :---: | :--- | :--- |
| **#001** | `http://example.com/login` | `GET` | Không có | `GET`, `POST` | **No** | Screen login function. |  None |
| **#002** | `http://api.example.com/login` | `POST` | `username`, `password`, `csrf_token` (hidden) | `POST` | **No** | Submit login form. | Probe Stack Traces |
| **#003** | `http://api.example.com/v1/users/profile` | `GET` | `user_id` (URL parameter) | `GET`, `PUT`, `DELETE` | **Yes** | Get current user profile. | Required user verification |
| **#004** | `http://api.example.com/v1/api/data/export` | `POST` | `csrf_token` (hidden) | `POST` | **No** | Submit data export form. | Create data in `/api/data/create` before export |

---
# Methodology

> MUST BE FOLLOWED TO ENSURE COMPREHENSIVE COVERAGE AND ACCURATE IDENTIFICATION OF ENTRY POINTS

## Black Box Testing

1. **Step 1**: Mustbe enbale Playwright MCP with proxy set to `127.0.0.1:8080` to capture all interactions in BurpSuite with the target application.
  - Check all requests in Playwright MCP to ensure that they are being captured correctly and that all interactions with the application are being logged for analysis.
  - All requests from Playwright must go through Burpsuite.
  - Use `PlayWright` in parallel with `Curl`, custom proxy through `127.0.0.1:8080` to ensure that all interactions are captured by Burp MCP for analysis.
  - DO NOT USE THE `curl` OR `Playwright` COMMANDS INDIVIDUALLY; you must combine both tools.

2. **Step 2**: Interact with the application as a normal user would, exploring all functionalities and features to understand how the application works and where potential vulnerabilities may lie.
 - For each page or functionality, must bef open new a windows of Playwright and interact with the application, ensuring that all interactions are captured by Burp MCP for analysis.

 - Interact with forms, buttons, links, and any user-controllable elements to identify potential entry points and parameters. Using realistic input values to trigger different application behaviors and responses. DO NOT use destructive payloads during this phase.

 - Enter a form and upload a valid file according to the application context, such as a profile picture or document, to see how the application handles file uploads and whether it exposes any vulnerabilities in the process.

3. **Step 3**: Analyze the captured requests and responses in Burp MCP to identify potential entry points, parameters, and functionalities that may be vulnerable to attacks.
  - Each request in HTTP history tab of Burp MCP should be analyzed to identify the URL, HTTP method, parameters (including hidden or custom), supported methods, authentication requirements, functionality, and any notes on potential vulnerabilities or areas of interest.

  - Can be calling `client-side-detect` to analyze HTML/JS responses to identify hidden fields, custom parameters, and any client-side logic that may indicate potential vulnerabilities or areas of interest.

  - Save any requests to spreadsheet with the following columns: `Number`, `URL`, `Method`, `Parameters` (include hidden or custom), `Methods Supported`, `Authentication Required`, `Functionality`, `Notes`


### Example
  ```
  GET /shoppingApp/buyme.asp?CUSTOMERID=100&ITEM=z101a&PRICE=62.50&IP=x.x.x.x HTTP/1.1
  Host: x.x.x.x
  Cookie: SESSIONID=Z29vZCBqb2IgcGFkYXdhIG15IHVzZXJuYW1lIGlzIGZvbyBhbmQgcGFzc3dvcmQgaXMgYmFy
  ```
  Here the tester would note all the parameters of the request such as CUSTOMERID, ITEM, PRICE, IP, and the Cookie header, which may contain sensitive information or be vulnerable to manipulation.

# Tips & Tricks

- Pay attention to hidden fields in forms, as they may contain sensitive information or be vulnerable to manipulation.
- Look for custom parameters in URLs or forms that may not be immediately visible but could be used to interact with the application in unexpected ways.
- Use realistic input values to trigger different application behaviors and responses, which can help identify potential vulnerabilities or areas of interest.
- Always use non-destructive payloads during the crawling phase to avoid causing any harm to the application or its data.
- When analyzing responses, look for any indications of how the application processes input, such as error messages, reflected parameters, or changes in the application's behavior that may indicate potential vulnerabilities.
- Pay attention to the application's structure and logic, as this can help identify hidden endpoints, parameters, and functionalities that may be vulnerable to attacks.

# References

- OWASP Web Security Testing Guide - https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points