#!/usr/bin/env python3
"""
JS Recon Script for Pentest — v2.0
Fixes: minified JS context window, entropy false positives, auth flow logic,
       obfuscation detection, crypto flow tracing, multi-file support.

Usage:
  python recon_js.py --file <path.js> [--output markdown|json] [--beautify]
  cat file.js | python recon_js.py --stdin [--beautify]
  python recon_js.py --file chunk1.js --file chunk2.js   # multi-file
"""

import re
import sys
import json
import math
import hashlib
import argparse
import textwrap
from collections import defaultdict
from pathlib import Path

from beautify_js import beautify_javascript

# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT EXTRACTION — Safe for minified JS (character window, not line)
# ─────────────────────────────────────────────────────────────────────────────
CONTEXT_WINDOW = 120  # chars each side of a match

def get_context(content: str, match_start: int, match_end: int, window: int = CONTEXT_WINDOW) -> dict:
    """Extract a character-window around a match. Safe for minified single-line JS."""
    total = len(content)
    ctx_start = max(0, match_start - window)
    ctx_end   = min(total, match_end + window)
    snippet   = content[ctx_start:ctx_end].replace('\n', ' ').strip()
    # Estimate line number cheaply (count newlines up to match)
    line_no = content[:match_start].count('\n') + 1
    return {
        "line":    line_no,
        "context": snippet[:300],  # hard cap — never dump whole minified file
    }

# ─────────────────────────────────────────────────────────────────────────────
# OBFUSCATION DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def detect_obfuscation(content: str) -> dict:
    signals = {}

    # eval-based packing (e.g. UglifyJS packer)
    if re.search(r'\beval\s*\(', content):
        signals["eval_usage"] = True

    # Function constructor obfuscation
    if re.search(r'new\s+Function\s*\(', content):
        signals["function_constructor"] = True

    # Heavy hex string encoding (_0x...)
    hex_vars = re.findall(r'_0x[a-f0-9]{4,}', content)
    if len(hex_vars) > 10:
        signals["hex_variable_names"] = len(hex_vars)

    # Huge hex string literals
    hex_strings = re.findall(r'["\'](?:\\x[0-9a-f]{2}){8,}["\']', content)
    if hex_strings:
        signals["hex_string_literals"] = len(hex_strings)

    # Base64 encoded code blocks
    b64_blocks = re.findall(r'["\']([A-Za-z0-9+/]{100,}={0,2})["\']', content)
    if b64_blocks:
        signals["base64_code_blocks"] = len(b64_blocks)

    # String array rotation (common in obfuscators)
    if re.search(r'\[.*\]\s*\[\s*\d+\s*\]', content) and len(hex_vars) > 5:
        signals["string_array_rotation"] = True

    # Single-line minified (> 5000 chars per line on average)
    lines = content.split('\n')
    avg_len = len(content) / max(len(lines), 1)
    if avg_len > 5000:
        signals["minified"] = True
        signals["avg_line_length"] = int(avg_len)

    return signals

# ─────────────────────────────────────────────────────────────────────────────
# BEAUTIFIER — Python jsbeautifier first, js-beautify CLI fallback
# ─────────────────────────────────────────────────────────────────────────────
def try_beautify(content: str) -> tuple[str, bool]:
    return beautify_javascript(content)

# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY — with false-positive filtering
# ─────────────────────────────────────────────────────────────────────────────
DATA_URI_RE = re.compile(r'data:[a-z]+/[a-z]+;base64,', re.IGNORECASE)
COMMON_NOISE = {
    # known non-secret high-entropy patterns
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "0123456789abcdefABCDEF",
}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    e = 0.0
    for count in freq.values():
        p = count / len(s)
        e -= p * math.log2(p)
    return e

def is_high_entropy_secret(s: str, threshold: float = 3.8) -> bool:
    if len(s) < 20 or len(s) > 512:
        return False
    if s in COMMON_NOISE:
        return False
    # Filter data URIs
    if DATA_URI_RE.search(s):
        return False
    # Filter obvious base64 image/SVG chunks (very long, low variety)
    if len(s) > 200 and s.count('=') > 5:
        return False
    return shannon_entropy(s) > threshold

# ─────────────────────────────────────────────────────────────────────────────
# OBFUSCATED VALUE DECODER — best-effort extraction
# ─────────────────────────────────────────────────────────────────────────────
def try_decode_value(raw: str) -> dict:
    """Attempt to decode obfuscated key values."""
    result = {"raw": raw, "decoded": None, "method": None}

    # Hex escape sequences: \x41\x42...
    if re.search(r'\\x[0-9a-fA-F]{2}', raw):
        try:
            decoded = bytes.fromhex(re.sub(r'\\x', '', raw)).decode('utf-8', errors='replace')
            result.update({"decoded": decoded, "method": "hex_unescape"})
            return result
        except Exception:
            pass

    # Unicode escapes: \u0041...
    if re.search(r'\\u[0-9a-fA-F]{4}', raw):
        try:
            decoded = raw.encode().decode('unicode_escape')
            result.update({"decoded": decoded, "method": "unicode_unescape"})
            return result
        except Exception:
            pass

    # Base64
    if re.match(r'^[A-Za-z0-9+/]+=*$', raw) and len(raw) % 4 == 0 and len(raw) >= 16:
        try:
            import base64
            decoded = base64.b64decode(raw).decode('utf-8', errors='replace')
            if decoded.isprintable():
                result.update({"decoded": decoded, "method": "base64"})
                return result
        except Exception:
            pass

    return result

# ─────────────────────────────────────────────────────────────────────────────
# PATTERN DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    r'fetch\s*\(\s*["`\']((?:/[^\s"`\']+|https?://[^\s"`\']+))["`\']',
    r'axios\s*\.\s*(?:get|post|put|delete|patch|head)\s*\(\s*["`\']((?:/[^\s"`\']+|https?://[^\s"`\']+))["`\']',
    r'axios\s*\(\s*\{[^}]{0,200}url\s*:\s*["`\']((?:/[^\s"`\']+|https?://[^\s"`\']+))["`\']',
    r'(?:baseURL|BASE_URL|API_URL|apiUrl|apiBase|endpoint)\s*[:=]\s*["`\'](https?://[^\s"`\']+|/[^\s"`\']+)["`\']',
    r'["`\'](/(?:api|v\d+|graphql|admin|internal|debug|mobile|auth|oauth|rpc|gateway|proxy|service)[/\w\-\.]*)["`\']',
    r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["`\']((?:/[^\s"`\']+|https?://[^\s"`\']+))["`\']',
    r'\$http\s*\.\s*(?:get|post|put|delete)\s*\(\s*["`\']((?:/[^\s"`\']+|https?://[^\s"`\']+))["`\']',
]

SECRET_PATTERNS = {
    "Firebase apiKey":      r'apiKey\s*:\s*["`\']([A-Za-z0-9_\-]{30,})["`\']',
    "Firebase authDomain":  r'authDomain\s*:\s*["`\']([^\s"`\']{10,})["`\']',
    "Firebase projectId":   r'projectId\s*:\s*["`\']([^\s"`\']{5,})["`\']',
    "AWS Access Key":       r'(?:AKIA|ASIA|AROA)[A-Z0-9]{16}',
    "AWS Secret":           r'(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["`\']([A-Za-z0-9/+=]{40})["`\']',
    "JWT Secret":           r'(?:JWT_SECRET|jwtSecret|jwt_secret)\s*[=:]\s*["`\']([^"`\']{8,})["`\']',
    "Generic API Key":      r'(?:api_key|apikey|API_KEY|x-api-key|APIKEY)\s*[=:]\s*["`\']([^"`\']{8,})["`\']',
    "Client Secret":        r'(?:client_secret|clientSecret|CLIENT_SECRET)\s*[=:]\s*["`\']([^"`\']{8,})["`\']',
    "Bearer Token":         r'["`\']Bearer\s+([A-Za-z0-9\-_\.]+)["`\']',
    "Private Key PEM":      r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "AES Key (32 hex)":     r'(?:aesKey|AES_KEY|encryptionKey|secretKey)\s*[=:]\s*["`\']([0-9a-fA-F]{32,64})["`\']',
    "AES IV":               r'(?:iv|IV|aesIv|initVector)\s*[=:]\s*["`\']([0-9a-fA-F]{16,32})["`\']',
    "RSA Public Modulus":   r'-----BEGIN (?:RSA )?PUBLIC KEY-----',
    "Stripe Key":           r'(?:sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]{24,}',
    "Google OAuth":         r'[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com',
    "Hardcoded Password":   r'(?:password|passwd|pwd)\s*[=:]\s*["`\']([^"`\']{4,})["`\']',
    "Generic Secret":       r'\bsecret\b\s*[=:]\s*["`\']([^"`\']{8,})["`\']',
    "SendGrid/Mailgun Key": r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|key-[0-9a-zA-Z]{32}',
}

# ─────────────────────────────────────────────────────────────────────────────
# AUTH LOGIC — detailed categories
# ─────────────────────────────────────────────────────────────────────────────
AUTH_CATEGORIES = {
    "Token Storage": [
        r'localStorage\s*\.\s*setItem\s*\(\s*["`\']([^"`\']*(?:token|auth|jwt|session|access)[^"`\']*)["`\']',
        r'sessionStorage\s*\.\s*setItem\s*\(\s*["`\']([^"`\']*(?:token|auth|jwt)[^"`\']*)["`\']',
        r'Cookies\s*\.\s*set\s*\(\s*["`\']([^"`\']*(?:token|auth|session)[^"`\']*)["`\']',
        r'document\.cookie\s*=.*(?:token|auth|session)',
    ],
    "Token Usage / Headers": [
        r'Authorization\s*:\s*["`\']?Bearer',
        r'headers\s*[\[{].*["`\'](?:Authorization|X-Auth-Token|X-API-Key|X-Access-Token)["`\']',
        r'\.setRequestHeader\s*\(\s*["`\']Authorization',
        r'interceptors\s*\.\s*request',   # axios interceptor adding auth
    ],
    "Token Retrieval": [
        r'localStorage\s*\.\s*getItem\s*\(\s*["`\']([^"`\']*(?:token|auth|jwt|session)[^"`\']*)["`\']',
        r'sessionStorage\s*\.\s*getItem\s*\(\s*["`\']([^"`\']*(?:token|auth|jwt)[^"`\']*)["`\']',
        r'Cookies\s*\.\s*get\s*\(\s*["`\']([^"`\']*(?:token|auth)[^"`\']*)["`\']',
    ],
    "Refresh Flow": [
        r'refresh_token',
        r'refreshToken',
        r'/(?:auth|token)/refresh',
        r'\.refresh\s*\(',
        r'grant_type\s*[:=]\s*["`\']refresh_token["`\']',
    ],
    "Client-Side Auth Check (bypass candidate)": [
        r'if\s*\(\s*!?\s*(?:isAuthenticated|isLoggedIn|isAuth|currentUser|loggedIn)\s*\)',
        r'if\s*\(\s*!?\s*(?:token|accessToken|authToken)\s*\)',
        r'role\s*[=!]==?\s*["`\'](?:admin|user|moderator|superuser|root)["`\']',
        r'permission\s*\.includes\s*\(',
        r'hasRole\s*\(',
        r'can\s*\(\s*["`\']',            # CASL / permission check
        r'guard\s*\(',
        r'isAdmin\s*[=!]==?\s*(?:true|false)',
    ],
    "Login / Registration Flow": [
        r'createUserWithEmailAndPassword',
        r'signInWithEmailAndPassword',
        r'signInWithPopup',
        r'signInWithRedirect',
        r'/(?:auth|login|signin|signup|register)',
        r'username\s*[:=]',
        r'password\s*[:=]',
        r'credentials\s*[:=]',
    ],
    "Response Auth Processing (bypass logic)": [
        r'(?:response|res)\s*\.\s*(?:status|statusCode)\s*[=!]==?\s*(?:200|401|403)',
        r'if\s*\(\s*(?:response|res|data)\s*\.\s*(?:success|ok|authenticated|authorized)\s*\)',
        r'(?:response|res|data)\s*\.\s*(?:token|accessToken|jwt)',
        r'if\s*\(\s*(?:response|res)\s*\.\s*(?:role|permission|isAdmin)',
    ],
    "Crypto / Encoding": [
        r'CryptoJS\s*\.\s*(?:AES|DES|TripleDES|Rabbit|RC4)\s*\.\s*(?:encrypt|decrypt)',
        r'crypto\s*\.\s*subtle\s*\.\s*(?:encrypt|decrypt|importKey|generateKey)',
        r'new\s+JSEncrypt\s*\(',         # RSA library
        r'new\s+NodeRSA\s*\(',
        r'forge\s*\.\s*(?:pki|rsa|aes)', # node-forge
        r'btoa\s*\(',
        r'atob\s*\(',
        r'\.encrypt\s*\(',
        r'\.decrypt\s*\(',
        r'AES\.encrypt',
        r'AES\.decrypt',
        r'md5\s*\(',
        r'sha(?:1|256|512)\s*\(',
        r'hmac\s*\(',
        r'pbkdf2\s*\(',
        r'bcrypt',
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO FLOW TRACER — find encrypt/decrypt call sites + nearby key usage
# ─────────────────────────────────────────────────────────────────────────────
CRYPTO_FLOW_PATTERNS = [
    # CryptoJS
    (r'CryptoJS\.AES\.encrypt\s*\(([^)]{0,200})\)', "CryptoJS.AES.encrypt"),
    (r'CryptoJS\.AES\.decrypt\s*\(([^)]{0,200})\)', "CryptoJS.AES.decrypt"),
    (r'CryptoJS\.(?:HmacSHA256|HmacSHA1|SHA256)\s*\(([^)]{0,200})\)', "CryptoJS.HMAC/Hash"),
    # WebCrypto
    (r'crypto\.subtle\.encrypt\s*\(([^)]{0,300})\)', "WebCrypto.encrypt"),
    (r'crypto\.subtle\.decrypt\s*\(([^)]{0,300})\)', "WebCrypto.decrypt"),
    (r'crypto\.subtle\.importKey\s*\(([^)]{0,300})\)', "WebCrypto.importKey"),
    # JSEncrypt / forge
    (r'\.encrypt\s*\(([^)]{0,200})\)', "generic .encrypt()"),
    (r'\.decrypt\s*\(([^)]{0,200})\)', "generic .decrypt()"),
]

def trace_crypto_flows(content: str) -> list:
    flows = []
    for pattern, label in CRYPTO_FLOW_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            ctx = get_context(content, m.start(), m.end(), window=200)
            args = m.group(1).strip().replace('\n', ' ')[:200] if m.lastindex else ""
            flows.append({
                "function":  label,
                "arguments": args,
                **ctx,
            })
    return flows

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN / HIDDEN PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
ADMIN_PATTERNS = [
    r'["`\'](/(?:admin|administrator|superuser|root|management|backstage|backoffice|internal|debug|devtools|console|panel|cp|staff|ops|hidden|secret)[/\w\-\.]*)["`\']',
    r'role\s*[=!]==?\s*["`\'](?:admin|superadmin|root|system|staff|operator)["`\']',
    r'isAdmin\s*[=!]==?\s*(?:true|1)',
    r'featureFlag[s]?\s*[\[.]\s*["`\']([^"`\']+)["`\']',
    r'debug(?:Mode|Flag|Enabled)\s*[=:]\s*true',
    r'__debug__',
    r'process\.env\.NODE_ENV\s*[=!]==?\s*["`\'](?:development|dev|test)["`\']',
    r'enableExperiment',
    r'INTERNAL_API',
    r'adminOnly\s*:\s*true',
    r'requiresAdmin\s*:\s*true',
]

# ─────────────────────────────────────────────────────────────────────────────
# GRAPHQL PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
GRAPHQL_PATTERNS = [
    (r'gql\s*`([^`]{10,})`',                            "gql template literal"),
    (r'(?:query|mutation|subscription)\s+\w+\s*\{[^}]+\}', "inline operation"),
    (r'__typename',                                       "__typename usage"),
    (r'__schema',                                         "introspection attempt"),
    (r'ApolloClient',                                     "ApolloClient init"),
    (r'GraphQLClient',                                    "GraphQLClient init"),
    (r'useQuery\s*\(',                                    "useQuery hook"),
    (r'useMutation\s*\(',                                 "useMutation hook"),
    (r'/graphql',                                         "GraphQL endpoint"),
]

# ─────────────────────────────────────────────────────────────────────────────
# OBJECT STRUCTURE PATTERNS — find interesting data shapes
# ─────────────────────────────────────────────────────────────────────────────
INTERESTING_FIELDS = [
    "userId", "user_id", "orderId", "order_id", "paymentStatus", "payment_status",
    "internalNotes", "internal_notes", "adminFlag", "admin_flag", "roleId", "role_id",
    "secretKey", "secret_key", "accessLevel", "access_level", "isAdmin", "is_admin",
    "accountBalance", "creditCard", "ssn", "dob", "dateOfBirth",
    "permissions", "scopes", "grants", "privilege",
]
FIELD_RE = re.compile(r'\b(' + '|'.join(INTERESTING_FIELDS) + r')\b', re.IGNORECASE)

def find_object_structures(content: str) -> list:
    results = []
    # TypeScript interfaces / type aliases
    for m in re.finditer(r'(?:interface|type)\s+(\w+)\s*(?:extends\s+\w+\s*)?\{([^}]{10,})\}',
                          content, re.IGNORECASE | re.DOTALL):
        body = m.group(2)
        if FIELD_RE.search(body):
            ctx = get_context(content, m.start(), m.end(), window=50)
            results.append({"kind": "TS interface/type", "name": m.group(1), "body": body.strip()[:400], **ctx})

    # Object literals with interesting fields
    for m in re.finditer(r'\{([^{}]{20,300})\}', content, re.DOTALL):
        body = m.group(1)
        if FIELD_RE.search(body):
            ctx = get_context(content, m.start(), m.end(), window=50)
            results.append({"kind": "object literal", "name": None, "body": body.strip()[:400], **ctx})

    return results

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────────────────────────────────────
def scan_js(content: str, filename: str = "target.js") -> dict:
    findings = {
        "filename":           filename,
        "size_bytes":         len(content.encode()),
        "obfuscation":        {},
        "api_endpoints":      [],
        "secrets":            [],
        "auth_logic":         {},
        "crypto_flows":       [],
        "admin_hints":        [],
        "graphql":            [],
        "object_structures":  [],
        "high_entropy":       [],
        "beautified":         False,
        "notes":              [],
    }

    # ── Obfuscation detection
    findings["obfuscation"] = detect_obfuscation(content)
    if findings["obfuscation"].get("minified"):
        findings["notes"].append("⚠️  File is minified — context windows used instead of line numbers.")
    if findings["obfuscation"].get("hex_variable_names"):
        findings["notes"].append(
            f"⚠️  {findings['obfuscation']['hex_variable_names']} obfuscated variable names detected (_0xXXXX). "
            "Hardcoded keys inside obfuscated blocks may not be recoverable via static analysis. "
            "Use browser DevTools breakpoints to intercept runtime values."
        )

    # ── 1. API Endpoints
    seen_endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            ep = m.group(1).strip()
            if ep in seen_endpoints or len(ep) < 2:
                continue
            seen_endpoints.add(ep)
            findings["api_endpoints"].append({"endpoint": ep, **get_context(content, m.start(), m.end())})

    # ── 2. Secrets (with decode attempt)
    for secret_type, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, content, re.IGNORECASE):
            raw_value = m.group(1) if m.lastindex else m.group(0)
            decode_result = try_decode_value(raw_value)
            ctx = get_context(content, m.start(), m.end())
            entry = {
                "type":           secret_type,
                "raw_preview":    raw_value[:60] + ("…" if len(raw_value) > 60 else ""),
                "decoded":        decode_result.get("decoded"),
                "decode_method":  decode_result.get("method"),
                **ctx,
            }
            findings["secrets"].append(entry)

    # ── 3. Auth Logic
    auth_findings = defaultdict(list)
    for category, patterns in AUTH_CATEGORIES.items():
        for pattern in patterns:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                ctx = get_context(content, m.start(), m.end())
                entry = {"match": m.group(0)[:120], **ctx}
                if entry not in auth_findings[category]:
                    auth_findings[category].append(entry)
    findings["auth_logic"] = dict(auth_findings)

    # ── 4. Crypto Flows
    findings["crypto_flows"] = trace_crypto_flows(content)

    # ── 5. Admin / Hidden
    seen_admin = set()
    for pattern in ADMIN_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            key = m.group(0)[:80]
            if key not in seen_admin:
                seen_admin.add(key)
                ctx = get_context(content, m.start(), m.end())
                findings["admin_hints"].append({"match": key, **ctx})

    # ── 6. GraphQL
    seen_gql = set()
    for pattern, label in GRAPHQL_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            key = m.group(0)[:100]
            if key not in seen_gql:
                seen_gql.add(key)
                ctx = get_context(content, m.start(), m.end())
                findings["graphql"].append({"type": label, "snippet": m.group(0)[:400], **ctx})

    # ── 7. Object Structures
    findings["object_structures"] = find_object_structures(content)

    # ── 8. High-entropy strings (filtered)
    seen_entropy = set()
    for m in re.finditer(r'["`\']([A-Za-z0-9+/=_\-]{20,512})["`\']', content):
        val = m.group(1)
        if val in seen_entropy:
            continue
        seen_entropy.add(val)
        if is_high_entropy_secret(val):
            ctx = get_context(content, m.start(), m.end())
            decode_result = try_decode_value(val)
            findings["high_entropy"].append({
                "value_preview": val[:60] + ("…" if len(val) > 60 else ""),
                "entropy":       round(shannon_entropy(val), 2),
                "decoded":       decode_result.get("decoded"),
                "decode_method": decode_result.get("method"),
                **ctx,
            })

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# MARKDOWN REPORT FORMATTER
# ─────────────────────────────────────────────────────────────────────────────
def format_report(findings: dict) -> str:
    out = []
    fn = findings["filename"]
    sz = findings["size_bytes"]

    out.append(f"# JS Recon Report — `{fn}` ({sz:,} bytes)\n")

    # Notes / warnings
    if findings["notes"]:
        for note in findings["notes"]:
            out.append(f"> {note}\n")

    # Obfuscation
    obs = findings["obfuscation"]
    if obs:
        out.append("\n## 🔍 Obfuscation / Minification")
        for k, v in obs.items():
            out.append(f"- **{k}**: {v}")

    def section(emoji, title, items, fmt_fn, cap=40):
        out.append(f"\n## {emoji} {title} ({len(items)} found)")
        if not items:
            out.append("_Nothing detected_")
            return
        for item in items[:cap]:
            out.append(fmt_fn(item))

    # API Endpoints
    section("🔌", "API Endpoints", findings["api_endpoints"], lambda x: (
        f"- `{x['endpoint']}` (line {x['line']})\n"
        f"  ```\n  {x['context']}\n  ```"
    ))

    # Secrets
    out.append(f"\n## 🚨 Secrets / Credentials ({len(findings['secrets'])} found)")
    if not findings["secrets"]:
        out.append("_Nothing detected_")
    for s in findings["secrets"][:40]:
        decoded_note = ""
        if s.get("decoded"):
            decoded_note = f"\n  🔓 **Decoded ({s['decode_method']})**: `{s['decoded'][:80]}`"
        out.append(
            f"- **{s['type']}** → `{s['raw_preview']}`{decoded_note}\n"
            f"  line {s['line']}: `{s['context'][:150]}`"
        )

    # Auth Logic
    auth = findings["auth_logic"]
    out.append(f"\n## 🔑 Auth Logic")
    if not auth:
        out.append("_Nothing detected_")
    for category, items in auth.items():
        out.append(f"\n### {category} ({len(items)})")
        for item in items[:15]:
            out.append(f"- line {item['line']}: `{item['match']}`\n  `{item['context'][:150]}`")

    # Crypto Flows
    out.append(f"\n## 🔐 Crypto / Encryption Flows ({len(findings['crypto_flows'])} found)")
    if not findings["crypto_flows"]:
        out.append("_No crypto calls detected_")
    for c in findings["crypto_flows"][:20]:
        out.append(
            f"- **{c['function']}** (line {c['line']})\n"
            f"  args: `{c['arguments'][:150]}`\n"
            f"  context: `{c['context'][:150]}`"
        )

    # Admin
    section("👤", "Admin / Hidden Functionality", findings["admin_hints"], lambda x: (
        f"- `{x['match']}` (line {x['line']})\n"
        f"  `{x['context'][:150]}`"
    ))

    # GraphQL
    section("📡", "GraphQL", findings["graphql"], lambda x: (
        f"- **{x['type']}** (line {x['line']})\n"
        f"  ```graphql\n  {x['snippet'][:200]}\n  ```"
    ))

    # Object Structures
    section("🏗️", "Interesting Object Structures", findings["object_structures"], lambda x: (
        f"- **{x['kind']}** {('`' + x['name'] + '`') if x['name'] else ''} (line {x['line']})\n"
        f"  ```js\n  {x['body'][:300]}\n  ```"
    ))

    # High-entropy
    out.append(f"\n## 🎲 High-Entropy Strings ({len(findings['high_entropy'])} found)")
    if not findings["high_entropy"]:
        out.append("_Nothing detected_")
    for h in findings["high_entropy"][:30]:
        decoded_note = ""
        if h.get("decoded"):
            decoded_note = f" → 🔓 decoded ({h['decode_method']}): `{h['decoded'][:60]}`"
        out.append(
            f"- entropy={h['entropy']} `{h['value_preview']}`{decoded_note} (line {h['line']})"
        )

    # Breakpoint guide if obfuscated
    if obs.get("hex_variable_names") or obs.get("eval_usage") or obs.get("function_constructor"):
        out.append("\n## 🛠️ Breakpoint Guide (for obfuscated values)")
        out.append(textwrap.dedent("""
        Static analysis cannot recover runtime-computed keys. To extract real values:

        1. **Browser DevTools → Sources tab** → find the JS file
        2. Search for `encrypt` / `decrypt` / `AES` / `CryptoJS` (Ctrl+F)
        3. Click the line number to set a breakpoint
        4. Trigger the action in the app (login, submit form, etc.)
        5. When paused, hover over variables or use the Console:
           ```js
           // Example: extract key from variable
           console.log(key)          // if it's a string
           console.log(key.toString())
           console.log(btoa(key))    // if it's a Uint8Array
           ```
        6. For WebCrypto keys (CryptoKey object), use:
           ```js
           crypto.subtle.exportKey('raw', cryptoKeyVar)
             .then(buf => console.log(btoa(String.fromCharCode(...new Uint8Array(buf)))))
           ```
        """).strip())

    return "\n".join(out)

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JS Recon for Pentest v2.0")
    parser.add_argument("--file",     action="append", dest="files",
                        help="Path to JS file (repeatable for multi-file)")
    parser.add_argument("--stdin",    action="store_true", help="Read from stdin")
    parser.add_argument("--output",   choices=["json", "markdown"], default="markdown")
    parser.add_argument("--beautify", action="store_true",
                        help="Attempt to beautify minified JS before scanning")
    args = parser.parse_args()

    inputs = []  # list of (content, filename)

    if args.stdin:
        content = sys.stdin.read()
        if args.beautify:
            content, did_beautify = try_beautify(content)
            if not did_beautify:
                print("# [warn] JS beautifier unavailable; scanning as-is", file=sys.stderr)
        inputs.append((content, "stdin"))

    elif args.files:
        for fpath in args.files:
            p = Path(fpath)
            content = p.read_text(errors="ignore")
            if args.beautify:
                content, did_beautify = try_beautify(content)
                if not did_beautify:
                    print(f"# [warn] Could not beautify {fpath}; scanning as-is", file=sys.stderr)
            # Unique filename based on path hash to avoid collisions
            inputs.append((content, p.name))
    else:
        parser.print_help()
        sys.exit(1)

    all_findings = [scan_js(content, fname) for content, fname in inputs]

    if args.output == "json":
        print(json.dumps(all_findings if len(all_findings) > 1 else all_findings[0], indent=2))
    else:
        for f in all_findings:
            print(format_report(f))
            print("\n" + "─" * 80 + "\n")
