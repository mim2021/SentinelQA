# SentinelQA (v0.3.0)

A browser extension that runs automated security health-checks on websites
and shows a report card (grade A-F), built by a QA engineer who asked:
"we test functionality all day - who tests security?"

## Current checks
**URL level**
- HTTPS encryption present or missing
- Raw IP address used as host
- '@' symbol hiding the real destination
- Punycode / homoglyph domains
- Free/cheap TLDs frequently abused in phishing
- Digits in domain (brand imitation)
- Pressure/security keywords in the URL
- Excessive URL length

**Page level**
- Password field submitting over HTTP
- Mixed content on HTTPS pages

**Security headers**
- X-Frame-Options, Content-Security-Policy, X-Content-Type-Options
- Strict-Transport-Security (HTTPS, non-local pages only)

Local dev servers (localhost, 127.0.0.1) are exempt from the HTTPS and raw-IP checks.
Results are stored per browser tab, so pages never show each other's findings.

## Roadmap
- [x] Page-level checks: insecure forms, mixed content
- [x] Security headers (background script)
- [ ] ML-based risk scoring
- [ ] Selenium automated tests

## Install (developer mode)
1. Download and extract this ZIP
2. Open chrome://extensions in Chrome
3. Turn ON "Developer mode" (top right)
4. Click "Load unpacked" and select the extracted sentinelqa folder
5. Click the SentinelQA icon in the toolbar on any website

## Try it
- google.com   -> expect grade A
- neverssl.com -> expect grade B (no HTTPS)
- localhost:8000/test.html -> password-over-HTTP warning (grade D)