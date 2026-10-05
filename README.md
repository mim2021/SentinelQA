# SentinelQA (v0.2.0)

A browser extension that runs automated security health-checks on websites
and shows a report card (grade A-F), built by a QA engineer who asked:
"we test functionality all day - who tests security?"

## Current checks (v0.2.0 - URL level)
- HTTPS encryption present or missing
- Raw IP address used as host
- '@' symbol hiding the real destination
- Punycode / homoglyph domains
- Free/cheap TLDs frequently abused in phishing
- Digits in domain (brand imitation)
- Pressure/security keywords in the URL
- Excessive URL length

## Roadmap
- [ ] Page-level checks: security headers (clickjacking), insecure forms, mixed content
- [ ] ML-based risk scoring
- [ ] Selenium automated tests

## Install (developer mode)
1. Download and extract this ZIP
2. Open chrome://extensions in Chrome
3. Turn ON "Developer mode" (top right)
4. Click "Load unpacked" and select the extracted sentinelqa_build folder
5. Click the SentinelQA icon in the toolbar on any website

## Try it
- google.com  -> expect grade A
- neverssl.com -> expect grade B (no HTTPS)
