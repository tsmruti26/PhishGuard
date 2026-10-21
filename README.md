# 🛡️ PhishGuard: Phishing Domain Generator & Quishing Scanner

PhishGuard is a dual-purpose security tool designed to detect and simulate modern phishing attacks. It combines traditional **typosquatting analysis** with **QR-code phishing (Quishing) detection**, providing security teams with the ability to proactively find deceptive domains and analyze malicious QR codes.

## 🚀 Features

### 1. Typosquatting Generator & Scanner
PhishGuard generates every possible permutation of a target domain to find registered "look-alikes."
- **Generation Techniques:**
    - **Omissions:** `google.com` $\rightarrow$ `goole.com`
    - **Repetitions:** `google.com` $\rightarrow$ `gooogle.com`
    - **Transpositions:** `google.com` $\rightarrow$ `googel.com`
    - **Keyboard Adjacency:** `google.com` $\rightarrow$ `gkogle.com` (based on QWERTY proximity)
    - **Homoglyphs:** `google.com` $\rightarrow$ `gоogle.com` (using Cyrillic 'о')
    - **TLD Swaps:** `.com` $\rightarrow$ `.net`, `.org`, `.biz`, `.info`, etc.
- **Registration Checking:** Uses asynchronous DNS resolution to identify which variants are actually live.
- **Risk Scoring:** Employs **Levenshtein Distance** and Unicode detection to rank domains by how visually deceptive they are to a human user.

### 2. Quishing (QR Phishing) Scanner
Detects malicious destinations embedded in QR codes, a vector that exploded in 2024-2025.
- **Automated Decoding:** Extracts URLs from image files.
- **URL Expansion:** Recursively follows redirects and expands shortened URLs (e.g., `bit.ly`, `t.co`) to uncover the final destination.
- **Heuristic Analysis:** Flags red flags such as:
    - Raw IP addresses as domains.
    - Use of URL shorteners for obfuscation.
    - Punycode/Unicode homoglyphs in the destination.

### 3. Security Awareness Generator
Creates "educational" malicious QR codes to help organizations train employees to be suspicious of unsolicited QR codes in public spaces.

---

## 🛠️ Installation & Usage

### Prerequisites
```bash
pip install dnspython python-whois python-Levenshtein qrcode[pil] pyzbar pillow requests click jinja2
```

### Running the Tool
```bash
# 1. Analyze a domain for registered typosquats (Outputs HTML report)
python main.py scan-domain google.com --format html

# 2. Scan a QR code for phishing indicators
python main.py scan-qr suspicious_qr.png --format json

# 3. Generate a test QR code for employee training
python main.py generate-qr "http://internal-security-test.com" training.png
```

---

## 🎓 Educational Context: Phishing Techniques

### Real-World Campaign Examples
- **The Microsoft QR Campaign (2023):** Attackers placed QR codes in public areas (parking lots, cafes) claiming to offer "Free Wi-Fi" or "Discount Vouchers," which led users to credential-harvesting pages.
- **Crypto Homoglyph Attacks:** Using Cyrillic characters to mimic exchange domains (e.g., `binаnce.com` where 'а' is Unicode `U+0430`), stealing API keys and funds.
- **Supply Chain Typosquatting:** Registering names similar to popular npm or PyPI packages (e.g., `requesst` instead of `requests`) to trick developers into installing malicious code.

### Defensive Measures
To protect against these attacks, organizations should implement:
1. **DMARC/SPF/DKIM:** Prevent email spoofing.
2. **Browser IDN Policies:** Modern browsers now display "Punycode" (e.g., `xn--...`) for domains containing mixed scripts to alert users to homoglyphs.
3. **QR Verification:** Educate users to **never** scan QR codes from untrusted public stickers and to always check the expanded URL before entering credentials.
4. **DNS Filtering:** Use security-focused DNS providers that block known phishing and newly registered domains (NRDs).

## ⚖️ Ethical Use
This tool is provided for **authorized security testing, defensive research, and educational purposes only**. Unauthorized scanning or simulation of phishing attacks against systems you do not own is illegal and unethical.
