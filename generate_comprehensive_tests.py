from src.scanners.quishing import QuishingGenerator
import os

gen = QuishingGenerator()
output_dir = "test_cases/qr_codes"

tests = {
    # Safe cases
    "safe_google.png": "https://www.google.com",
    "safe_microsoft.png": "https://www.microsoft.com",
    
    # URL Shortener cases
    "suspicious_bitly.png": "https://bit.ly/3YpZzXo",
    "suspicious_tinyurl.png": "https://tinyurl.com/y7v8j2",
    
    # IP Address cases
    "suspicious_ip_direct.png": "http://104.26.10.23",
    "suspicious_ip_local.png": "http://192.168.1.1",
    
    # Homoglyph/Punycode cases
    "suspicious_homoglyph_google.png": "http://xn--gogle-kva.com",
    "suspicious_homoglyph_apple.png": "http://xn--pple-5ia.com",
    
    # Edge cases / Invalid
    "invalid_text.png": "This is not a URL",
    "invalid_empty.png": "",
}

for filename, url in tests.items():
    path = os.path.join(output_dir, filename)
    gen.generate_test_qr(url, path)
    print(f"Generated {path} for: {url}")
