from src.scanners.quishing import QuishingGenerator
import os

gen = QuishingGenerator()
tests = {
    "safe.png": "https://www.google.com",
    "shortened.png": "https://bit.ly/3YpZzXo",
    "ip_address.png": "http://1.1.1.1",
    "homoglyph.png": "http://xn--gogle-kva.com",
}

for filename, url in tests.items():
    gen.generate_test_qr(url, filename)
    print(f"Generated {filename} for {url}")
