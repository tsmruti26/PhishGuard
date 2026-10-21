import requests
from pyzbar.pyzbar import decode
from PIL import Image
import qrcode
from urllib.parse import urlparse

class QuishingScanner:
    def __init__(self, domain_checker=None):
        self.domain_checker = domain_checker

    def scan_qr(self, image_path):
        """Decodes a QR code from an image and analyzes the URL."""
        try:
            img = Image.open(image_path)
            decoded_objects = decode(img)
            if not decoded_objects:
                return {"error": "No QR code found in image"}

            # Assume the first QR code found is the target
            data = decoded_objects[0].data.decode('utf-8')
            return self.analyze_url(data)
        except Exception as e:
            return {"error": f"Scanning failed: {str(e)}"}

    def expand_url(self, url):
        """Expands shortened URLs to find the final destination."""
        try:
            # We use a timeout and disable redirects initially to check for suspicious patterns
            # but eventually we want the final destination.
            response = requests.get(url, allow_redirects=True, timeout=5)
            return response.url
        except Exception as e:
            return url

    def analyze_url(self, url):
        """Analyzes a URL for phishing indicators."""
        final_url = self.expand_url(url)
        parsed = urlparse(final_url)
        domain = parsed.netloc

        analysis = {
            "original_url": url,
            "final_url": final_url,
            "domain": domain,
            "is_suspicious": False,
            "indicators": []
        }

        if not domain:
            analysis["is_suspicious"] = True
            analysis["indicators"].append("Invalid domain")
            return analysis

        # Indicator 1: URL Shorteners
        shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly']
        if any(s in domain for s in shorteners):
            analysis["indicators"].append("Uses URL shortener")
            # Note: We already expanded it, but the fact it used one is a signal

        # Indicator 2: IP address as domain
        if domain.replace('.', '').isdigit():
            analysis["is_suspicious"] = True
            analysis["indicators"].append("Domain is a raw IP address")

        # Indicator 3: Homoglyphs / Unicode
        if any(ord(c) > 127 for c in domain):
            analysis["is_suspicious"] = True
            analysis["indicators"].append("Contains Unicode/Homoglyph characters")

        # Integration with DomainChecker (if provided)
        if self.domain_checker:
            # We can't easily provide the 'original' domain without context,
            # but the CLI will handle that logic.
            pass

        if analysis["indicators"]:
            analysis["is_suspicious"] = True

        return analysis

class QuishingGenerator:
    @staticmethod
    def generate_test_qr(data, filename="test_qr.png"):
        """Generates a QR code for security awareness testing."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)
        return filename

if __name__ == "__main__":
    # Simple self-test
    gen = QuishingGenerator()
    test_url = "http://bit.ly/some-fake-phish" # This might actually redirect
    gen.generate_test_qr(test_url, "quish_test.png")
    print("Generated test QR code: quish_test.png")

    scanner = QuishingScanner()
    result = scanner.scan_qr("quish_test.png")
    print(f"Scan Result: {result}")
