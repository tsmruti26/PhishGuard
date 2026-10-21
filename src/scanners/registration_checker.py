import asyncio
import dns.resolver
import whois
from datetime import datetime
import Levenshtein

class RegistrationChecker:
    def __init__(self, concurrency_limit=100): # Increased from 10 to 100
        self.concurrency_limit = concurrency_limit
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1 # Reduced from 2 to 1
        self.resolver.lifetime = 1 # Reduced from 2 to 1

    async def check_dns(self, domain):
        """Check if domain is registered using an extremely fast async check."""
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self._resolve_ultra_fast, domain)
        except Exception:
            return False

    def _resolve_ultra_fast(self, domain):
        """Direct socket-level check for A record to bypass resolver overhead."""
        try:
            res = dns.resolver.Resolver()
            res.timeout = 0.3  # Ultra-aggressive timeout
            res.lifetime = 0.3
            res.resolve(domain, 'A')
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            # Quick fallback to Google DNS
            try:
                res_g = dns.resolver.Resolver()
                res_g.nameservers = ['8.8.8.8']
                res_g.timeout = 0.3
                res_g.lifetime = 0.3
                res_g.resolve(domain, 'A')
                return True
            except Exception:
                return False

    def get_whois_info(self, domain):
        """Fetches registration date via WHOIS."""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            return {
                "creation_date": creation_date,
                "registrar": w.registrar,
                "status": "Registered"
            }
        except Exception:
            return None

    def calculate_risk_score(self, original, variant):
        """
        Calculates a sophisticated risk score (0-100) based on multiple
        visual and structural deception vectors.
        """
        orig_name = original.rsplit('.', 1)[0]
        var_name = variant.rsplit('.', 1)[0]

        # 1. Base Similarity (Levenshtein)
        distance = Levenshtein.distance(orig_name, var_name)
        max_len = len(orig_name) if len(orig_name) > len(var_name) else len(var_name)
        if max_len == 0: return 0.0

        # Basic ratio
        similarity = (1 - (distance / max_len)) * 100

        # 2. High-Risk Multipliers (Deception Vectors)
        risk_bonus = 0.0

        # Vector A: Homoglyphs (Non-ASCII characters)
        # These are high-risk because they are explicitly meant to deceive
        if any(ord(c) > 127 for c in var_name):
            risk_bonus += 30.0

        # Vector B: Bit-flip / Keyboard Adjacency (Low distance, high visual similarity)
        # If distance is only 1 and the string is long, it's very deceptive
        if distance == 1 and max_len > 5:
            risk_bonus += 15.0

        # Vector C: Subdomain abuse (e.g., google.com.evil.com)
        # If the original name is inside the variant name but not as a direct match
        if orig_name in var_name and orig_name != var_name:
            risk_bonus += 20.0

        # Vector D: Common Phishing Patterns (e.g., adding 'login', 'verify', 'secure')
        phish_keywords = ['login', 'verify', 'secure', 'account', 'update', 'signin']
        if any(kw in var_name.lower() for kw in phish_keywords):
            risk_bonus += 15.0

        # Final Score Calculation
        # We use a weighted average so that high-risk markers can push a
        # medium similarity score into the "High Risk" category.
        final_score = similarity + risk_bonus

        # Cap at 100, floor at 0
        return max(0.0, min(100.0, final_score))

async def main():
    checker = RegistrationChecker()
    # Added known existing domains for verification
    test_domains = ["google.com", "microsoft.com", "nonexistent-domain-xyz-123.io"]

    print(f"Checking {len(test_domains)} domains...")

    # Process in batches to respect concurrency_limit
    results = []
    for i in range(0, len(test_domains), checker.concurrency_limit):
        batch = test_domains[i:i+checker.concurrency_limit]
        tasks = [checker.check_dns(d) for d in batch]
        batch_results = await asyncio.gather(*tasks)
        results.extend(batch_results)

    for domain, registered in zip(test_domains, results):
        status = "Registered" if registered else "Unresolved"
        print(f"{domain}: {status}")

if __name__ == "__main__":
    asyncio.run(main())
