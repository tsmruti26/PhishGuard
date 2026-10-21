import asyncio
import time
import random
import sys
import os

# Ensure src is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from src.generators.domain_gen import DomainVariantGenerator
from src.scanners.registration_checker import RegistrationChecker

async def benchmark_domain_gen():
    print("[*] Benchmarking Domain Generator...")
    gen = DomainVariantGenerator()
    start = time.time()
    # Use a complex domain to maximize variants
    variants = gen.generate_all("international-security-standard.org")
    end = time.time()
    print(f"    - Generated {len(variants)} variants in {end-start:.4f}s")
    return len(variants)

async def benchmark_dns_resolver():
    print("[*] Benchmarking DNS Resolver (Load Test)...")
    checker = RegistrationChecker(concurrency_limit=50)

    # Simulate 500 real-world lookups
    test_domains = [f"test-{random.randint(1,1000000)}.io" for _ in range(500)]

    start = time.time()
    tasks = [checker.check_dns(d) for d in test_domains]
    await asyncio.gather(*tasks)
    end = time.time()

    print(f"    - Checked 500 domains in {end-start:.4f}s")
    print(f"    - Average speed: {(end-start)/500:.4f}s per domain")

async def main():
    print("=== PHISHGUARD REAL-WORLD LOAD TEST ===")
    await benchmark_domain_gen()
    await benchmark_dns_resolver()
    print("=======================================")

if __name__ == "__main__":
    asyncio.run(main())
