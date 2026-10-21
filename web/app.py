from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

# Import project logic
from src.generators.domain_gen import DomainVariantGenerator
from src.scanners.registration_checker import RegistrationChecker
from src.scanners.quishing import QuishingScanner, QuishingGenerator

app = Flask(__name__)
CORS(app)

# Initialize project tools
domain_gen = DomainVariantGenerator()
reg_checker = RegistrationChecker()
qr_scanner = QuishingScanner(domain_checker=reg_checker)

# Create a thread pool for DNS checks to prevent blocking the Flask server
executor = ThreadPoolExecutor(max_workers=100) # Increased from 20 to 100


def run_async_dns(variants):
    """Helper to run async DNS checks in a synchronous thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def check_all():
        # Use a high-concurrency semaphore to maximize throughput
        semaphore = asyncio.Semaphore(200)

        async def sem_check(domain):
            async with semaphore:
                return await reg_checker.check_dns(domain)

        tasks = [sem_check(v) for v in variants]
        return await asyncio.gather(*tasks)

    try:
        return loop.run_until_complete(check_all())
    except Exception as e:
        print(f"[!] Thread Loop Error: {e}")
        return [False] * len(variants)
    finally:
        loop.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan-domain', methods=['POST'])
def scan_domain():
    try:
        data = request.json
        domain = data.get('domain')
        print(f"\n[!] Request received for domain: {domain}")

        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        # 1. Generate variants (fast)
        variants = domain_gen.generate_all(domain)
        print(f"[*] Generated {len(variants)} variants. Starting DNS checks...")

        # 2. Run DNS checks in the thread pool
        try:
            future = executor.submit(run_async_dns, variants)
            is_registered = future.result(timeout=120)
        except Exception as e:
            print(f"[!] DNS Error: {str(e)}")
            return jsonify({"error": f"DNS scan failed: {str(e)}"}), 500

        # 3. Process results
        results = []
        for variant, registered in zip(variants, is_registered):
            if registered:
                try:
                    score = reg_checker.calculate_risk_score(domain, variant)
                    results.append({
                        "domain": variant,
                        "risk_score": score,
                        "status": "Registered"
                    })
                except Exception as score_e:
                    print(f"[!] Scoring Error for {variant}: {score_e}")

        results.sort(key=lambda x: x['risk_score'], reverse=True)
        print(f"[+] Analysis complete. Found {len(results)} registered variants.")
        return jsonify({"results": results})
    except Exception as e:
        print(f"[!!!] CRITICAL SERVER ERROR: {e}")
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

@app.route('/api/scan-qr', methods=['POST'])
def scan_qr():
    print("\n[!] Request received for QR scan")
    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    file = request.files['image']
    path = os.path.join("temp_qr.png")
    file.save(path)

    result = qr_scanner.scan_qr(path)
    print(f"[+] QR scan complete. Suspicious: {result.get('is_suspicious')}")
    return jsonify(result)

if __name__ == "__main__":
    # Changed port to 8080 to avoid Windows system conflicts
    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)

