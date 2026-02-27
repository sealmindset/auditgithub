# iAPI Assessment & Discovery Implementation Plan

## 1. High-Level Architecture Document

The iAPI architecture follows a **Linear Discovery Pipeline with Feedback Loops**. It is designed to act as a "Search Engine for APIs" within your infrastructure, moving from broad DNS reconnaissance to deep packet inspection and specification reconstruction.

Enable AI powered analysis through AI agents, sub-agents, Claude skills and MCP tools throughout the pipeline and applications to provide intelligent insights and recommendation, self-learning and continuous improvement, self-healing and adaptive security measures, self-annealing Design of Experiments, self-optimization, and self-scaling, and enhanced identification and classification of API endpoints, resources, and vulnerabilities.

Refer to the markdown files in the docs/apirecon for additional details.

### The Pipeline Stages

1.  **The Reconnaissance Layer (Broad Scope)**
    * **Input:** Root domain (e.g., `example.com`).
    * **Tools:** `Amass`, `Subfinder`.
    * **Logic:** Aggregates passive DNS data and Certificate Transparency logs.
    * **Heuristics:** Filters for `api.`, `dev.`, `stg-api.` subdomains.

2.  **The Asset Enrichment Layer (Fingerprinting)**
    * **Input:** Live subdomains.
    * **Tools:** `Katana` (JS Crawling), `httpx`.
    * **Logic:** Fetches `robots.txt`, `sitemap.xml`, and parses client-side JS bundles.
    * **Heuristics:** Regex extraction for AWS keys, JWTs, and internal paths (e.g., `/v1/internal/`).

3.  **The Active Discovery Layer (Fuzzing)**
    * **Input:** Discovered endpoints + JavaScript paths.
    * **Tools:** `ffuf` (Endpoint Fuzzing), `Kiterunner` (Contextual API Brute-forcing), `Arjun` (Parameter Discovery).
    * **Logic:**
        * **Smart Fuzzing:** Uses distinct wordlists based on tech stack (e.g., Spring Boot vs. Express).
        * **Parameter Mining:** Identifies hidden query params that alter logic (e.g., `?debug=true`).

4.  **The Reconstruction Layer (Reverse Engineering)**
    * **Input:** Raw HTTP traffic (Request/Response pairs) from Fuzzing layer.
    * **Engine:** Custom Python `SpecBuilder`.
    * **Logic:**
        * **Path Normalization:** Clusters URLs (e.g., `/user/101` & `/user/102` $\rightarrow$ `/user/{id}`).
        * **Schema Inference:** Analyzes JSON response keys/types to build data models.
    * **Output:** `rogue-openapi.json`.

5.  **The Vulnerability Assessment Layer (DAST)**
    * **Input:** `rogue-openapi.json`.
    * **Tools:** `Nuclei`, `ZAP` (Docker), `TruffleHog`.
    * **Logic:** Runs template-based scans against the *reconstructed* spec, ensuring coverage of undocumented endpoints.

### EASM Integration & Continuous Monitoring
* **Drift Detection:** The generated `rogue-openapi.json` is hashed and stored. On the next run, a `diff` is calculated. New endpoints trigger alerts; removed endpoints are marked as "Zombie/Deprecated."
* **Data Normalization:** All findings are converted to **SARIF (Static Analysis Results Interchange Format)** for ingestion into DefectDojo or Jira.

---

## 2. Core Orchestration Code (Python)

This Python script demonstrates the Orchestrator pattern. It chains broad reconnaissance into JavaScript analysis, and finally into active parameter discovery.

```python
import subprocess
import re
import json
import logging
from typing import List, Dict

# Configuration
TARGET_DOMAIN = "target-example.com"
OUTPUT_DIR = "./iapi_results"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("iAPI-Orchestrator")

class APIDiscoveryOrchestrator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.endpoints = []
        self.suspected_secrets = []

    def run_recon(self):
        """Step 1: Broad Recon using Subfinder and Amass"""
        logger.info(f"[*] Starting Recon on {self.domain}...")
        
        # Using Subfinder for speed
        cmd = ["subfinder", "-d", self.domain, "-silent", "-o", f"{OUTPUT_DIR}/subs.txt"]
        subprocess.run(cmd, check=True)
        
        with open(f"{OUTPUT_DIR}/subs.txt", "r") as f:
            self.subdomains = [line.strip() for line in f.readlines()]
        
        # Filter for API-identifying patterns
        api_subs = [s for s in self.subdomains if re.search(r'(api|dev|stg|svc|internal)', s)]
        logger.info(f"[+] Found {len(api_subs)} API-related subdomains: {api_subs}")
        return api_subs

    def parse_js_artifacts(self, target_url):
        """Step 2: Crawl JS and extract Secrets/Paths using Katana + Regex"""
        logger.info(f"[*] Analyzing JS artifacts on {target_url}...")
        
        # 1. Crawl for JS files
        katana_cmd = ["katana", "-u", target_url, "-jc", "-em", "js", "-silent"]
        result = subprocess.run(katana_cmd, capture_output=True, text=True)
        js_urls = result.stdout.splitlines()

        # 2. Heuristic Scanning on found JS content (Simulated fetch & scan)
        # Patterns for AWS, Google, JWT, and API Paths
        patterns = {
            "AWS_KEY": r"AKIA[0-9A-Z]{16}",
            "GOOGLE_API": r"AIza[0-9A-Za-z\\-_]{35}",
            "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
            "API_PATH": r"[\"'](\/api\/v[0-9]\/[a-zA-Z0-9_\-]+)[\"']"
        }

        # (In production, use 'curl' or 'requests' to fetch content. Logic simplified here.)
        # checking a dummy JS content block:
        dummy_js_content = "const endpoint = '/api/v1/users'; const key = 'AKIAIOSFODNN7EXAMPLE';"
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, dummy_js_content)
            if matches:
                logger.warning(f"[!] Found {name}: {matches}")
                if name == "API_PATH":
                    self.endpoints.extend(matches)

    def active_discovery(self, target_url):
        """Step 3: FFuf for Fuzzing & Arjun for Parameter Discovery"""
        logger.info(f"[*] Starting Active Fuzzing on {target_url}...")
        
        # ffuf: Discover endpoints
        # logic: -w wordlist.txt -u target/FUZZ -mc 200,401,403
        
        # Arjun: Discover hidden parameters on a discovered endpoint
        # Example: Found /api/v1/search
        endpoint = f"{target_url}/api/v1/search" 
        logger.info(f"[*] Brute-forcing parameters on {endpoint}...")
        
        arjun_cmd = ["arjun", "-u", endpoint, "--get", "-oJ", f"{OUTPUT_DIR}/params.json"]
        # subprocess.run(arjun_cmd) # Commented to prevent execution in non-env
        
        logger.info(f"[+] Parameter Scan Complete. Check {OUTPUT_DIR}/params.json")

    def execute_pipeline(self):
        api_targets = self.run_recon()
        for target in api_targets:
            # Add protocol for tools
            full_url = f"https://{target}"
            self.parse_js_artifacts(full_url)
            self.active_discovery(full_url)

if __name__ == "__main__":
    orchestrator = APIDiscoveryOrchestrator(TARGET_DOMAIN)
    orchestrator.execute_pipeline()
