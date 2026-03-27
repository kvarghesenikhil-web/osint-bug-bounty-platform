import subprocess
import json
import sys
import tempfile
import os
import re
from datetime import datetime

domain = sys.argv[1]
scan_id = sys.argv[2]

BASE_DIR = "/home/kali/osint-bug-bounty-platform/data/scans"
STATUS_FILE = os.path.join(BASE_DIR, f"{scan_id}.status.json")
RESULT_FILE = os.path.join(BASE_DIR, f"{scan_id}.json")


def write_status(status, message=None):
    payload = {
        "scan_id": scan_id,
        "domain": domain,
        "status": status,
        "message": message,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    with open(STATUS_FILE, "w") as f:
        json.dump(payload, f, indent=2)


def clean_host(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0].strip()


def calculate_risk(asset):
    score = 0
    reasons = []

    status = str(asset.get("status") or "")
    title = (asset.get("title") or "").lower()
    domain_name = (asset.get("domain") or "").lower()
    ports = asset.get("ports", [])

    if status == "200":
        score += 30
        reasons.append("HTTP 200 asset")
    elif status in ["301", "302"]:
        score += 15
        reasons.append(f"Redirect status {status}")
    elif status in ["401", "403"]:
        score += 25
        reasons.append(f"Restricted asset ({status})")
    elif status == "404":
        score += 5
        reasons.append("404 asset still indexed")

    keyword_scores = {
        "admin": 25,
        "login": 20,
        "api": 20,
        "dashboard": 20,
        "support": 10,
        "dev": 25,
        "staging": 25,
        "test": 15,
        "internal": 25,
    }

    for keyword, value in keyword_scores.items():
        if keyword in title or keyword in domain_name:
            score += value
            reasons.append(f"Contains keyword: {keyword}")

    port_scores = {
        "80": 5,
        "443": 5,
        "8080": 10,
        "8443": 10,
    }

    for port in ports:
        if port in port_scores:
            score += port_scores[port]
            reasons.append(f"Port {port} exposed")

    if asset.get("title") and status != "404":
        score += 10
        reasons.append("Page title identified")

    if domain_name.count(".") >= 3:
        score += 5
        reasons.append("Deep subdomain")

    return score, reasons


def get_priority(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def run_deep_scan():
    if "." not in domain:
        raise ValueError("Please provide a valid root domain like hackerone.com")

    sub_file = None
    alive_file = None

    try:
        write_status("running", "Starting subdomain enumeration")

        subfinder = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        subs = [s.strip() for s in subfinder.stdout.strip().split("\n") if s.strip()]
        subs = list(dict.fromkeys(subs))[:30]

        if not subs:
            return []

        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            for sub in subs:
                f.write(sub + "\n")
            sub_file = f.name

        write_status("running", "Probing live HTTP assets")

        httpx = subprocess.run(
            [
                "httpx",
                "-l", sub_file,
                "-silent",
                "-no-color",
                "-threads", "10",
                "-timeout", "2",
                "-retries", "0",
                "-status-code",
                "-title",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )

        alive_lines = [line.strip() for line in httpx.stdout.strip().split("\n") if line.strip()]
        alive_hosts = [clean_host(line.split(" ")[0]) for line in alive_lines]

        if not alive_hosts:
            return []

        alive_hosts = list(dict.fromkeys(alive_hosts))

        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            for host in alive_hosts:
                f.write(host + "\n")
            alive_file = f.name

        write_status("running", "Resolving IP addresses")

        dnsx = subprocess.run(
            ["dnsx", "-l", alive_file, "-silent", "-resp"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        ip_map = {}
        for line in dnsx.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            host = line.split()[0].strip()
            ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", line)
            if ips and host not in ip_map:
                ip_map[host] = ips[0]

        write_status("running", "Scanning web ports")

        port_map = {}
        try:
            naabu = subprocess.run(
                ["naabu", "-l", alive_file, "-silent", "-p", "80,443,8080,8443"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            for line in naabu.stdout.strip().split("\n"):
                line = line.strip()
                if not line or ":" not in line:
                    continue
                host, port = line.rsplit(":", 1)
                host = clean_host(host)
                port = port.strip()
                if port.isdigit():
                    port_map.setdefault(host, set()).add(port)
        except subprocess.TimeoutExpired:
            pass

        write_status("running", "Calculating risk scores")

        result = []

        for line in alive_lines:
            url = line.split(" ")[0]
            domain_only = clean_host(url)

            parts = line.split("[")
            status = parts[1].split("]")[0] if len(parts) > 1 else None
            title = parts[2].split("]")[0] if len(parts) > 2 else None

            asset = {
                "url": url,
                "domain": domain_only,
                "status": status,
                "title": title,
                "ip": ip_map.get(domain_only),
                "ports": sorted(list(port_map.get(domain_only, set()))),
            }

            risk_score, reasons = calculate_risk(asset)
            asset["risk_score"] = risk_score
            asset["priority"] = get_priority(risk_score)
            asset["reasons"] = reasons

            result.append(asset)

        result.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        return result

    finally:
        if sub_file and os.path.exists(sub_file):
            os.unlink(sub_file)
        if alive_file and os.path.exists(alive_file):
            os.unlink(alive_file)


def main():
    try:
        write_status("queued", "Scan created")
        results = run_deep_scan()

        payload = {
            "scan_id": scan_id,
            "domain": domain,
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat() + "Z",
            "data": results,
        }

        with open(RESULT_FILE, "w") as f:
            json.dump(payload, f, indent=2)

        write_status("completed", f"Scan finished with {len(results)} assets")

    except Exception as e:
        error_payload = {
            "scan_id": scan_id,
            "domain": domain,
            "status": "failed",
            "error": str(e),
            "failed_at": datetime.utcnow().isoformat() + "Z",
        }

        with open(RESULT_FILE, "w") as f:
            json.dump(error_payload, f, indent=2)

        write_status("failed", str(e))


if __name__ == "__main__":
    main()
