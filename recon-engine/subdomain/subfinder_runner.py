import subprocess
import json
import sys
import tempfile
import os
import re

domain = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "fast"


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


def run_pipeline(domain, mode="fast"):
    if "." not in domain:
        return [{"error": "Please provide a valid root domain like hackerone.com"}]

    host_file = None
    alive_file = None

    try:
        if mode == "fast":
            targets = [domain, f"www.{domain}"]
            httpx_threads = 2
            httpx_timeout = 1
            httpx_process_timeout = 15
            use_dnsx = False
            use_naabu = False
        else:
            subfinder = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            targets = [s.strip() for s in subfinder.stdout.strip().split("\n") if s.strip()]
            targets = list(dict.fromkeys(targets))[:15]

            if not targets:
                return []

            httpx_threads = 5
            httpx_timeout = 2
            httpx_process_timeout = 45
            use_dnsx = True
            use_naabu = True

        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            for target in targets:
                f.write(target + "\n")
            host_file = f.name

        try:
            httpx = subprocess.run(
                [
                    "httpx",
                    "-l", host_file,
                    "-silent",
                    "-no-color",
                    "-threads", str(httpx_threads),
                    "-timeout", str(httpx_timeout),
                    "-retries", "0",
                    "-status-code",
                    "-title",
                ],
                capture_output=True,
                text=True,
                timeout=httpx_process_timeout,
            )
        except subprocess.TimeoutExpired:
            return [{"error": "httpx stage timed out. Try a smaller target or lighter scan settings."}]

        alive_lines = [line.strip() for line in httpx.stdout.strip().split("\n") if line.strip()]
        alive_hosts = [clean_host(line.split(" ")[0]) for line in alive_lines]

        if not alive_hosts:
            return []

        alive_hosts = list(dict.fromkeys(alive_hosts))

        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            for host in alive_hosts:
                f.write(host + "\n")
            alive_file = f.name

        ip_map = {}
        if use_dnsx:
            dnsx = subprocess.run(
                ["dnsx", "-l", alive_file, "-silent", "-resp"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            for line in dnsx.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                host = line.split()[0].strip()
                ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", line)
                if ips and host not in ip_map:
                    ip_map[host] = ips[0]

        port_map = {}
        if use_naabu:
            try:
                naabu = subprocess.run(
                    ["naabu", "-l", alive_file, "-silent", "-p", "80,443"],
                    capture_output=True,
                    text=True,
                    timeout=30,
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

    except Exception as e:
        return [{"error": str(e)}]

    finally:
        if host_file and os.path.exists(host_file):
            os.unlink(host_file)
        if alive_file and os.path.exists(alive_file):
            os.unlink(alive_file)


if __name__ == "__main__":
    data = run_pipeline(domain, mode)
    print(json.dumps(data) if data else "[]")
