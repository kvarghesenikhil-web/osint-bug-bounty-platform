import subprocess
import json
import sys
import tempfile

domain = sys.argv[1]

def run_pipeline(domain):
    try:
        # Step 1: Run subfinder
        subfinder_cmd = ["/home/kali/go/bin/subfinder", "-d", domain, "-silent"]

        subfinder_result = subprocess.run(
            subfinder_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        subdomains = subfinder_result.stdout.strip().split("\n")

        if not subdomains or subdomains == [""]:
            return []

        # Step 2: Write to temp file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            for sub in subdomains:
                f.write(sub + "\n")
            temp_file = f.name

        # Step 3: Run httpx on file
        httpx_cmd = [
 	    "/home/kali/go/bin/httpx",
    	    "-l", temp_file,
	    "-silent",
	    "-no-color",
	    "-threads", "50",
	    "-timeout", "5",
	    "-retries", "0",
	    "-status-code",
	    "-title",
	    "-tech-detect"
	]

        httpx_result = subprocess.run(
            httpx_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        lines = httpx_result.stdout.strip().split("\n")

        structured = []

        for line in lines:
            if not line:
                continue

            url = line.split(" ")[0]

            status = None
            title = None
            tech = []

            try:
                parts = line.split("[")

                if len(parts) > 1:
                    status = parts[1].split("]")[0]

                if len(parts) > 2:
                    title = parts[2].split("]")[0]

                if len(parts) > 3:
                    tech = parts[3].split("]")[0].split(",")

            except:
                pass

            structured.append({
                "url": url,
                "status": status,
                "title": title,
                "technologies": tech
            })

        return structured

    except subprocess.TimeoutExpired:
        return [{"error": "Scan timed out"}]

    except Exception as e:
        return [{"error": str(e)}]


if __name__ == "__main__":
    data = run_pipeline(domain)

    if not data:
        print("[]")
    else:
        print(json.dumps(data))
