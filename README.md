# OSINT Bug Bounty Intelligence Platform

A live OSINT and bug bounty intelligence platform built with **React**, **Node.js**, and **Python**, designed for **authorized reconnaissance workflows** and **attack surface triage**.

This project combines a Python-based recon engine with an Express backend and a React dashboard to support:

* **Fast target triage** for responsive UI interaction
* **Deep asynchronous scans** for richer asset discovery and enrichment
* **Risk-based prioritization** with explainable scoring reasons
* **Live dashboard visualization** for findings review and workflow demonstration

---

## Features

* Root-domain based scanning workflow
* Background deep scans with scan IDs
* Status polling and result retrieval
* Asset enrichment with:

  * HTTP status
  * page title
  * resolved IP address
  * selected web ports
* Risk scoring and priority tagging
* Explainable reasons for each score
* Frontend dashboard with findings table and filters

---

## Architecture

```text
React Frontend
    ↓
Node.js / Express API
    ↓
Fast Scan Service  |  Deep Async Scan Service
                   ↓
            Python Recon Engine
     subfinder → httpx → dnsx → naabu
                   ↓
          JSON Scan Result Persistence
```

---

## Project Structure

```text
osint-bug-bounty-platform/
├── backend/
│   ├── src/
│   │   ├── routes/
│   │   │   └── reconRoutes.js
│   │   └── services/
│   │       └── reconService.js
│   └── server.js
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── App.css
│   └── package.json
│
├── recon-engine/
│   ├── venv/
│   └── subdomain/
│       ├── subfinder_runner.py
│       └── deep_scan_runner.py
│
├── data/
│   └── scans/
│
└── .gitignore
```

---

## Scan Modes

### Fast Mode

Fast mode is designed for **responsive frontend use**.

It performs a lightweight scan against:

* `domain`
* `www.domain`

It is used for:

* instant UI-friendly target checks
* low-latency API responses
* stable live demo behavior

### Deep Mode

Deep mode is designed for **background scanning**.

It performs:

* subdomain enumeration with `subfinder`
* live host probing with `httpx`
* IP resolution with `dnsx`
* selected web port checks with `naabu`
* risk scoring and prioritization

Deep mode runs asynchronously and saves results to disk.

---

## Tech Stack

### Frontend

* React
* Vite
* CSS

### Backend

* Node.js
* Express.js
* CORS

### Recon Engine

* Python 3
* subfinder
* httpx
* dnsx
* naabu

### Persistence

* File-based JSON scan storage

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/kvarghesenikhil-web/osint-bug-bounty-platform.git
cd osint-bug-bounty-platform
```

### 2. Install backend dependencies

```bash
cd backend
npm install
```

### 3. Install frontend dependencies

```bash
cd ../frontend
npm install
```

### 4. Set up Python virtual environment

```bash
cd ../recon-engine
python3 -m venv venv
source venv/bin/activate
```

### 5. Install system and recon tools

Make sure the following are installed and available in `PATH`:

* `subfinder`
* `httpx`
* `dnsx`
* `naabu`

Example Go-based installation pattern:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

Then add Go tools to your shell path:

```bash
echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.zshrc
source ~/.zshrc
```

---

## Running the Project

### Start backend

```bash
cd backend
node server.js
```

Backend runs on:

```text
http://localhost:3000
```

### Start frontend

```bash
cd frontend
npm run dev -- --host 0.0.0.0 --port 5173
```

Frontend runs on:

```text
http://localhost:5173
```

---

## API Endpoints

### Fast target scan

```http
GET /api/recon/subdomains/:domain
```

Used for lightweight synchronous scans.

---

### Start deep scan

```http
POST /api/recon/scan/deep
Content-Type: application/json
```

Request body:

```json
{
  "domain": "hackerone.com"
}
```

Example response:

```json
{
  "success": true,
  "scanId": "148643d1-8c13-47f1-a97d-12801fec9ad1",
  "status": "queued",
  "domain": "hackerone.com"
}
```

---

### Check deep scan status

```http
GET /api/recon/status/:scanId
```

Example response:

```json
{
  "success": true,
  "scan_id": "148643d1-8c13-47f1-a97d-12801fec9ad1",
  "domain": "hackerone.com",
  "status": "completed",
  "message": "Scan finished with 10 assets"
}
```

---

### Get deep scan results

```http
GET /api/recon/results/:scanId
```

Example response:

```json
{
  "success": true,
  "scan_id": "148643d1-8c13-47f1-a97d-12801fec9ad1",
  "domain": "hackerone.com",
  "status": "completed",
  "data": [
    {
      "url": "https://api.hackerone.com",
      "domain": "api.hackerone.com",
      "status": "200",
      "title": "HackerOne API",
      "ip": "172.64.151.42",
      "ports": ["443", "80", "8080", "8443"],
      "risk_score": 90,
      "priority": "high",
      "reasons": [
        "HTTP 200 asset",
        "Contains keyword: api",
        "Port 443 exposed",
        "Port 80 exposed",
        "Port 8080 exposed",
        "Port 8443 exposed",
        "Page title identified"
      ]
    }
  ]
}
```

---

## Risk Scoring Model

The platform assigns each asset:

* `risk_score`
* `priority`
* `reasons[]`

### Current scoring inputs

* HTTP status code
* page title
* domain keywords
* selected ports
* subdomain depth

### Example signals

* `200` responses are weighted higher
* `api`, `admin`, `login`, `support`, `staging`, `dev` keywords increase interest
* ports like `8080` and `8443` add score
* deeper subdomains receive additional weight

This makes the output more useful for triage than raw recon data alone.

---

## Frontend Workflow

1. User enters a root domain
2. Frontend starts a deep scan
3. Backend returns a `scanId`
4. Frontend polls scan status
5. When completed, frontend fetches results
6. Findings are rendered in a dashboard table with filters and summary cards

---

## Persistence Model

Deep scan results are stored as JSON files.

### Status file

```text
data/scans/<scanId>.status.json
```

### Result file

```text
data/scans/<scanId>.json
```

This file-based persistence keeps the MVP simple and easy to debug while still supporting a real asynchronous workflow.

---

## Current Output Example

Example prioritized findings:

* `api.hackerone.com` → high priority
* `www.hackerone.com` → high priority
* redirecting infrastructure assets → medium priority
* low-value 404 assets → low priority

This demonstrates the platform’s ability to move from raw discovery to explainable prioritization.

---

## Screenshots

Add screenshots here after capturing the running dashboard.

Suggested screenshots:

* homepage/dashboard view
* deep scan in progress
* completed findings table
* priority summary cards

Example section format:

```md
## Screenshots

![Dashboard Overview](./docs/screenshots/dashboard-overview.png)
![Deep Scan Results](./docs/screenshots/deep-scan-results.png)
```

---

## Current Limitations

* File-based storage instead of database-backed persistence
* No authentication or multi-user isolation
* No scan cancellation controls yet
* No export/download controls yet
* No charts or historical trends yet

These are acceptable limitations for the current MVP and demo version.

---

## Roadmap

### Phase 4

* recent scan history
* dashboard charts and KPIs
* export results as JSON
* improved result browsing

### Future Enhancements

* MongoDB integration
* authenticated user sessions
* scan queue management
* historical scan diffing
* richer asset views and detail pages

---

## Intended Use

This platform is intended for:

* authorized bug bounty workflows
* allowed attack surface analysis
* cybersecurity portfolio and research demonstrations

It is designed for **authorized reconnaissance only**.

---

## Resume / Portfolio Description

> Built a live OSINT and bug bounty intelligence platform using React, Node.js, and Python, supporting asynchronous deep scans, risk-based asset prioritization, scan-status polling, and interactive dashboard visualization for authorized reconnaissance workflows.

---

## Author

**Nikhil Varghese**

GitHub: `kvarghesenikhil-web`
