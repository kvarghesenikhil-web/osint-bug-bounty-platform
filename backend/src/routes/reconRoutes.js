const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { runSubfinder } = require("../services/reconService");

const SCAN_DIR = "/home/kali/osint-bug-bounty-platform/data/scans";

router.get("/subdomains/:domain", async (req, res) => {
  try {
    const result = await runSubfinder(req.params.domain);
    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: String(err) });
  }
});

router.post("/scan/deep", express.json(), (req, res) => {
  try {
    const domain = (req.body.domain || "").trim();

    if (!domain || !domain.includes(".")) {
      return res.status(400).json({
        success: false,
        error: "Provide a valid root domain like hackerone.com",
      });
    }

    const scanId = crypto.randomUUID();

    const child = spawn("python3", [
      "/home/kali/osint-bug-bounty-platform/recon-engine/subdomain/deep_scan_runner.py",
      domain,
      scanId,
    ], {
      detached: true,
      stdio: "ignore",
    });

    child.unref();

    res.json({
      success: true,
      scanId,
      status: "queued",
      domain,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: String(err) });
  }
});

router.get("/status/:scanId", (req, res) => {
  try {
    const filePath = path.join(SCAN_DIR, `${req.params.scanId}.status.json`);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: "Scan status not found",
      });
    }

    const raw = fs.readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    res.json({ success: true, ...parsed });
  } catch (err) {
    res.status(500).json({ success: false, error: String(err) });
  }
});

router.get("/results/:scanId", (req, res) => {
  try {
    const filePath = path.join(SCAN_DIR, `${req.params.scanId}.json`);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: "Scan result not found",
      });
    }

    const raw = fs.readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    res.json({ success: true, ...parsed });
  } catch (err) {
    res.status(500).json({ success: false, error: String(err) });
  }
});

module.exports = router;
