const fs = require("fs");
const path = require("path");

function runSubfinder(domain) {
  return new Promise((resolve) => {
    try {
      const filePath = path.join(
        "/home/kali/osint-bug-bounty-platform/data/latest_scan.json"
      );

      const raw = fs.readFileSync(filePath, "utf-8");
      const parsed = JSON.parse(raw);

      resolve(parsed);
    } catch (err) {
      resolve([{ error: `Failed to load saved scan: ${err.message}` }]);
    }
  });
}

module.exports = { runSubfinder };
