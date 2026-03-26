const { spawn } = require("child_process");

function runSubfinder(domain) {
  return new Promise((resolve, reject) => {
    const process = spawn("python3", [
      "../recon-engine/subdomain/subfinder_runner.py",
      domain,
    ]);

    let output = "";

    process.stdout.on("data", (data) => {
      output += data.toString();
    });

    process.stderr.on("data", (err) => {
      console.error(err.toString());
    });

    process.on("close", () => {
  try {
    if (!output || output.trim() === "") {
      return resolve([]);
    }

    const parsed = JSON.parse(output);
    resolve(parsed);
  } catch (e) {
    console.error("Raw output:", output);
    reject("JSON parse failed");
  }
});
  });
}

module.exports = { runSubfinder };
