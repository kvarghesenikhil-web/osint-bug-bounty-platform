const express = require("express");
const router = express.Router();
const { runSubfinder } = require("../services/reconService");

router.get("/subdomains/:domain", async (req, res) => {
  try {
    const result = await runSubfinder(req.params.domain);
    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
