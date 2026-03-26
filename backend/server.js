const express = require("express");
const app = express();
app.get("/", (req, res) => {
  res.send("Server is working");
});
const reconRoutes = require("./src/routes/reconRoutes");

app.use("/api/recon", reconRoutes);

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
