const express = require("express");
const cors = require("cors");

const app = express();
const reconRoutes = require("./src/routes/reconRoutes");

app.use(cors({
  origin: "http://localhost:5173",
}));

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Server is working");
});

app.use("/api/recon", reconRoutes);

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
