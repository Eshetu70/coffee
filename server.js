/**
 * Yordi Coffee Backend (MongoDB Atlas + Mongoose)
 * Fixes common "buffering timed out" by:
 * - forcing IPv4 first (Windows DNS issue)
 * - disabling mongoose buffering so errors show immediately
 * - adding /api/health to verify connection
 *
 * Install:
 *   npm i express cors mongoose dotenv
 *
 * Run:
 *   node server.js
 */

require("dotenv").config();

const dns = require("dns");
// ✅ Fix Windows/Node DNS IPv6 issues that often cause Atlas timeouts
dns.setDefaultResultOrder("ipv4first");

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();

// ---------- CONFIG ----------
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}

// ---------- MIDDLEWARE ----------
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------- MONGOOSE SETTINGS ----------
mongoose.set("strictQuery", true);

// ✅ If DB is not connected, don't buffer queries for 10 seconds then timeout.
//    Instead throw a real error immediately.
mongoose.set("bufferCommands", false);

// ---------- CONNECT ----------
(async () => {
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 8000,
      socketTimeoutMS: 20000,
      family: 4,
    });
    console.log("✅ Yordi Coffee backend running on port " + PORT);
    console.log("✅ MongoDB connected:", mongoose.connection.name);
  } catch (err) {
    console.error("❌ MongoDB error:", err?.message || err);
    console.error("🔎 Common fixes:");
    console.error("  1) Atlas: Network Access -> Add IP (or 0.0.0.0/0 for testing)");
    console.error("  2) Verify MONGODB_URI is correct and password is URL-encoded");
    console.error("  3) Restart server after editing .env");
    process.exit(1);
  }
})();

// ---------- MODEL ----------
const coffeeSchema = new mongoose.Schema(
  {
    id: { type: String, index: true }, // optional custom id
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "coffee", trim: true }, // e.g. espresso, latte, etc.
    price: { type: Number, required: true },
    image: { type: String, default: "" }, // URL or base64 data URL
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const Coffee = mongoose.model("Coffee", coffeeSchema);

// ---------- ROUTES ----------
app.get("/", (req, res) => {
  res.json({ ok: true, app: "Yordi Coffee API" });
});

// ✅ Health check to confirm mongo is connected
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    mongoState: mongoose.connection.readyState, // 0=disconnected 1=connected 2=connecting 3=disconnecting
    db: mongoose.connection.name,
  });
});

// GET all coffee
app.get("/api/coffee", async (req, res) => {
  try {
    const list = await Coffee.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load coffee", details: err?.message || String(err) });
  }
});

// POST add coffee
app.post("/api/coffee", async (req, res) => {
  try {
    const { name, description = "", category = "coffee", price, image = "" } = req.body || {};

    if (!name || price === undefined) {
      return res.status(400).json({ error: "name and price are required" });
    }

    const created = await Coffee.create({
      id: "coffee-" + Date.now(),
      name: String(name).trim(),
      description: String(description || "").trim(),
      category: String(category || "coffee").trim(),
      price: Number(price),
      image: String(image || ""),
    });

    res.json(created);
  } catch (err) {
    res.status(500).json({ error: "Failed to add coffee", details: err?.message || String(err) });
  }
});

// PUT update coffee by Mongo _id
app.put("/api/coffee/:id", async (req, res) => {
  try {
    const { name, description = "", category = "coffee", price, image } = req.body || {};

    if (!name || price === undefined) {
      return res.status(400).json({ error: "name and price are required" });
    }

    const update = {
      name: String(name).trim(),
      description: String(description || "").trim(),
      category: String(category || "coffee").trim(),
      price: Number(price),
    };

    // only update image if provided
    if (image !== undefined) update.image = String(image || "");

    const updated = await Coffee.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!updated) return res.status(404).json({ error: "Coffee not found" });

    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update coffee", details: err?.message || String(err) });
  }
});

// DELETE coffee
app.delete("/api/coffee/:id", async (req, res) => {
  try {
    const deleted = await Coffee.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Coffee not found" });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete coffee", details: err?.message || String(err) });
  }
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://localhost:${PORT}`);
});
