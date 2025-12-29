/**
 * Yordi Coffee Backend (MongoDB Atlas + Mongoose)
 * - Coffee CRUD (JSON + base64 image)
 * - Orders (checkout)
 * - /api/health
 */

require("dotenv").config();

const dns = require("dns");
dns.setDefaultResultOrder("ipv4first");

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();

// ---------- CONFIG ----------
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

// Optional: lock admin actions with an API key (recommended)
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "";

if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}

// ---------- MIDDLEWARE ----------
app.use(
  cors({
    origin: "*", // for GitHub Pages + testing (you can restrict later)
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-admin-key"],
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------- MONGOOSE SETTINGS ----------
mongoose.set("strictQuery", true);
mongoose.set("bufferCommands", false);

// ---------- CONNECT ----------
(async () => {
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 8000,
      socketTimeoutMS: 20000,
      family: 4,
    });
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

// ---------- ADMIN AUTH (optional) ----------
function requireAdmin(req, res, next) {
  if (!ADMIN_API_KEY) return next(); // if not set, allow (for now)
  const key = req.headers["x-admin-key"];
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: "Unauthorized (bad admin key)" });
  }
  next();
}

// ---------- MODELS ----------
const coffeeSchema = new mongoose.Schema(
  {
    id: { type: String, index: true }, // optional custom id
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "coffee", trim: true },
    price: { type: Number, required: true },
    image: { type: String, default: "" }, // base64 data URL or normal URL
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const Coffee = mongoose.model("Coffee", coffeeSchema);

// Orders
const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, index: true },
    customer: {
      fullName: String,
      phone: String,
      city: String,
      address: String,
    },
    payment: {
      method: { type: String, default: "cash" }, // cash/telebirr
      status: { type: String, default: "pending" }, // pending/paid
    },
    items: [
      {
        productId: String, // coffee _id as string
        name: String,
        price: Number,
        qty: Number,
        image: String,
      },
    ],
    total: { type: Number, default: 0 },
    status: { type: String, default: "placed" }, // placed/processing/delivered/cancelled
  },
  { timestamps: true }
);

const Order = mongoose.model("Order", orderSchema);

// ---------- ROUTES ----------
app.get("/", (req, res) => {
  res.json({ ok: true, app: "Yordi Coffee API" });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    mongoState: mongoose.connection.readyState,
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

// POST add coffee (ADMIN optional)
app.post("/api/coffee", requireAdmin, async (req, res) => {
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

// PUT update coffee by Mongo _id (ADMIN optional)
app.put("/api/coffee/:id", requireAdmin, async (req, res) => {
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

    if (image !== undefined) update.image = String(image || "");

    const updated = await Coffee.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!updated) return res.status(404).json({ error: "Coffee not found" });

    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update coffee", details: err?.message || String(err) });
  }
});

// DELETE coffee (ADMIN optional)
app.delete("/api/coffee/:id", requireAdmin, async (req, res) => {
  try {
    const deleted = await Coffee.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Coffee not found" });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete coffee", details: err?.message || String(err) });
  }
});

// ✅ CHECKOUT: Create order
app.post("/api/orders", async (req, res) => {
  try {
    const { customer, payment, items } = req.body || {};
    if (!customer?.fullName || !customer?.phone || !customer?.address) {
      return res.status(400).json({ error: "customer fullName, phone, address are required" });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "items are required" });
    }

    const total = items.reduce((sum, it) => sum + (Number(it.price) || 0) * (Number(it.qty) || 1), 0);

    const order = await Order.create({
      orderId: "ORD-" + Date.now(),
      customer: {
        fullName: String(customer.fullName || "").trim(),
        phone: String(customer.phone || "").trim(),
        city: String(customer.city || "").trim(),
        address: String(customer.address || "").trim(),
      },
      payment: {
        method: String(payment?.method || "cash"),
        status: "pending",
      },
      items: items.map((it) => ({
        productId: String(it.productId || ""),
        name: String(it.name || ""),
        price: Number(it.price) || 0,
        qty: Number(it.qty) || 1,
        image: String(it.image || ""),
      })),
      total,
      status: "placed",
    });

    res.json({ ok: true, orderId: order.orderId });
  } catch (err) {
    res.status(500).json({ error: "Failed to place order", details: err?.message || String(err) });
  }
});

// (Optional admin) list orders
app.get("/api/orders", requireAdmin, async (req, res) => {
  try {
    const list = await Order.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load orders", details: err?.message || String(err) });
  }
});

// ---------- START ----------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server listening on port ${PORT}`);
});
