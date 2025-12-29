/**
 * Yordi Coffee Backend (MongoDB Atlas + Mongoose)
 * - Coffee CRUD (admin protected with ADMIN_KEY)
 * - Auth (register/login) with JWT
 * - Orders + "My Orders"
 * - Email to admin on new order (Gmail App Password)
 */

require("dotenv").config();

const dns = require("dns");
dns.setDefaultResultOrder("ipv4first");

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();

// -------- CONFIG --------
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

const ADMIN_KEY = process.env.ADMIN_KEY || "";          // admin password for CRUD coffee
const JWT_SECRET = process.env.JWT_SECRET || "";        // for user auth
const GMAIL_USER = process.env.GMAIL_USER || "";        // your gmail
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || ""; // app password
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.EMAIL_TO || ""; // send orders here

if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in .env");
  process.exit(1);
}

app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"] }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

mongoose.set("strictQuery", true);
mongoose.set("bufferCommands", false);

// -------- CONNECT --------
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
    process.exit(1);
  }
})();

// -------- MODELS --------
const coffeeSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "coffee", trim: true },
    price: { type: Number, required: true },
    image: { type: String, default: "" }, // base64 data URL or URL
  },
  { timestamps: true }
);
const Coffee = mongoose.model("Coffee", coffeeSchema);

const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, unique: true, lowercase: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

    items: [
      {
        productId: String,
        name: String,
        price: Number,
        qty: Number,
        image: String,
      },
    ],

    customer: {
      fullName: String,
      phone: String,
      email: String,
      address: String,
      city: String,
      country: String,
      notes: String,
    },

    payment: {
      method: { type: String, default: "cash" }, // cash/card/telebirr
      telebirrRef: { type: String, default: "" },
      status: { type: String, default: "pending" },
    },

    total: { type: Number, default: 0 },
    status: { type: String, default: "placed" },
  },
  { timestamps: true }
);
const Order = mongoose.model("Order", orderSchema);

// -------- HELPERS --------
function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) return next(); // dev mode if you forgot to set it
  const key = req.header("x-admin-key") || "";
  if (key !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized (admin key)" });
  next();
}

function authMiddleware(req, res, next) {
  const auth = req.header("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function calcTotal(items = []) {
  return items.reduce((sum, it) => sum + (Number(it.price) || 0) * (Number(it.qty) || 1), 0);
}

// -------- EMAIL (ADMIN) --------
let transporter = null;
function getTransporter() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) return null;
  if (transporter) return transporter;

  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD,
    },
  });
  return transporter;
}

async function sendAdminOrderEmail(orderDoc) {
  const t = getTransporter();
  if (!t) {
    console.warn("⚠️ Email not configured (missing GMAIL_USER or GMAIL_APP_PASSWORD). Skipping email.");
    return { ok: false, reason: "Email not configured" };
  }
  if (!ADMIN_EMAIL) {
    console.warn("⚠️ ADMIN_EMAIL not set. Skipping email.");
    return { ok: false, reason: "ADMIN_EMAIL not set" };
  }

  const o = orderDoc;
  const lines = (o.items || []).map((it) => `- ${it.name} (qty ${it.qty}) — ${it.price} ETB`);
  const customer = o.customer || {};

  const subject = `☕ New Yordi Coffee Order: ${o.orderId}`;
  const text =
`New Order Received

Order ID: ${o.orderId}
Total: ${o.total} ETB
Payment: ${o.payment?.method || ""}  Ref: ${o.payment?.telebirrRef || ""}

Customer:
Name: ${customer.fullName || ""}
Phone: ${customer.phone || ""}
Email: ${customer.email || ""}
Address: ${customer.address || ""}, ${customer.city || ""}, ${customer.country || ""}

Notes:
${customer.notes || ""}

Items:
${lines.join("\n")}

Placed at: ${new Date(o.createdAt).toLocaleString()}
`;

  await t.sendMail({
    from: GMAIL_USER,
    to: ADMIN_EMAIL,
    subject,
    text,
  });

  return { ok: true };
}

// -------- ROUTES --------
app.get("/", (req, res) => {
  res.json({ ok: true, app: "Yordi Coffee API" });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    mongoState: mongoose.connection.readyState,
    db: mongoose.connection.name,
    emailConfigured: Boolean(GMAIL_USER && GMAIL_APP_PASSWORD && ADMIN_EMAIL),
  });
});

// ---- COFFEE (PUBLIC GET, ADMIN WRITE) ----
app.get("/api/coffee", async (req, res) => {
  try {
    const list = await Coffee.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load coffee", details: err?.message || String(err) });
  }
});

app.post("/api/coffee", requireAdmin, async (req, res) => {
  try {
    const { name, description = "", category = "coffee", price, image = "" } = req.body || {};
    if (!name || price === undefined) return res.status(400).json({ error: "name and price are required" });

    const created = await Coffee.create({
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

app.put("/api/coffee/:id", requireAdmin, async (req, res) => {
  try {
    const { name, description = "", category = "coffee", price, image } = req.body || {};
    if (!name || price === undefined) return res.status(400).json({ error: "name and price are required" });

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

app.delete("/api/coffee/:id", requireAdmin, async (req, res) => {
  try {
    const deleted = await Coffee.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Coffee not found" });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete coffee", details: err?.message || String(err) });
  }
});

// ---- AUTH ----
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};
    if (!fullName || !email || !password) return res.status(400).json({ error: "fullName, email, password required" });
    if (String(password).length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    const exists = await User.findOne({ email: String(email).toLowerCase().trim() }).lean();
    if (exists) return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({
      fullName: String(fullName).trim(),
      email: String(email).toLowerCase().trim(),
      passwordHash,
    });

    const token = jwt.sign({ userId: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { fullName: user.fullName, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: "Register failed", details: err?.message || String(err) });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password required" });

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ userId: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { fullName: user.fullName, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err?.message || String(err) });
  }
});

// ---- ORDERS ----
app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const {
      items = [],
      fullName,
      phone,
      email = "",
      address,
      city = "",
      country = "Ethiopia",
      notes = "",
      paymentMethod = "cash",
      telebirrRef = "",
    } = req.body || {};

    if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "Cart is empty" });
    if (!fullName || !phone || !address) return res.status(400).json({ error: "fullName, phone, address required" });

    const total = calcTotal(items);
    const orderId = "ORD-" + Date.now();

    const order = await Order.create({
      orderId,
      userId: req.user.userId,
      items,
      customer: { fullName, phone, email, address, city, country, notes },
      payment: { method: paymentMethod, telebirrRef: telebirrRef || "", status: "pending" },
      total,
      status: "placed",
    });

    // send email to admin (non-blocking style but awaited for error visibility)
    try {
      await sendAdminOrderEmail(order);
    } catch (mailErr) {
      console.error("❌ Email send failed:", mailErr?.message || mailErr);
      // do not fail the order if email fails
    }

    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: "Failed to place order", details: err?.message || String(err) });
  }
});

app.get("/api/orders/my", authMiddleware, async (req, res) => {
  try {
    const list = await Order.find({ userId: req.user.userId }).sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load orders", details: err?.message || String(err) });
  }
});

// -------- START --------
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://localhost:${PORT}`);
});
