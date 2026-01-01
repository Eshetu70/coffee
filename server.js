// server.js ✅ MATCHES YOUR FRONTEND (Yordi Coffee)
// --------------------------------------------------
// Endpoints your index.html calls:
//  GET    /api/health
//  GET    /api/admin/verify          (x-admin-key)
//  GET    /api/coffee
//  POST   /api/coffee               (x-admin-key)
//  PUT    /api/coffee/:id           (x-admin-key)
//  DELETE /api/coffee/:id           (x-admin-key)
//  POST   /api/auth/register
//  POST   /api/auth/login
//  POST   /api/orders               (Authorization: Bearer <token>)
//  GET    /api/orders/my            (Authorization: Bearer <token>)
//  GET    /api/admin/orders         (x-admin-key)
//  PUT    /api/admin/orders/:id     (x-admin-key)
//  POST   /api/admin/orders/:id/email (x-admin-key)
//
// ✅ Forces DB separation (Yordi_Coffee) even if same Atlas cluster as Sena Fashion
// Collections:
// - yordi_coffee_items
// - yordi_users
// - yordi_orders

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

// ---------- CONFIG ----------
const PORT = process.env.PORT || 3000;

// ✅ Can be same cluster URI as Fashion
const MONGODB_URI = process.env.MONGODB_URI;

// ✅ Force DB name for Yordi
const DB_NAME = process.env.DB_NAME || "Yordi_Coffee";

// ✅ Must match your frontend header: x-admin-key
const ADMIN_API_KEY = (process.env.ADMIN_API_KEY || "").trim();

// ✅ JWT for customer auth
const JWT_SECRET = (process.env.JWT_SECRET || "").trim();

// Email (optional for "Email Customer")
const GMAIL_USER = (process.env.GMAIL_USER || "").trim();
const GMAIL_APP_PASSWORD = (process.env.GMAIL_APP_PASSWORD || "").trim();
const EMAIL_FROM_NAME = (process.env.EMAIL_FROM_NAME || "Yordi Coffee").trim();

// Validate required env
if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in .env");
  process.exit(1);
}
if (!ADMIN_API_KEY) {
  console.warn("⚠️ ADMIN_API_KEY is missing. Admin routes will return 401 until you set it.");
}

// ---------- MIDDLEWARE ----------
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
  })
);

// ✅✅✅ FIX: DO NOT USE app.options("*") or app.options("/*") (your express/router crashes)
// Instead, handle preflight requests safely here:
app.use((req, res, next) => {
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "12mb" })); // base64 images
app.use(express.urlencoded({ extended: true }));

mongoose.set("strictQuery", true);
mongoose.set("bufferCommands", false);

// ---------- CONNECT (force db) ----------
let yordiDb = null;

(async () => {
  try {
    const base = await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 8000,
      socketTimeoutMS: 20000,
      family: 4,
    });

    // ✅ Force separation by DB name
    yordiDb = base.connection.useDb(DB_NAME, { useCache: true });

    console.log("✅ Mongo cluster connected");
    console.log("✅ Yordi DB forced to:", yordiDb.name);
  } catch (err) {
    console.error("❌ MongoDB error:", err?.message || err);
    process.exit(1);
  }
})();

function requireDb(req, res, next) {
  if (!yordiDb) return res.status(503).json({ error: "DB not ready yet" });
  next();
}

// ---------- MODELS (on yordiDb) ----------
// Coffee
const coffeeSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "coffee", trim: true }, // your UI uses beans/ground/espresso/...
    price: { type: Number, required: true },
    image: { type: String, default: "" }, // base64 or URL
  },
  { timestamps: true, collection: "yordi_coffee_items" }
);

// Users
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true, collection: "yordi_users" }
);
userSchema.index({ email: 1 }, { unique: true });

// Orders
const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "YordiUser" },

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
      method: { type: String, default: "cash" },
      telebirrRef: { type: String, default: "" },
      status: { type: String, default: "pending" }, // pending/paid/failed
    },

    total: { type: Number, default: 0 },
    status: { type: String, default: "placed" }, // placed/processing/delivered/cancelled
  },
  { timestamps: true, collection: "yordi_orders" }
);

function getModels() {
  const Coffee = yordiDb.models.YordiCoffee || yordiDb.model("YordiCoffee", coffeeSchema);
  const User = yordiDb.models.YordiUser || yordiDb.model("YordiUser", userSchema);
  const Order = yordiDb.models.YordiOrder || yordiDb.model("YordiOrder", orderSchema);
  return { Coffee, User, Order };
}

// ---------- HELPERS ----------
function requireAdmin(req, res, next) {
  const key = (req.header("x-admin-key") || "").trim();

  if (!ADMIN_API_KEY) {
    return res.status(401).json({ error: "Admin not configured on server (missing ADMIN_API_KEY)" });
  }

  if (!key || key !== ADMIN_API_KEY) return res.status(401).json({ error: "Unauthorized (admin key)" });
  next();
}

function authMiddleware(req, res, next) {
  const auth = req.header("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { userId, email }
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function calcTotal(items = []) {
  return (items || []).reduce((sum, it) => sum + (Number(it.price) || 0) * (Number(it.qty) || 1), 0);
}

// ---------- EMAIL (optional) ----------
let mailer = null;
function getMailer() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) return null;
  if (mailer) return mailer;
  mailer = nodemailer.createTransport({
    service: "gmail",
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
  });
  return mailer;
}

async function sendCustomerEmail({ to, subject, text }) {
  const t = getMailer();
  if (!t) throw new Error("Email not configured (missing GMAIL_USER or GMAIL_APP_PASSWORD).");
  if (!to) throw new Error("Customer email is missing.");
  await t.sendMail({
    from: `"${EMAIL_FROM_NAME}" <${GMAIL_USER}>`,
    to,
    subject,
    text,
  });
}

// ---------- ROUTES ----------
app.get("/", (req, res) => res.json({ ok: true, app: "Yordi Coffee API" }));

app.get("/api/health", requireDb, (req, res) => {
  res.json({
    ok: true,
    forcedDb: yordiDb.name,
    adminKeySet: Boolean(ADMIN_API_KEY),
    emailConfigured: Boolean(GMAIL_USER && GMAIL_APP_PASSWORD),
    collections: {
      coffee: "yordi_coffee_items",
      users: "yordi_users",
      orders: "yordi_orders",
    },
  });
});

// ---- ADMIN VERIFY (frontend uses this to unlock admin) ----
app.get("/api/admin/verify", requireDb, requireAdmin, (req, res) => res.json({ ok: true }));

// ---- COFFEE ----
app.get("/api/coffee", requireDb, async (req, res) => {
  try {
    const { Coffee } = getModels();
    const list = await Coffee.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load coffee", details: err?.message || String(err) });
  }
});

app.post("/api/coffee", requireDb, requireAdmin, async (req, res) => {
  try {
    const { Coffee } = getModels();
    const { name, description = "", category = "coffee", price, image = "" } = req.body || {};

    if (!name || price === undefined || price === null)
      return res.status(400).json({ error: "name and price are required" });

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

app.put("/api/coffee/:id", requireDb, requireAdmin, async (req, res) => {
  try {
    const { Coffee } = getModels();
    const { name, description = "", category = "coffee", price, image } = req.body || {};

    if (!name || price === undefined || price === null)
      return res.status(400).json({ error: "name and price are required" });

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

app.delete("/api/coffee/:id", requireDb, requireAdmin, async (req, res) => {
  try {
    const { Coffee } = getModels();
    const deleted = await Coffee.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Coffee not found" });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete coffee", details: err?.message || String(err) });
  }
});

// ---- AUTH ----
app.post("/api/auth/register", requireDb, async (req, res) => {
  try {
    const { User } = getModels();
    const { fullName, email, password } = req.body || {};

    if (!fullName || !email || !password)
      return res.status(400).json({ error: "fullName, email, password required" });
    if (String(password).length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters" });

    const emailNorm = String(email).toLowerCase().trim();
    const exists = await User.findOne({ email: emailNorm }).lean();
    if (exists) return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({
      fullName: String(fullName).trim(),
      email: emailNorm,
      passwordHash,
    });

    const token = jwt.sign({ userId: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: "30d" });

    res.json({ token, user: { fullName: user.fullName, email: user.email } });
  } catch (err) {
    if (String(err?.code) === "11000") return res.status(400).json({ error: "Email already registered" });
    res.status(500).json({ error: "Register failed", details: err?.message || String(err) });
  }
});

app.post("/api/auth/login", requireDb, async (req, res) => {
  try {
    const { User } = getModels();
    const { email, password } = req.body || {};

    if (!email || !password) return res.status(400).json({ error: "email and password required" });

    const emailNorm = String(email).toLowerCase().trim();
    const user = await User.findOne({ email: emailNorm });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ userId: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: "30d" });

    res.json({ token, user: { fullName: user.fullName, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err?.message || String(err) });
  }
});

// ---- ORDERS (CUSTOMER) ----
app.post("/api/orders", requireDb, authMiddleware, async (req, res) => {
  try {
    const { Order } = getModels();

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

    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: "Failed to place order", details: err?.message || String(err) });
  }
});

app.get("/api/orders/my", requireDb, authMiddleware, async (req, res) => {
  try {
    const { Order } = getModels();
    const list = await Order.find({ userId: req.user.userId }).sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load orders", details: err?.message || String(err) });
  }
});

// ---- ADMIN: ALL ORDERS ----
app.get("/api/admin/orders", requireDb, requireAdmin, async (req, res) => {
  try {
    const { Order } = getModels();
    const list = await Order.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load admin orders", details: err?.message || String(err) });
  }
});

// ---- ADMIN: UPDATE ORDER ----
app.put("/api/admin/orders/:id", requireDb, requireAdmin, async (req, res) => {
  try {
    const { Order } = getModels();
    const { status, paymentStatus } = req.body || {};

    const update = {};
    if (status !== undefined) update.status = String(status);
    if (paymentStatus !== undefined) update["payment.status"] = String(paymentStatus);

    const updated = await Order.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!updated) return res.status(404).json({ error: "Order not found" });

    res.json({ ok: true, order: updated });
  } catch (err) {
    res.status(500).json({ error: "Failed to update order", details: err?.message || String(err) });
  }
});

// ---- ADMIN: EMAIL CUSTOMER ABOUT ORDER ----
app.post("/api/admin/orders/:id/email", requireDb, requireAdmin, async (req, res) => {
  try {
    const { Order } = getModels();
    const { template = "custom", message = "", subject = "" } = req.body || {};

    const order = await Order.findById(req.params.id).lean();
    if (!order) return res.status(404).json({ error: "Order not found" });

    const customerEmail = (order.customer?.email || "").trim();
    if (!customerEmail) return res.status(400).json({ error: "Customer email is missing on this order" });

    const orderId = order.orderId || "";
    const customerName = order.customer?.fullName || "Customer";
    const payMethod = order.payment?.method || "";
    const payStatus = order.payment?.status || "pending";
    const orderStatus = order.status || "placed";
    const total = order.total || 0;

    const templates = {
      paid: {
        subject: `Payment Confirmed - Order ${orderId}`,
        text: `Hello ${customerName},

Thank you! We have confirmed your payment for Order ${orderId}.
Payment Status: PAID
Order Status: ${orderStatus}
Total: ${total} ETB

— ${EMAIL_FROM_NAME}`,
      },
      failed: {
        subject: `Payment Issue - Order ${orderId}`,
        text: `Hello ${customerName},

We were unable to confirm your payment for Order ${orderId}.
Payment Status: FAILED
Payment Method: ${payMethod}
Order Status: ${orderStatus}
Total: ${total} ETB

Message from admin:
${message || "(none)"}

— ${EMAIL_FROM_NAME}`,
      },
      processing: {
        subject: `Order Update - Order ${orderId} is Processing`,
        text: `Hello ${customerName},

Your Order ${orderId} is now being processed.
Order Status: PROCESSING
Payment: ${payMethod} (${payStatus})
Total: ${total} ETB

Message from admin:
${message || "(none)"}

— ${EMAIL_FROM_NAME}`,
      },
      delivered: {
        subject: `Delivered - Order ${orderId}`,
        text: `Hello ${customerName},

Good news! Your Order ${orderId} has been delivered.
Order Status: DELIVERED
Total: ${total} ETB

Thank you for choosing ${EMAIL_FROM_NAME}.

— ${EMAIL_FROM_NAME}`,
      },
      custom: {
        subject: subject || `Message about your order ${orderId}`,
        text: `Hello ${customerName},

${message || ""}

Order: ${orderId}
Order Status: ${orderStatus}
Payment: ${payMethod} (${payStatus})
Total: ${total} ETB

— ${EMAIL_FROM_NAME}`,
      },
    };

    const picked = templates[String(template || "custom").toLowerCase()] || templates.custom;

    await sendCustomerEmail({ to: customerEmail, subject: picked.subject, text: picked.text });

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to send email", details: err?.message || String(err) });
  }
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`✅ Yordi backend listening on http://localhost:${PORT}`);
});
