/**
 * Yordi Coffee Backend (MongoDB + Mongoose)
 * - Coffee CRUD (ADMIN protected with ADMIN_API_KEY)
 * - Auth (register/login) with JWT
 * - Orders + My Orders (JWT required)
 * - Admin: verify key, view/update ALL orders, email customer (Gmail SMTP)
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

// ---------- CONFIG ----------
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

const ADMIN_API_KEY = process.env.ADMIN_API_KEY || ""; // ✅ your env name
const JWT_SECRET = process.env.JWT_SECRET || "";

// Email (optional)
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";
const EMAIL_FROM_NAME = process.env.EMAIL_FROM_NAME || "Yordi Coffee";

// Validate required env
if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in .env");
  process.exit(1);
}

// ---------- MIDDLEWARE ----------
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
  })
);

// ✅ SAFE preflight handler (prevents path-to-regexp "*" crash)
app.use((req, res, next) => {
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

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
    process.exit(1);
  }
})();

// ---------- MODELS ----------
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
      status: { type: String, default: "pending" }, // pending/paid/failed
    },

    total: { type: Number, default: 0 },
    status: { type: String, default: "placed" }, // placed/processing/delivered/cancelled
  },
  { timestamps: true }
);
const Order = mongoose.model("Order", orderSchema);

// ---------- HELPERS ----------
function requireAdmin(req, res, next) {
  if (!ADMIN_API_KEY) {
    // If not set, allow (dev only)
    return next();
  }
  const key = (req.header("x-admin-key") || "").trim();
  if (!key || key !== ADMIN_API_KEY) return res.status(401).json({ error: "Unauthorized (admin key)" });
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

// ---------- EMAIL (GMAIL SMTP) ----------
let mailer = null;

function getMailer() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) return null;
  if (mailer) return mailer;

  // ✅ More reliable on Render than "service:gmail"
  mailer = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, // SSL
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },

    // ✅ prevent long hangs
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 30000,
    pool: false,

    tls: {
      servername: "smtp.gmail.com",
      rejectUnauthorized: true,
    },
  });

  return mailer;
}

async function sendCustomerEmail({ to, subject, text }) {
  const t = getMailer();
  if (!t) throw new Error("Email not configured (missing GMAIL_USER or GMAIL_APP_PASSWORD).");
  if (!to) throw new Error("Customer email is missing.");

  // ✅ fail fast with clear message if auth/network issue
  await t.verify();

  await t.sendMail({
    from: `"${EMAIL_FROM_NAME}" <${GMAIL_USER}>`,
    to,
    subject,
    text,
  });
}

// ---------- ROUTES ----------
app.get("/", (req, res) => {
  res.json({ ok: true, app: "Yordi Coffee API" });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    mongoState: mongoose.connection.readyState,
    db: mongoose.connection.name,
    adminKeySet: Boolean(ADMIN_API_KEY),
    emailConfigured: Boolean(GMAIL_USER && GMAIL_APP_PASSWORD),
  });
});

// ---- ADMIN VERIFY (unlock admin UI) ----
app.get("/api/admin/verify", requireAdmin, (req, res) => {
  res.json({ ok: true });
});

// ✅ EMAIL TEST (use to debug Render)
app.post("/api/admin/email-test", requireAdmin, async (req, res) => {
  try {
    const { to } = req.body || {};
    if (!to) return res.status(400).json({ error: "to is required" });

    await sendCustomerEmail({
      to: String(to).trim(),
      subject: "Yordi Coffee - Email Test",
      text: "This is a test email sent from your Render server.",
    });

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Email test failed", details: err?.message || String(err) });
  }
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

// ---- ORDERS (CUSTOMER) ----
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

// ---- ADMIN: ALL ORDERS ----
app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  try {
    const list = await Order.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load admin orders", details: err?.message || String(err) });
  }
});

// ---- ADMIN: UPDATE ORDER ----
app.put("/api/admin/orders/:id", requireAdmin, async (req, res) => {
  try {
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
app.post("/api/admin/orders/:id/email", requireAdmin, async (req, res) => {
  try {
    const { template = "custom", message = "", subject = "" } = req.body || {};

    const order = await Order.findById(req.params.id).lean();
    if (!order) return res.status(404).json({ error: "Order not found" });

    const customerEmail = (order.customer?.email || "").trim();
    // ✅ THIS is exactly where that check belongs
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

If you have any questions, reply to this email.

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

Please reply to this email or resend the payment and share the reference.

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

    await sendCustomerEmail({
      to: customerEmail,
      subject: picked.subject,
      text: picked.text,
    });

    res.json({ ok: true });
  } catch (err) {
    // ✅ better error details for your frontend
    res.status(500).json({
      error: "Failed to send email",
      details: err?.message || String(err),
      hint:
        "If you see 'Connection timeout' on Render, Gmail SMTP may be blocked/slow. Try /api/admin/email-test or use Resend/SendGrid.",
    });
  }
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://localhost:${PORT}`);
});
