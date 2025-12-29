/**
 * Yordi Coffee Backend (MongoDB Atlas + Mongoose + JWT Auth + Orders + Email)
 * - Customers: register/login, JWT token
 * - Orders: place order, view "my orders"
 * - Admin email notification: sends order details to eshetuwek1@gmail.com
 *
 * Install:
 *   npm i express cors mongoose dotenv jsonwebtoken bcryptjs nodemailer
 *
 * Run:
 *   node server.js
 */

require("dotenv").config();

const dns = require("dns");
dns.setDefaultResultOrder("ipv4first");

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const app = express();

// ---------- CONFIG ----------
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "eshetuwek1@gmail.com";
const GMAIL_USER = process.env.GMAIL_USER; // your gmail address
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD; // gmail app password

// Optional admin protection for coffee CRUD
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || ""; // if empty, admin routes are open (NOT recommended)

if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in .env");
  process.exit(1);
}

// ---------- MIDDLEWARE ----------
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }));
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
    console.error("🔎 Fix tips:");
    console.error("  - Atlas: Network Access -> Add IP (or 0.0.0.0/0 for testing)");
    console.error("  - Verify MONGODB_URI password is URL-encoded");
    process.exit(1);
  }
})();

// ---------- EMAIL (Gmail App Password) ----------
let mailer = null;
if (GMAIL_USER && GMAIL_APP_PASSWORD) {
  mailer = nodemailer.createTransport({
    service: "gmail",
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
  });
} else {
  console.warn("⚠️ Email not configured. Add GMAIL_USER and GMAIL_APP_PASSWORD in .env to enable order emails.");
}

async function sendOrderEmail({ to, subject, html }) {
  if (!mailer) return;
  await mailer.sendMail({
    from: `"Yordi Coffee" <${GMAIL_USER}>`,
    to,
    subject,
    html,
  });
}

// ---------- HELPERS ----------
function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Missing token" });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function adminRequired(req, res, next) {
  if (!ADMIN_API_KEY) return next(); // not recommended, but allowed
  const key = req.headers["x-admin-key"] || "";
  if (String(key) !== String(ADMIN_API_KEY)) {
    return res.status(401).json({ error: "Unauthorized (admin key required)" });
  }
  next();
}

function money(n) {
  const x = Number(n) || 0;
  return Math.round(x);
}

// ---------- MODELS ----------
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

const coffeeSchema = new mongoose.Schema(
  {
    id: { type: String, index: true }, // optional custom id
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "coffee", trim: true }, // beans, ground, etc.
    size: { type: String, default: "single", trim: true }, // optional
    price: { type: Number, required: true },
    image: { type: String, default: "" }, // base64 or URL
  },
  { timestamps: true }
);

const Coffee = mongoose.model("Coffee", coffeeSchema);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, unique: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    customer: {
      fullName: String,
      phone: String,
      email: String,
      address: String,
      city: String,
      country: String,
      notes: String,
    },
    items: [
      {
        productId: String,
        name: String,
        price: Number,
        qty: Number,
        image: String,
      },
    ],
    payment: {
      method: { type: String, default: "cash" }, // cash/card/telebirr
      status: { type: String, default: "pending" },
      telebirrRef: { type: String, default: "" },
    },
    total: { type: Number, default: 0 },
    status: { type: String, default: "placed" }, // placed/processing/delivered/cancelled
  },
  { timestamps: true }
);

const Order = mongoose.model("Order", orderSchema);

// ---------- ROUTES ----------
app.get("/", (req, res) => res.json({ ok: true, app: "Yordi Coffee API" }));

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    mongoState: mongoose.connection.readyState,
    db: mongoose.connection.name,
    emailConfigured: Boolean(mailer),
  });
});

// ---------- AUTH ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: "fullName, email, password are required" });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const existing = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (existing) return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({
      fullName: String(fullName).trim(),
      email: String(email).toLowerCase().trim(),
      passwordHash,
    });

    const token = signToken(user);
    res.json({ token, user: { id: user._id, fullName: user.fullName, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: "Register failed", details: err?.message || String(err) });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Invalid email or password" });

    const token = signToken(user);
    res.json({ token, user: { id: user._id, fullName: user.fullName, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err?.message || String(err) });
  }
});

// ---------- COFFEE ----------
app.get("/api/coffee", async (req, res) => {
  try {
    const list = await Coffee.find().sort({ createdAt: -1 }).lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to load coffee", details: err?.message || String(err) });
  }
});

// Admin-only (recommended) create/update/delete coffee
app.post("/api/coffee", adminRequired, async (req, res) => {
  try {
    const { name, description = "", category = "coffee", size = "single", price, image = "" } = req.body || {};
    if (!name || price === undefined) return res.status(400).json({ error: "name and price are required" });

    const created = await Coffee.create({
      id: "coffee-" + Date.now(),
      name: String(name).trim(),
      description: String(description || "").trim(),
      category: String(category || "coffee").trim(),
      size: String(size || "single").trim(),
      price: Number(price),
      image: String(image || ""),
    });

    res.json(created);
  } catch (err) {
    res.status(500).json({ error: "Failed to add coffee", details: err?.message || String(err) });
  }
});

app.put("/api/coffee/:id", adminRequired, async (req, res) => {
  try {
    const { name, description = "", category = "coffee", size = "single", price, image } = req.body || {};
    if (!name || price === undefined) return res.status(400).json({ error: "name and price are required" });

    const update = {
      name: String(name).trim(),
      description: String(description || "").trim(),
      category: String(category || "coffee").trim(),
      size: String(size || "single").trim(),
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

app.delete("/api/coffee/:id", adminRequired, async (req, res) => {
  try {
    const deleted = await Coffee.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Coffee not found" });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete coffee", details: err?.message || String(err) });
  }
});

// ---------- ORDERS ----------
app.post("/api/orders", authRequired, async (req, res) => {
  try {
    const {
      items,
      fullName,
      phone,
      email,
      address,
      city,
      country,
      notes,
      paymentMethod,
      telebirrRef,
    } = req.body || {};

    const parsedItems = Array.isArray(items) ? items : [];
    if (!parsedItems.length) return res.status(400).json({ error: "Cart is empty" });

    if (!fullName || !phone || !address) {
      return res.status(400).json({ error: "fullName, phone, address are required" });
    }

    const total = money(
      parsedItems.reduce((sum, it) => sum + (Number(it.price) || 0) * (Number(it.qty) || 1), 0)
    );

    const orderId = "YORDI-" + Date.now();

    const order = await Order.create({
      orderId,
      userId: req.user.id,
      customer: {
        fullName: String(fullName || ""),
        phone: String(phone || ""),
        email: String(email || req.user.email || ""),
        address: String(address || ""),
        city: String(city || ""),
        country: String(country || ""),
        notes: String(notes || ""),
      },
      items: parsedItems.map((it) => ({
        productId: String(it.productId || ""),
        name: String(it.name || ""),
        price: Number(it.price) || 0,
        qty: Number(it.qty) || 1,
        image: String(it.image || ""),
      })),
      payment: {
        method: String(paymentMethod || "cash"),
        status: "pending",
        telebirrRef: String(telebirrRef || ""),
      },
      total,
      status: "placed",
    });

    // ✅ Email you (admin) + optionally email customer
    const itemsHtml = order.items
      .map(
        (it) =>
          `<li><b>${escapeHtml(it.name)}</b> — Qty: ${it.qty} — ${money(it.price)} ETB</li>`
      )
      .join("");

    const adminHtml = `
      <h2>☕ New Yordi Coffee Order</h2>
      <p><b>Order ID:</b> ${escapeHtml(order.orderId)}</p>
      <p><b>Total:</b> ${money(order.total)} ETB</p>

      <h3>Customer</h3>
      <p>
        <b>Name:</b> ${escapeHtml(order.customer.fullName)}<br/>
        <b>Phone:</b> ${escapeHtml(order.customer.phone)}<br/>
        <b>Email:</b> ${escapeHtml(order.customer.email || "")}<br/>
        <b>Address:</b> ${escapeHtml(order.customer.address)}, ${escapeHtml(order.customer.city || "")}, ${escapeHtml(order.customer.country || "")}<br/>
        <b>Notes:</b> ${escapeHtml(order.customer.notes || "")}
      </p>

      <h3>Items</h3>
      <ul>${itemsHtml}</ul>

      <h3>Payment</h3>
      <p><b>Method:</b> ${escapeHtml(order.payment.method)}<br/>
         <b>Telebirr Ref:</b> ${escapeHtml(order.payment.telebirrRef || "")}</p>

      <p style="color:#666;">Created: ${new Date(order.createdAt).toLocaleString()}</p>
    `;

    // send to you
    await sendOrderEmail({
      to: ADMIN_EMAIL,
      subject: `New Order ${order.orderId} — ${money(order.total)} ETB`,
      html: adminHtml,
    });

    // send to customer (if they provided an email)
    if (order.customer.email) {
      const customerHtml = `
        <h2>✅ Your Yordi Coffee Order is Placed</h2>
        <p><b>Order ID:</b> ${escapeHtml(order.orderId)}</p>
        <p><b>Total:</b> ${money(order.total)} ETB</p>
        <h3>Items</h3>
        <ul>${itemsHtml}</ul>
        <p style="color:#666;">We will contact you soon. Thank you!</p>
      `;
      await sendOrderEmail({
        to: order.customer.email,
        subject: `Yordi Coffee Order Confirmation — ${order.orderId}`,
        html: customerHtml,
      });
    }

    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: "Failed to place order", details: err?.message || String(err) });
  }
});

app.get("/api/orders/my", authRequired, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 }).lean();
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: "Failed to load orders", details: err?.message || String(err) });
  }
});

// ---------- SMALL HTML ESCAPER FOR EMAIL ----------
function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`✅ Server listening on port ${PORT}`);
});
