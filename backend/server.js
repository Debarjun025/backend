// ================== server.js ==================
require("dotenv").config();
console.log("ENV CHECK:", process.env.MONGO_URI);

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const mongoose = require("mongoose");
const cloudinary = require("cloudinary").v2;
const cloudinaryStorage = require("multer-storage-cloudinary");

// ====== MODELS ======
const User = require("./models/user");
const Member = require("./models/member");
const Donation = require("./models/donation");

const app = express();

/* ================== CORS ================== */
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://vivekanandaboysclub2010.vercel.app",
];

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes(origin)) cb(null, true);
      else cb(new Error("CORS not allowed"));
    },
    credentials: true,
  })
);

app.options("*", cors());

/* ================== BASIC SETUP ================== */
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || "secret";

/* ================== MONGODB ================== */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

/* ================== CLOUDINARY ================== */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = cloudinaryStorage({
  cloudinary,
  params: {
    folder: "bbc",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
  },
});
const upload = multer({ storage });

/* ================== TOP ADMIN AUTO CREATE ================== */
async function createTopAdmin() {
  if (!process.env.TOP_ADMIN_EMAIL || !process.env.TOP_ADMIN_PASSWORD) return;

  const exists = await User.findOne({ email: process.env.TOP_ADMIN_EMAIL });
  if (!exists) {
    const hash = await bcrypt.hash(process.env.TOP_ADMIN_PASSWORD, 10);
    await User.create({
      name: "Top Admin",
      email: process.env.TOP_ADMIN_EMAIL,
      password: hash,
      role: "top-admin",
      emailVerified: true,
    });
    console.log("✅ Top admin created");
  }
}
createTopAdmin();

/* ================== AUTH MIDDLEWARE ================== */
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

/* ================== AUTH ================== */
app.post("/api/auth/register", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);

  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: hash,
    phone: req.body.phone,
  });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ token, user });
});

app.post("/api/auth/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  if (user.banned)
    return res.status(403).json({ error: "Account is banned" });

  const ok = await bcrypt.compare(req.body.password, user.password);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ token, user });
});

/* ================== ADMIN (TOP ADMIN ONLY) ================== */

// GET ALL USERS
app.get("/api/admin/all-users", authMiddleware, async (req, res) => {
  if (req.user.role !== "top-admin")
    return res.status(403).json({ error: "Top admin only" });

  const users = await User.find().select("-password").sort({ createdAt: -1 });
  res.json({ users });
});

// MANUAL EMAIL VERIFY
app.post("/api/admin/verify-user", authMiddleware, async (req, res) => {
  if (req.user.role !== "top-admin")
    return res.status(403).json({ error: "Top admin only" });

  await User.findByIdAndUpdate(req.body.id, { emailVerified: true });
  res.json({ ok: true });
});

// PROMOTE / DEMOTE
app.post("/api/admin/change-role", authMiddleware, async (req, res) => {
  if (req.user.role !== "top-admin")
    return res.status(403).json({ error: "Top admin only" });

  const { id, role } = req.body;

  if (!["user", "admin"].includes(role))
    return res.status(400).json({ error: "Invalid role" });

  await User.findByIdAndUpdate(id, { role });
  res.json({ ok: true });
});

// BAN / UNBAN USER
app.post("/api/admin/toggle-ban", authMiddleware, async (req, res) => {
  if (req.user.role !== "top-admin")
    return res.status(403).json({ error: "Top admin only" });

  const { id, banned } = req.body;
  await User.findByIdAndUpdate(id, { banned });
  res.json({ ok: true });
});

// RESET PASSWORD BY TOP ADMIN
app.post("/api/admin/reset-password", authMiddleware, async (req, res) => {
  if (req.user.role !== "top-admin")
    return res.status(403).json({ error: "Top admin only" });

  const hash = await bcrypt.hash(req.body.password, 10);
  await User.findByIdAndUpdate(req.body.id, { password: hash });

  res.json({ ok: true });
});

/* ================== HEALTH ================== */
app.get("/api/ping", (req, res) => res.json({ ok: true }));

/* ================== START ================== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("🚀 Server running on", PORT));
