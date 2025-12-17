// ================== server.js ==================
require("dotenv").config();
console.log("ENV CHECK:", process.env.MONGO_URI);

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Resend } = require("resend");
const resend = new Resend(process.env.RESEND_API_KEY);

const mongoose = require("mongoose");
const cloudinary = require("cloudinary").v2;
const cloudinaryStorage = require("multer-storage-cloudinary");

// ====== MODELS ======
const User = require("./models/user");
const Member = require("./models/member");
const Donation = require("./models/donation");
const Otp = require("./models/otp");

const app = express();

/* ================== CORS ================== */
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://vivekanandaboysclub2010.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS not allowed"));
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
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("❌ MONGO_URI missing in .env");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI)
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
    });
    console.log("Top admin created");
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

/* ================== AUTH ROUTES ================== */
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password, phone } = req.body;
  const hash = await bcrypt.hash(password, 10);

  const user = await User.create({
    name,
    email,
    password: hash,
    phone,
  });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ token, user });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ token, user });
});

/* ================== EMAIL OTP ================== */
app.post("/api/auth/request-verify", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  if (user.emailVerified) {
    return res.json({ ok: true, alreadyVerified: true });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();

  await Otp.deleteMany({ user_id: user._id, type: "email" });

  await Otp.create({
    user_id: user._id,
    code,
    type: "email",
    target: user.email,
  });

  await resend.emails.send({
    from: "BBC <onboarding@resend.dev>",
    to: user.email,
    subject: "Email Verification OTP",
    html: `<h2>Your OTP is ${code}</h2><p>Valid for 5 minutes.</p>`,
  });

  res.json({ ok: true });
});

app.post("/api/auth/verify-otp", authMiddleware, async (req, res) => {
  const { code } = req.body;

  const otp = await Otp.findOne({
    user_id: req.user.id,
    code,
    type: "email",
  });

  if (!otp) return res.status(400).json({ error: "Invalid OTP" });

  const diff = Date.now() - otp.createdAt.getTime();
  if (diff > 5 * 60 * 1000) {
    await otp.deleteOne();
    return res.status(400).json({ error: "OTP expired" });
  }

  await User.findByIdAndUpdate(req.user.id, {
    emailVerified: true,
  });

  await otp.deleteOne();
  res.json({ ok: true, verified: true });
});

/* ================== HEALTH ================== */
app.get("/api/ping", (req, res) => res.json({ ok: true }));

/* ================== START ================== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("Server running on", PORT));
