const mongoose = require("mongoose");

const donationSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  amount: { type: Number, default: 0 },
  donor_names: { type: String, default: "Unknown" },
  screenshot_url: { type: String, default: null },   // Cloudinary URL
  screenshot_public_id: { type: String, default: null }, // cloudinary public id for deletion
  upi_id: { type: String, default: "-" },
  category: { type: String, default: "General" },
  payment_mode: { type: String, default: "Online" }, // Online | Manual | Cash etc
  status: { type: String, default: "pending" }
}, { timestamps: true });

module.exports = mongoose.model("Donation", donationSchema);
