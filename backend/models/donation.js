const mongoose = require("mongoose");

const DonationSchema = new mongoose.Schema(
  {
    amount: Number,
    donor_names: String,
    screenshot: String, // Cloudinary URL
    upi_id: String,
    category: String,
    payment_mode: { type: String, default: "Online" },
    status: { type: String, default: "pending" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Donation", DonationSchema);
