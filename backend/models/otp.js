const mongoose = require("mongoose");

const OtpSchema = new mongoose.Schema(
  {
    user_id: mongoose.Schema.Types.ObjectId,
    code: String,
    type: String,
    target: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("Otp", OtpSchema);
