const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true, required: true },
    password: String,

    // 📞 PHONE SYSTEM
    countryCode: { type: String, default: "+91" },
    phone: String,
    phoneVerified: { type: Boolean, default: false },

    role: { type: String, default: "user" },

    // 📧 Manual email verification
    emailVerified: { type: Boolean, default: false },

    // 🚫 Ban system
    banned: { type: Boolean, default: false },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);
