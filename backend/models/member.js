const mongoose = require("mongoose");

const MemberSchema = new mongoose.Schema(
  {
    name: String,
    role: { type: String, enum: ["admin", "member"], default: "member" },
    phone: String,
    image: String, // Cloudinary URL
    facebook: String,
    instagram: String,
    whatsapp: String,
    category: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("Member", MemberSchema);
