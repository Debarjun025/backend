const mongoose = require("mongoose");

const memberSchema = new mongoose.Schema({
  name: String,
  role: String, // Admin / Member
  phone: String,
  image_url: String,
  image_public_id: String,
  facebook: String,
  instagram: String,
  whatsapp: String,
  category: String
}, { timestamps: true });

module.exports = mongoose.model("Member", memberSchema);
