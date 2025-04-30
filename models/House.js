const mongoose = require('mongoose');

const houseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  price: Number,
  address: String,
  images: [String],
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: {
    type: String,
    enum: ['available', 'rented', 'sold'],
    default: 'available'
  }
}, { timestamps: true });

module.exports = mongoose.model('House', houseSchema);
