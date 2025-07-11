const mongoose = require('mongoose');

// Define the schema
const blacklistedTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true }, // Each token must be unique
  expiresAt: { type: Date, required: true } // Token expiration (in milliseconds)
});

// Create a TTL index to auto-delete expired tokens
blacklistedTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Export the model
const BlacklistedToken = mongoose.model('BlacklistedToken', blacklistedTokenSchema);
