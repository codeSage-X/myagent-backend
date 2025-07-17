const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: function() {
      return !this.googleId;
    }
  },
  isHouseOwner: {
    type: Boolean,
    default: false
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verifyToken: String,
  verifyTokenExpires: Date,
    resetPasswordToken: String,
  resetPasswordExpires: Date,
  // Google OAuth fields
  googleId: {
    type: String,
    sparse: true // Allows null values but ensures uniqueness when present
  },
  avatar: String, // Store Google profile picture
  provider: {
    type: String,
    enum: ['local', 'google'],
    default: 'local'
  },
  // For users who signed up with Google but want to add password later
  hasPassword: {
    type: Boolean,
    default: function() {
      return !this.googleId; // false for Google users, true for regular users
    }
  }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  
  // Set hasPassword to true when password is being set
  if (this.password) {
    this.hasPassword = true;
  }
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Generate email verification token (instance method)
userSchema.methods.generateVerificationToken = function () {
  const token = crypto.randomBytes(32).toString('hex');
  this.verifyToken = crypto.createHash('sha256').update(token).digest('hex');
  this.verifyTokenExpires = Date.now() + 1000 * 60 * 60; // 1 hour expiry
  return token;
};

// Method to check if user can login with password
userSchema.methods.canLoginWithPassword = function() {
  return this.hasPassword && this.password;
};

module.exports = mongoose.model('User', userSchema);
