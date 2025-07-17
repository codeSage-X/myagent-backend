const User = require('../models/User');
const BlacklistedToken = require('../models/BlacklistedToken');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const passport = require('passport');

// Helper function to generate JWT
const generateToken = (userId) => {
  const payload = { user: { id: userId } };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });
};

// Helper function to get user response object
const getUserResponse = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  isHouseOwner: user.isHouseOwner,
  avatar: user.avatar,
  provider: user.provider,
  hasPassword: user.hasPassword
});

exports.register = async (req, res) => {
  const { name, email, password, isHouseOwner } = req.body;

  try {
    let existingUser = await User.findOne({ email });
    if (existingUser) {
      if (existingUser.googleId && !existingUser.hasPassword) {
        return res.status(400).json({ 
          msg: 'An account with this email exists via Google. Please sign in with Google or add a password to your account.' 
        });
      }
      return res.status(400).json({ msg: 'User already exists' });
    }

    const user = new User({ name, email, password, isHouseOwner });

    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    user.verifyToken = hashedOTP;
    user.verifyTokenExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: `"My Agent App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Email Verification Code',
      html: `
        <p>Hi ${name},</p>
        <p>Your verification code is:</p>
        <h2>${otp}</h2>
        <p>This code will expire in 10 minutes.</p>
      `
    });

    res.status(201).json({
      msg: 'Registration successful. Please check your email for the verification code.'
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    // Check if user registered with Google and has no password
    if (user.googleId && !user.hasPassword) {
      return res.status(400).json({ 
        msg: 'This account was created with Google. Please sign in with Google or add a password to your account.',
        loginWithGoogle: true
      });
    }

    if (!user.isVerified) {
      return res.status(401).json({ msg: 'Please verify your email before logging in.' });
    }

    if (!user.password) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = generateToken(user._id);

    res.json({
      token,
      user: getUserResponse(user)
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};

// Google OAuth Routes
exports.googleAuth = passport.authenticate('google', {
  scope: ['profile', 'email']
});

exports.googleCallback = (req, res, next) => {
  passport.authenticate('google', { session: false }, (err, user) => {
    if (err) {
      console.error('Google OAuth error:', err);
      return res.redirect(`${process.env.CLIENT_URL}/auth/error?message=Authentication failed`);
    }

    if (!user) {
      return res.redirect(`${process.env.CLIENT_URL}/auth/error?message=Authentication failed`);
    }

    try {
      const token = generateToken(user._id);
      
      // Redirect to frontend with token
      res.redirect(`${process.env.CLIENT_URL}/auth/success?token=${token}`);
    } catch (error) {
      console.error('Token generation error:', error);
      res.redirect(`${process.env.CLIENT_URL}/auth/error?message=Token generation failed`);
    }
  })(req, res, next);
};

// Add password to Google account
exports.addPassword = async (req, res) => {
  const { password } = req.body;
  const userId = req.user?.id;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ msg: 'User not found' });

    if (user.hasPassword) {
      return res.status(400).json({ msg: 'Account already has a password. Use change password instead.' });
    }

    user.password = password; // Will be hashed by pre-save middleware
    await user.save();

    res.status(200).json({ msg: 'Password added successfully. You can now login with email and password.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};

// Link Google account to existing account
exports.linkGoogleAccount = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    if (user.googleId) {
      return res.status(400).json({ msg: 'Google account already linked' });
    }

    if (!user.canLoginWithPassword()) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    // Store user in session for Google OAuth
    req.session.linkAccountUserId = user._id;
    
    res.json({ msg: 'Credentials verified. Please proceed with Google authentication.', linkAccount: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};


exports.verifyEmail = async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ msg: 'Email and OTP are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    if (!user.verifyTokenExpires || user.verifyTokenExpires < Date.now()) {
      return res.status(400).json({ msg: 'OTP has expired. Please request a new one.' });
    }

    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    if (user.verifyToken !== hashedOTP) {
      return res.status(400).json({ msg: 'Invalid OTP. Please check and try again.' });
    }

    user.isVerified = true;
    user.verifyToken = undefined;
    user.verifyTokenExpires = undefined;
    await user.save();

    res.status(200).json({ msg: 'Email verified successfully. You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};


exports.resendVerificationEmail = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    if (user.isVerified) {
      return res.status(400).json({ msg: 'Email already verified' });
    }

    // ⏱️ Check if OTP was recently sent (within 60 seconds)
    if (user.verifyTokenExpires && Date.now() < user.verifyTokenExpires - (9 * 60 * 1000)) {
      return res.status(429).json({
        msg: 'OTP already sent recently. Please wait before requesting another.'
      });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    user.verifyToken = hashedOTP;
    user.verifyTokenExpires = Date.now() + 10 * 60 * 1000; // valid for 10 minutes
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: `"My Agent App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Verification Code (Resent)',
      html: `
        <p>Hi ${user.name},</p>
        <p>Your new verification code is:</p>
        <h2>${otp}</h2>
        <p>This code will expire in 10 minutes.</p>
      `
    });

    res.status(200).json({ msg: 'Verification code resent successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};

// FORGOT PASSWORD - Send OTP
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    user.resetPasswordToken = hashedOTP;
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: `"My Agent App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Reset Your Password',
      html: `
        <p>Hi ${user.name},</p>
        <p>Your password reset OTP is:</p>
        <h2>${otp}</h2>
        <p>This code will expire in 10 minutes.</p>
      `
    });

    res.status(200).json({ msg: 'Reset code sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};
// RESET PASSWORD with OTP
exports.resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    if (!user.resetPasswordExpires || user.resetPasswordExpires < Date.now()) {
      return res.status(400).json({ msg: 'OTP has expired. Please request a new one.' });
    }

    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    if (user.resetPasswordToken !== hashedOTP) {
      return res.status(400).json({ msg: 'Invalid OTP. Please check and try again.' });
    }

    // Set the new password directly and let the pre-save middleware handle hashing
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ msg: 'Password reset successful. You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};

// CHANGE PASSWORD (Authenticated)
exports.changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user?.id;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Current password is incorrect' });

    // Set the new password directly and let the pre-save middleware handle hashing
    user.password = newPassword;
    await user.save();

    res.status(200).json({ msg: 'Password changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};

// Updated logout function
exports.logout = async (req, res) => {
  try {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(400).json({ msg: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add token to blacklist
    await BlacklistedToken.create({
      token: token,
      expiresAt: new Date(decoded.exp * 1000)
    });

    res.status(200).json({ msg: 'Successfully logged out' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};


