const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

exports.register = async (req, res) => {
  const { name, email, password, isHouseOwner } = req.body;

  try {
    let existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ msg: 'User already exists' });

    const user = new User({ name, email, password, isHouseOwner });

    // 🔐 Generate a 6-digit OTP
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
    // 1. Find user by email
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    // 2. Check if email is verified
    if (!user.isVerified) {
      return res.status(401).json({ msg: 'Please verify your email before logging in.' });
    }

    // 3. Check password match
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    // 4. Create JWT payload
    const payload = {
      user: {
        id: user._id
      }
    };

    // 5. Sign token
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });

    // 6. Return token and user info
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isHouseOwner: user.isHouseOwner
      }
    });

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


