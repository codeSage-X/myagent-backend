const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

exports.register = async (req, res) => {
  const { name, email, password, isHouseOwner } = req.body;

  try {
    // Check if user exists
    let existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ msg: 'User already exists' });

    // Create new user
    const user = new User({ name, email, password, isHouseOwner });

    // Generate email verification token
    const verificationToken = user.generateVerificationToken();
    await user.save();

    // Create email transport
    const transporter = nodemailer.createTransport({
      service: 'gmail', // Or any other service like SendGrid, Mailgun
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Send verification email
    const verifyURL = `${process.env.CLIENT_URL}/verify-email?token=${verificationToken}&email=${email}`;

    await transporter.sendMail({
      from: `"My Agent App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify Your Email',
      html: `
        <p>Hi ${name},</p>
        <p>Thanks for registering. Please verify your email by clicking the link below:</p>
        <a href="${verifyURL}">Verify Email</a>
        <p>This link will expire in 1 hour.</p>
      `
    });

    res.status(201).json({
      msg: 'Registration successful. Please check your email to verify your account.'
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
  const { token, email } = req.query;

  if (!token || !email) {
    return res.status(400).json({ msg: 'Missing token or email' });
  }

  try {
    // Hash the token received from query
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with matching hashed token and valid expiry
    const user = await User.findOne({
      email,
      verifyToken: hashedToken,
      verifyTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ msg: 'Invalid or expired verification token' });
    }

    // Mark user as verified
    user.isVerified = true;
    user.verifyToken = undefined;
    user.verifyTokenExpires = undefined;
    await user.save();

    return res.status(200).json({ msg: 'Email verified successfully. You can now log in.' });
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

    // Generate new verification token
    const verificationToken = user.generateVerificationToken();
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const verifyURL = `${process.env.CLIENT_URL}/verify-email?token=${verificationToken}&email=${email}`;

    await transporter.sendMail({
      from: `"My Agent App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Resend: Verify Your Email',
      html: `
        <p>Hi ${user.name},</p>
        <p>Please verify your email by clicking the link below:</p>
        <a href="${verifyURL}">Verify Email</a>
        <p>This link will expire in 1 hour.</p>
      `
    });

    res.status(200).json({ msg: 'Verification email resent successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
};