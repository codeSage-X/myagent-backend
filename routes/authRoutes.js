const express = require('express');
const router = express.Router();
const {
  register,
  login,
  resendVerificationEmail,
  verifyEmail,
  forgotPassword,
  resetPassword,
  changePassword
} = require('../controllers/authController');

const authMiddleware = require('../middleware/authMiddleware');

// Auth routes
router.post('/register', register);
router.post('/login', login);
router.get('/verify-email', verifyEmail);
router.post('/resend-verification', resendVerificationEmail);
router.post('/logout', (req, res) => {
  res.status(200).json({ message: 'Successfully logged out' });
});

// New Password Flow
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/change-password', authMiddleware, changePassword);

module.exports = router;
