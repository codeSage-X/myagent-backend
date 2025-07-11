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
const {
  authLimiter,
  passwordResetLimiter
} = require('../middleware/rateLimiters');

// Auth routes
router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.get('/verify-email', verifyEmail);
router.post('/resend-verification', resendVerificationEmail);
router.post('/logout', (req, res) => {
  res.status(200).json({ message: 'Successfully logged out' });
});
router.post('/forgot-password', passwordResetLimiter, forgotPassword);
router.post('/reset-password', passwordResetLimiter, resetPassword);
router.post('/change-password', passwordResetLimiter, authMiddleware, changePassword);

module.exports = router;
