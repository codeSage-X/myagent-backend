const express = require('express');
const router = express.Router();
const { register, login, resendVerificationEmail, verifyEmail } = require('../controllers/authController');


// @route   POST /api/auth/register
router.post('/register', register);

// @route   POST /api/auth/login
router.post('/login', login);

// @route   GET /api/auth/verify-email
router.get('/verify-email', verifyEmail); 

router.post('/resend-verification', resendVerificationEmail);

// @route   POST /api/auth/logout
router.post('/logout', (req, res) => {
  res.status(200).json({ message: 'Successfully logged out' });
});

module.exports = router;
