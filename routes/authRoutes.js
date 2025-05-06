const express = require('express');
const router = express.Router();
const { register, login } = require('../controllers/authController');

// @route   POST /api/auth/register
router.post('/register', register);

// @route   POST /api/auth/login
router.post('/login', login);

router.post('/logout', (req, res) => {
    // Optionally log this on server, but mainly for client to clear token
    res.status(200).json({ message: 'Successfully logged out' });
  });
  

module.exports = router;
