// routes/authRoutes.js
const express = require('express');
const router = express.Router();

// Example route
router.get('/test', (req, res) => {
  res.send('Auth route working!');
});

module.exports = router;
