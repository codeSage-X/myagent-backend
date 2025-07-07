const express = require('express');
const router = express.Router();
const { deleteUserById } = require('../controllers/authController');

// @route   DELETE /api/auth/users/:id
router.delete('/users/:id', deleteUserById);


module.exports = router;