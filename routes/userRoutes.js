// routes/user.js
const express = require('express');
const router = express.Router();
const {
  getAllUsers,
  getUserById,
  editUserById,
  deleteUserById,
} = require('../controllers/userController');

// Base path: /api/users

router.get('/', getAllUsers);               // GET /api/users
router.get('/:id', getUserById);            // GET /api/users/:id
router.put('/:id', editUserById);           // PUT /api/users/:id
router.delete('/:id', deleteUserById);      // DELETE /api/users/:id

module.exports = router;
