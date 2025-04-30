const express = require('express');
const router = express.Router();
const houseController = require('../controllers/houseController');
const authMiddleware = require('../middleware/authMiddleware'); // protect()

router.get('/', houseController.getAllHouses);

// Protected route: only logged-in owners can create houses
router.post('/', authMiddleware, houseController.createHouse);

module.exports = router;
