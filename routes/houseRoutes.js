const express = require('express');
const router = express.Router();
const houseController = require('../controllers/houseController'); // Adjust path if needed
const auth = require('../middleware/authMiddleware');

router.post('/', auth, houseController.createHouse); // 🔐 protect this route
router.get('/', houseController.getAllHouses);

module.exports = router;
