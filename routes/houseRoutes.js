const express = require('express');
const router = express.Router();
const houseController = require('../controllers/houseController'); // Adjust path if needed

// Example route
router.post('/', houseController.createHouse);

module.exports = router;
