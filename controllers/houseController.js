const House = require('../models/House');

// GET all houses
exports.getAllHouses = async (req, res) => {
  try {
    const houses = await House.find();
    res.json(houses);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// POST a new house
exports.createHouse = async (req, res) => {
  const { title, description, price, address, images } = req.body;
  try {
    const house = new House({
      title,
      description,
      price,
      address,
      images,
      ownerId: req.user.id  // Assuming user is authenticated
    });

    const saved = await house.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};
