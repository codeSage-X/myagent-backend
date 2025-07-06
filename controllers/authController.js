const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.register = async (req, res) => {
  const { name, email, password, isHouseOwner } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    user = new User({ name, email, password, isHouseOwner });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '30d'
    });

    res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email, isHouseOwner } });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });


    // 3. Create JWT payload
    const payload = {
      user: {
        id: user._id // 👈 This is what you'll decode later in middleware
      }
    };

    // 4. Sign the token
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });

    // 5. Return token and user info
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isHouseOwner: user.isHouseOwner

      }
    });


    res.json({ token, user: { id: user._id, name: user.name, email: user.email, isHouseOwner: user.isHouseOwner } });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
};
