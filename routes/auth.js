// routes/auth.js
const express = require("express");
const router = express.Router();
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

const User = require("../models/user");
const authMiddleware = require("../middleware/auth");

dotenv.config();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post(
  "/register",
  [
    check("name", "Name is required").not().isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    console.log("register");
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Extract data
    const { name, email, password } = req.body;
    console.log(req.body);

    try {
      // Check if user exists
      let user = await User.findOne({ email });
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }

      // Create new user instance
      user = new User({
        name,
        email,
        password,
      });

      // Hash password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

      // Save user to database
      await user.save();

      // Create payload for JWT
      const payload = {
        user: {
          id: user.id,
        },
      };

      // Sign JWT
      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE },
        (err, token) => {
          if (err) throw err;
          res.status(201).json({ token, user: { id: user.id, name, email } });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user & get token
 * @access  Public
 */
router.post(
  "/login",
  [
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password is required").exists(),
  ],
  async (req, res) => {
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Extract data
    const { email, password } = req.body;

    try {
      // Check for user
      let user = await User.findOne({ email }).select("+password");
      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "Invalid Credentials" }] });
      }

      // Compare password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: "Invalid Credentials" }] });
      }

      // Create payload
      const payload = {
        user: {
          id: user.id,
        },
      };

      // Sign JWT
      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE },
        (err, token) => {
          if (err) throw err;
          res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email },
          });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

/**
 * @route   GET /api/auth/me
 * @desc    Get current logged-in user
 * @access  Private
 */
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password"); // Exclude password
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Private
 *
 * Note: Since JWT is stateless, to "logout" we can implement token blacklisting.
 * However, for simplicity, we'll handle logout on the client by deleting the token.
 * Alternatively, implement a token blacklist in the database or cache.
 */
router.post("/logout", authMiddleware, async (req, res) => {
  // Optionally implement token blacklisting
  // For simplicity, we'll respond with success
  res.json({ msg: "Logged out successfully" });
});

module.exports = router;
