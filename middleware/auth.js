const jwt = require("jsonwebtoken");
const AppError = require("../utils/AppError");
const User = require("../models/User");

exports.protect = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    throw new AppError("Please log in to access this resource", 401);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      throw new AppError("User no longer exists", 401);
    }

    req.user = user;
    next();
  } catch (error) {
    throw new AppError("Invalid token", 401);
  }
};
