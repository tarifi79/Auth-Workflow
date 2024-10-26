const jwt = require("jsonwebtoken");
const crypto = require("crypto");

exports.generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: "24h",
  });
};

exports.generateVerificationToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

exports.getCookieOptions = () => {
  return {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  };
};
