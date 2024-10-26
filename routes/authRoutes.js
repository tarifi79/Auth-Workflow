// routes/authRoutes.js
const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { protect } = require("../middleware/auth");

// Public routes
router.post("/register", authController.register);
router.post("/login", authController.login);
router.get("/logout", authController.logout);
router.post("/forgot-password", authController.forgotPassword);
router.patch("/reset-password/:token", authController.resetPassword);
router.get("/verify/:token", authController.verifyEmail);
router.post("/resend-verification", authController.resendVerification);

// Protected routes (require authentication)
router.use(protect); // All routes after this middleware require authentication
router.get("/current-user", authController.getCurrentUser);
router.patch("/update-user", authController.updateUser);
router.patch("/change-password", authController.changePassword);

module.exports = router;
