const User = require("../models/User");
const AppError = require("../utils/AppError");
const emailService = require("../utils/emailService");
const tokenService = require("../utils/tokenService");
const { StatusCodes } = require("http-status-codes");

/**
 * Register a new user
 * @route POST /api/v1/auth/register
 * @param {string} name - User's full name
 * @param {string} email - User's email address
 * @param {string} password - User's password
 * @returns {object} Message confirming registration
 */
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  // Check for existing user
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new AppError("Email already registered", StatusCodes.BAD_REQUEST);
  }

  // Generate verification token with 24-hour expiry
  const verificationToken = tokenService.generateVerificationToken();
  const tokenExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  // Create new user
  const user = await User.create({
    name,
    email,
    password,
    verificationToken,
    verificationTokenExpires: tokenExpiry,
  });

  // Send verification email
  await emailService.sendVerificationEmail(email, verificationToken);

  res.status(StatusCodes.CREATED).json({
    status: "success",
    message:
      "Registration successful. Please check your email to verify your account.",
  });
};

/**
 * Verify user's email address
 * @route GET /api/v1/auth/verify/:token
 * @param {string} token - Email verification token
 * @returns {object} Message confirming verification
 */
exports.verifyEmail = async (req, res) => {
  const { token } = req.params;

  // Find user with valid verification token
  const user = await User.findOne({
    verificationToken: token,
    verificationTokenExpires: { $gt: Date.now() },
  });

  if (!user) {
    throw new AppError(
      "Invalid or expired verification token",
      StatusCodes.BAD_REQUEST
    );
  }

  // Update user verification status
  user.isVerified = true;
  user.verificationToken = undefined;
  user.verificationTokenExpires = undefined;
  await user.save();

  // Auto login after verification
  const jwtToken = tokenService.generateToken(user._id);
  res.cookie("jwt", jwtToken, tokenService.getCookieOptions());

  res.status(StatusCodes.OK).json({
    status: "success",
    message: "Email verified successfully",
  });
};

/**
 * Login user
 * @route POST /api/v1/auth/login
 * @param {string} email - User's email
 * @param {string} password - User's password
 * @returns {object} Success message and sets JWT cookie
 */
exports.login = async (req, res) => {
  const { email, password } = req.body;

  // Validate request body
  if (!email || !password) {
    throw new AppError(
      "Please provide email and password",
      StatusCodes.BAD_REQUEST
    );
  }

  // Find user and include password for comparison
  const user = await User.findOne({ email }).select("+password");

  // Verify user exists and password is correct
  if (!user || !(await user.comparePassword(password))) {
    throw new AppError("Invalid email or password", StatusCodes.UNAUTHORIZED);
  }

  // Check email verification status
  if (!user.isVerified) {
    throw new AppError(
      "Please verify your email first",
      StatusCodes.UNAUTHORIZED
    );
  }

  // Generate token and set cookie
  const token = tokenService.generateToken(user._id);
  res.cookie("jwt", token, tokenService.getCookieOptions());

  res.status(StatusCodes.OK).json({
    status: "success",
    message: "Logged in successfully",
  });
};

/**
 * Logout user
 * @route GET /api/v1/auth/logout
 * @returns {object} Success message and clears JWT cookie
 */
exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 1000),
    httpOnly: true,
  });

  res.status(StatusCodes.OK).json({
    status: "success",
    message: "Logged out successfully",
  });
};

/**
 * Request password reset
 * @route POST /api/v1/auth/forgot-password
 * @param {string} email - User's email address
 * @returns {object} Message confirming reset email sent
 */
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  // Find user by email
  const user = await User.findOne({ email });

  if (!user) {
    throw new AppError("No user found with that email", StatusCodes.NOT_FOUND);
  }

  // Generate reset token with 1-hour expiry
  const resetToken = tokenService.generateVerificationToken();
  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  await user.save();

  // Send password reset email
  await emailService.sendResetPasswordEmail(email, resetToken);

  res.status(StatusCodes.OK).json({
    status: "success",
    message: "Password reset email sent",
  });
};

/**
 * Reset password using token
 * @route PATCH /api/v1/auth/reset-password/:token
 * @param {string} token - Reset password token
 * @param {string} password - New password
 * @returns {object} Success message and sets new JWT cookie
 */
exports.resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  // Find user with valid reset token
  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() },
  }).select("+password");

  if (!user) {
    throw new AppError(
      "Invalid or expired reset token",
      StatusCodes.BAD_REQUEST
    );
  }

  // Verify new password is different from current
  const isSamePassword = await user.comparePassword(password);
  if (isSamePassword) {
    throw new AppError(
      "New password cannot be the same as your old password",
      StatusCodes.BAD_REQUEST
    );
  }

  // Update password and clear reset token
  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  // Auto login after password reset
  const jwtToken = tokenService.generateToken(user._id);
  res.cookie("jwt", jwtToken, tokenService.getCookieOptions());

  res.status(StatusCodes.OK).json({
    status: "success",
    message: "Password reset successfully",
  });
};

/**
 * Update current user's profile
 * @route PATCH /api/v1/auth/update-user
 * @param {string} name - Optional: User's new name
 * @param {string} email - Optional: User's new email
 * @requires Authentication
 * @returns {object} Updated user data
 */
exports.updateUser = async (req, res) => {
  // Validate allowed updates
  const allowedUpdates = ["name", "email"];
  const updates = Object.keys(req.body);
  const isValidOperation = updates.every((update) =>
    allowedUpdates.includes(update)
  );

  if (!isValidOperation) {
    throw new AppError("Invalid updates", StatusCodes.BAD_REQUEST);
  }

  // If updating email, check availability
  if (req.body.email) {
    const existingUser = await User.findOne({ email: req.body.email });
    if (
      existingUser &&
      existingUser._id.toString() !== req.user._id.toString()
    ) {
      throw new AppError("Email already in use", StatusCodes.BAD_REQUEST);
    }
  }

  // Update user
  const user = await User.findByIdAndUpdate(req.user._id, req.body, {
    new: true,
    runValidators: true,
  });

  res.status(StatusCodes.OK).json({
    status: "success",
    data: { user },
  });
};

/**
 * Get current user's profile
 * @route GET /api/v1/auth/current-user
 * @requires Authentication
 * @returns {object} Current user data
 */
exports.getCurrentUser = async (req, res) => {
  const user = await User.findById(req.user._id);

  res.status(StatusCodes.OK).json({
    status: "success",
    data: { user },
  });
};

/**
 * Change current user's password
 * @route PATCH /api/v1/auth/change-password
 * @param {string} currentPassword - Current password
 * @param {string} newPassword - New password
 * @requires Authentication
 * @returns {object} Success message and sets new JWT cookie
 */
exports.changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  // Validate request body
  if (!currentPassword || !newPassword) {
    throw new AppError(
      "Please provide both current and new password",
      StatusCodes.BAD_REQUEST
    );
  }

  // Get user with password field
  const user = await User.findById(req.user._id).select("+password");

  // Verify current password
  const isCurrentPasswordValid = await user.comparePassword(currentPassword);
  if (!isCurrentPasswordValid) {
    throw new AppError(
      "Current password is incorrect",
      StatusCodes.UNAUTHORIZED
    );
  }

  // Check if new password is different
  const isSamePassword = await user.comparePassword(newPassword);
  if (isSamePassword) {
    throw new AppError(
      "New password cannot be the same as your current password",
      StatusCodes.BAD_REQUEST
    );
  }

  // Update password
  user.password = newPassword;
  await user.save();

  // Generate new token and set cookie
  const token = tokenService.generateToken(user._id);
  res.cookie("jwt", token, tokenService.getCookieOptions());

  res.status(StatusCodes.OK).json({
    status: "success",
    message: "Password changed successfully",
  });
};

/**
 * Resend email verification link
 * @route POST /api/v1/auth/resend-verification
 * @param {string} email - User's email address
 * @returns {object} Message confirming verification email sent
 */
exports.resendVerification = async (req, res) => {
  const { email } = req.body;

  // Find user by email
  const user = await User.findOne({ email });

  if (!user) {
    throw new AppError("No user found with that email", StatusCodes.NOT_FOUND);
  }

  if (user.isVerified) {
    throw new AppError("Email is already verified", StatusCodes.BAD_REQUEST);
  }

  // Generate new verification token
  const verificationToken = tokenService.generateVerificationToken();
  user.verificationToken = verificationToken;
  user.verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  await user.save();

  // Send verification email
  await emailService.sendVerificationEmail(user.email, verificationToken);

  res.status(StatusCodes.OK).json({
    status: "success",
    message: "Verification email resent successfully",
  });
};
