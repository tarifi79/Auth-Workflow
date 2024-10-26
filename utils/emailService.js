const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.sendVerificationEmail = async (email, token) => {
  const verificationURL = `http://localhost:3000/api/auth/verify/${token}`;

  console.log("Verification URL:", verificationURL); // For testing

  await transporter.sendMail({
    to: email,
    subject: "Verify Your Email",
    html: `
            <h1>Email Verification</h1>
            <p>Please click the link below to verify your email:</p>
            <a href="${verificationURL}">${verificationURL}</a>
            <p>This link will expire in 24 hours.</p>
        `,
  });
};

exports.sendResetPasswordEmail = async (email, token) => {
  const resetURL = `http://localhost:3000/api/auth/reset-password/${token}`;

  console.log("Reset Password URL:", resetURL); // For testing

  await transporter.sendMail({
    to: email,
    subject: "Reset Your Password",
    html: `
            <h1>Password Reset</h1>
            <p>Please click the link below to reset your password:</p>
            <a href="${resetURL}">${resetURL}</a>
            <p>This link will expire in 1 hour.</p>
        `,
  });
};
