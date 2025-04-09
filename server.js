const express = require("express");
const AWS = require("aws-sdk");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const cors = require("cors");
const dotenv = require("dotenv");
const { OAuth2Client } = require("google-auth-library");

dotenv.config();

const app = express();
const port = 3000;

// Configure AWS Cognito
AWS.config.update({ region: process.env.AWS_COGNITO_REGION });
const cognito = new AWS.CognitoIdentityServiceProvider();

const clientId = process.env.AWS_COGNITO_CLIENT_ID;
const clientSecret = process.env.AWS_COGNITO_CLIENT_SECRET;
const googleClientId = process.env.GOOGLE_CLIENT_ID;

const googleClient = new OAuth2Client(googleClientId);

app.use(cors());
app.use(bodyParser.json());

// Helper: calculate secret hash for AWS Cognito
function calculateSecretHash(username, clientId, clientSecret) {
  const message = username + clientId;
  const hmac = crypto.createHmac("sha256", clientSecret);
  hmac.update(message);
  return hmac.digest("base64");
}

// ✅ Google Sign-In
app.post("/google-signin", async (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(400).json({ error: "No token provided" });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: googleClientId,
    });

    const payload = ticket.getPayload();
    console.log("✅ Google payload:", payload);

    // Here you could match this user with your DB or create a Cognito user
    return res.status(200).json({ message: "Google sign-in successful", user: payload });
  } catch (error) {
    console.error("❌ Google sign-in error:", error);
    return res.status(401).json({ error: "Google sign-in verification failed" });
  }
});

// ✅ Sign-Up
app.post("/signup", async (req, res) => {
  const { phoneNumber, email, password } = req.body;

  const secretHash = calculateSecretHash(email, clientId, clientSecret);
  const params = {
    ClientId: clientId,
    Username: email,
    Password: password,
    UserAttributes: [
      { Name: "email", Value: email },
      { Name: "phone_number", Value: phoneNumber },
    ],
    SecretHash: secretHash,
  };

  cognito.signUp(params, (err, data) => {
    if (err) {
      console.error("❌ Sign-up error:", err);
      return res.status(400).json({ error: err.message });
    }
    res.status(200).json({ message: "Sign-up successful", data });
  });
});

// ✅ Verify OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const secretHash = calculateSecretHash(email, clientId, clientSecret);

  const params = {
    ClientId: clientId,
    Username: email,
    ConfirmationCode: otp,
    SecretHash: secretHash,
  };

  cognito.confirmSignUp(params, (err, data) => {
    if (err) {
      console.error("❌ OTP verification error:", err);
      return res.status(400).json({ error: err.message });
    }
    res.status(200).json({ message: "OTP verified successfully", data });
  });
});

// ✅ Sign-In
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

  const secretHash = calculateSecretHash(email, clientId, clientSecret);
  const params = {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: clientId,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
      SECRET_HASH: secretHash,
    },
  };

  cognito.initiateAuth(params, (err, data) => {
    if (err) {
      console.error("❌ Sign-in error:", err);
      return res.status(401).json({ error: "Invalid credentials" });
    }
    res.status(200).json(data);
  });
});

// ✅ Forgot Password (send OTP)
app.post("/forgot-password", async (req, res) => {
  const { userName } = req.body;
  const secretHash = calculateSecretHash(userName, clientId, clientSecret);

  const params = {
    ClientId: clientId,
    Username: userName,
    SecretHash: secretHash,
  };

  cognito.forgotPassword(params, (err, data) => {
    if (err) {
      console.error("❌ Forgot password error:", err);
      return res.status(400).json({ error: err.message });
    }
    res.status(200).json({ message: "Password reset code sent", data });
  });
});

// ✅ Reset Password
app.post("/reset-password", async (req, res) => {
  const { userName, verificationCode, newPassword } = req.body;
  const secretHash = calculateSecretHash(userName, clientId, clientSecret);

  const params = {
    ClientId: clientId,
    Username: userName,
    ConfirmationCode: verificationCode,
    Password: newPassword,
    SecretHash: secretHash,
  };

  cognito.confirmForgotPassword(params, (err, data) => {
    if (err) {
      console.error("❌ Reset password error:", err);
      return res.status(400).json({ error: err.message });
    }
    res.status(200).json({ message: "Password reset successfully", data });
  });
});

// ✅ Start Server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
