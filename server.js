const express = require("express");
const AWS = require("aws-sdk");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const cors = require("cors"); 

require("dotenv").config();

const app = express();
const port = 3000;

// Configure AWS Cognito
AWS.config.update({
  region: process.env.AWS_COGNITO_REGION, // Replace with your region
});

const cognito = new AWS.CognitoIdentityServiceProvider();
const clientId = process.env.AWS_COGNITO_CLIENT_ID; // Replace with your App Client ID
const clientSecret = process.env.AWS_COGNITO_CLIENT_SECRET; // Replace with your actual client secret

console.log("CREDI",cognito,clientId,clientSecret);
app.use(cors()); 
app.use(bodyParser.json());

// Helper function to calculate SECRET_HASH
function calculateSecretHash(username, clientId, clientSecret) {
  const message = username + clientId;
  const hmac = crypto.createHmac("sha256", clientSecret);
  hmac.update(message);
  return hmac.digest("base64");
}

// Google Sign-In endpoint
app.post('/google-signin', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'No token provided' });
  }

  try {
    // Verify the Google token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID, // Specify the CLIENT_ID of the app
    });

    const payload = ticket.getPayload();
    console.log('Google Payload:', payload);

    // You can now authenticate or create a user based on the payload information
    // For example, you can create a new user or issue a session token here

    return res.status(200).json({ message: 'Google sign-in successful', user: payload });
  } catch (error) {
    console.error('Google sign-in error:', error);
    return res.status(400).json({ error: 'Google sign-in verification failed' });
  }
});


// Route to authenticate user (Sign-In)
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;  // Retrieve email and password from the request body

  // Check if email or password is missing
  if (!email || !password) {
    return res.status(400).send({ error: "Email and password are required." });
  }

  // Calculate the SECRET_HASH if the app client uses a client secret
  const secretHash = calculateSecretHash(email, clientId, clientSecret);

  const params = {
    AuthFlow: "USER_PASSWORD_AUTH",  // Use USER_PASSWORD_AUTH flow for email/password
    ClientId: clientId,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
      SECRET_HASH: secretHash,  // Include the SECRET_HASH in the AuthParameters
    },
  };

  cognito.initiateAuth(params, (err, data) => {
    if (err) {
      console.log("Sign-in error:", err);
      res.status(400).send({ error: "Error signing in" });
    } else {
      res.status(200).send(data);
    }
  });
});


// Route to sign up a new user
app.post("/signup", async (req, res) => {
  const { phoneNumber, email, password } = req.body;
  // Calculate the SECRET_HASH
  const secretHash = calculateSecretHash(email, clientId, clientSecret);

  const params = {
    ClientId: clientId,  // Your App Client ID
    Username: email,     // Use the email as the username
    Password: password,  // User password
    UserAttributes: [
      {
        Name: "email",   // Store email as an attribute
        Value: email,
        
      },{
        Name: "phone_number",   // Store email as an attribute
        Value: phoneNumber,
      }
    ],
    SecretHash: secretHash,  // Include SECRET_HASH in the request
  };

  cognito.signUp(params, (err, data) => {
    if (err) {
      console.log("Sign-up error:", err);
      res.status(400).send({ error: "Error signing up" });
    } else {
      res.status(200).send({ message: "Sign-up successful", data });
    }
  });
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  // Calculate the SECRET_HASH
  const secretHash = calculateSecretHash(email, clientId, clientSecret);

  const params = {
    ClientId: clientId,  // Your App Client ID
    Username: email,  // The username (email or phone number)
    ConfirmationCode: otp,  // The OTP sent to the user
    SecretHash: secretHash,  // Include SECRET_HASH in the request
  };

  cognito.confirmSignUp(params, (err, data) => {
    if (err) {
      console.log("OTP verification error:", err);
      res.status(400).send({ error: "Error verifying OTP" });
    } else {
      res.status(200).send({
        message: "OTP verified successfully.",
        data,
      });
    }
  });
});

// Route to initiate password reset (forgot password)
app.post("/forgot-password", async (req, res) => {
  const { userName } = req.body;  // The username (email or phone number) for the user requesting password reset

  // Calculate the SECRET_HASH
  const secretHash = calculateSecretHash(userName, clientId, clientSecret);

  const params = {
    ClientId: clientId,  // Your App Client ID
    Username: userName,  // The email or phone number of the user
    SecretHash: secretHash,  // Include SECRET_HASH in the request
  };

  cognito.forgotPassword(params, (err, data) => {
    if (err) {
      console.log("Forgot password error:", err);
      res.status(400).send({ error: "Error initiating password reset" });
    } else {
      res.status(200).send({
        message: "Password reset code sent successfully.",
        data,
      });
    }
  });
});

// Route to reset the user's password
app.post("/reset-password", async (req, res) => {
  const { userName, verificationCode, newPassword } = req.body;

  // Calculate the SECRET_HASH
  const secretHash = calculateSecretHash(userName, clientId, clientSecret);

  const params = {
    ClientId: clientId,  // Your App Client ID
    Username: userName,  // The username (email or phone number)
    ConfirmationCode: verificationCode,  // The verification code sent to the user
    Password: newPassword,  // The new password the user wants to set
    SecretHash: secretHash,  // Include SECRET_HASH in the request
  };

  cognito.confirmForgotPassword(params, (err, data) => {
    if (err) {
      console.log("Reset password error:", err);
      res.status(400).send({ error: "Error resetting password" });
    } else {
      res.status(200).send({
        message: "Password reset successfully.",
        data,
      });
    }
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});