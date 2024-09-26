// Areeb Ashraf - aa2672
const express = require("express");
const forge = require("node-forge");
const jwt = require("jsonwebtoken");
const base64url = require("base64url");

// Initialize the Express app
const app = express();
const port = 8080; // Define the port where the server will listen

// Function to generate RSA key pairs (private and public keys)
function createRsaKeys() {
  const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  return keyPair;
}

// Generate key pairs
const activeKeyPair = createRsaKeys();
const expiredKeyPair = createRsaKeys();

// Helper function to properly convert large integers to Base64URL-encoded strings
function integerToBase64(value) {
  const byteBuffer = Buffer.from(value.toString(16), "hex");
  return base64url(byteBuffer);
}

// Function to get the PEM-formatted private key from the key pair
function getPemPrivateKey(keyPair) {
  return forge.pki.privateKeyToPem(keyPair.privateKey);
}

// Convert private keys to PEM format
const activePrivateKeyPem = getPemPrivateKey(activeKeyPair);
const expiredPrivateKeyPem = getPemPrivateKey(expiredKeyPair);

// Middleware for unsupported HTTP methods
app.use((req, res, next) => {
  if (["PUT", "PATCH", "DELETE", "HEAD"].includes(req.method)) {
    return res.status(405).send("Method Not Allowed");
  }
  next();
});

// POST /auth endpoint for JWT creation
app.post("/auth", (req, res) => {
  const isTokenExpired = req.query.expired;

  const jwtHeader = {
    kid: isTokenExpired ? "expiredKID" : "activeKID",
  };

  const tokenPayload = {
    user: "username",
    exp: Math.floor(Date.now() / 1000) + (isTokenExpired ? -3600 : 3600), // Set expiration
  };

  const privateKeyToUse = isTokenExpired
    ? expiredPrivateKeyPem
    : activePrivateKeyPem;

  const signedJwt = jwt.sign(tokenPayload, privateKeyToUse, {
    algorithm: "RS256",
    header: jwtHeader,
  });

  res.status(200).send(signedJwt);
});

// GET /.well-known/jwks.json endpoint for JWKS
app.get("/.well-known/jwks.json", (req, res) => {
  const jwks = {
    keys: [
      {
        alg: "RS256",
        kty: "RSA",
        use: "sig",
        kid: "activeKID",
        n: integerToBase64(activeKeyPair.publicKey.n), // Ensure proper Base64URL encoding
        e: "AQAB", // Correct exponent encoding for 65537
      },
    ],
  };

  res.status(200).json(jwks);
});

// Handle unsupported routes
app.all("*", (req, res) => {
  return res.status(405).send("Method Not Allowed");
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
