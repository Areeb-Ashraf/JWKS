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
  // Generate RSA key pair with 2048 bits and a public exponent of 65537 (0x10001)
  const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  return keyPair;
}

// Generate two key pairs: one for the active key and another for an expired key
const activeKeyPair = createRsaKeys();
const expiredKeyPair = createRsaKeys();

// Helper function to convert large integers to Base64URL-encoded strings
function integerToBase64(value) {
  // Convert the integer to a hexadecimal string
  const hexValue = value.toString(16);
  // Convert the hex string to a Buffer and then to Base64URL
  const byteBuffer = Buffer.from(hexValue, "hex");
  return base64url(byteBuffer); // Return Base64URL-encoded result
}

// Function to get the PEM-formatted private key from the key pair
function getPemPrivateKey(keyPair) {
  return forge.pki.privateKeyToPem(keyPair.privateKey);
}

// Convert the private keys to PEM format
const activePrivateKeyPem = getPemPrivateKey(activeKeyPair);
const expiredPrivateKeyPem = getPemPrivateKey(expiredKeyPair);

// Middleware to handle unsupported HTTP methods (PUT, PATCH, DELETE, HEAD)
app.use((req, res, next) => {
  // If the method is unsupported, respond with a 405 status
  if (["PUT", "PATCH", "DELETE", "HEAD"].includes(req.method)) {
    res.status(405).send("Method Not Allowed");
  } else {
    next(); // Otherwise, pass the request to the next middleware
  }
});

// POST /auth endpoint for JWT creation
app.post("/auth", (req, res) => {
  const isTokenExpired = req.query.expired; // Check if the request is asking for an expired token

  // Define JWT header with key ID (kid) indicating which key was used to sign the token
  const jwtHeader = {
    kid: isTokenExpired ? "expiredKID" : "activeKID",
  };

  // Define the token payload (claims), including the user and expiration time
  const tokenPayload = {
    user: "username",
    exp: Math.floor(Date.now() / 1000) + (isTokenExpired ? -3600 : 3600), // Expiration set based on query
  };

  // Select the appropriate private key depending on whether the token is expired
  const privateKeyToUse = isTokenExpired
    ? expiredPrivateKeyPem
    : activePrivateKeyPem;

  // Sign the token using the RS256 algorithm and send it in the response
  const signedJwt = jwt.sign(tokenPayload, privateKeyToUse, {
    algorithm: "RS256",
    header: jwtHeader,
  });

  res.status(200).send(signedJwt); // Send the signed JWT token as the response
});

// GET /.well-known/jwks.json endpoint for providing JWKS (JSON Web Key Set)
app.get("/.well-known/jwks.json", (req, res) => {
  // Construct the JWKS response, containing the public part of the RSA key
  const jwks = {
    keys: [
      {
        alg: "RS256",
        kty: "RSA",
        use: "sig",
        kid: "activeKID",
        n: integerToBase64(activeKeyPair.publicKey.n),
        e: integerToBase64(activeKeyPair.publicKey.e),
      },
    ],
  };

  // Send the JWKS response as a JSON object
  res.status(200).json(jwks);
});

// Handle all other routes by responding with 405 (Method Not Allowed)
app.all("*", (req, res) => {
  res.status(405).send("Method Not Allowed");
});

// Start the server on the specified port
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
