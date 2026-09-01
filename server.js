const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_VERIFY_SERVICE_SID = process.env.TWILIO_VERIFY_SERVICE_SID;
const ADMIN_KEY = process.env.ADMIN_KEY || "";

/*
  14 FITNESS GYM
  Backend:
  - SMS OTP with Twilio Verify
  - OTP verification
  - Returning-member recognition
  - Membership registration
  - Basic rate limiting
  - Signed verification token

  IMPORTANT:
  Never put Twilio credentials in index.html or order.html.
*/

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.static(__dirname));

/* =========================================================
   CONFIG
========================================================= */

const GYM_NAME = "14 FITNESS GYM";

const PLAN_INFO = {
  "1400": {
    name: "1 MONTH + FREE ADMISSION",
    months: 1,
    amount: 1400
  },

  "7560": {
    name: "6 MONTHS + FREE ADMISSION",
    months: 6,
    amount: 7560
  },

  "14280": {
    name: "1 YEAR + FREE ADMISSION",
    months: 12,
    amount: 14280
  },

  "700": {
    name: "1 MONTH RENEWAL",
    months: 1,
    amount: 700
  }
};

/*
  In-memory member store for the current server process.

  Later, when we connect your Telegram/payment backend or
  a database, this can be replaced with permanent storage.
*/
const members = new Map();

/*
  OTP request rate limiting.

  Twilio Verify itself also provides protection, but we keep
  a small server-side cooldown so a visitor cannot repeatedly
  hammer the endpoint.
*/
const otpRequests = new Map();

const OTP_COOLDOWN_MS = 60 * 1000;
const OTP_WINDOW_MS = 10 * 60 * 1000;
const MAX_OTP_REQUESTS_PER_WINDOW = 5;

/* =========================================================
   HELPERS
========================================================= */

function normalizeIndianPhone(value) {
  let phone = String(value || "").replace(/\D/g, "");

  if (phone.startsWith("91") && phone.length === 12) {
    phone = phone.slice(2);
  }

  if (phone.length > 10) {
    phone = phone.slice(-10);
  }

  if (!/^[6-9][0-9]{9}$/.test(phone)) {
    return null;
  }

  return "+91" + phone;
}

function cleanName(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function validName(name) {
  return /^[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]{1,59}$/.test(name);
}

function validAge(age) {
  const n = Number(age);
  return Number.isInteger(n) && n >= 12 && n <= 90;
}

function getPlan(plan) {
  return PLAN_INFO[String(plan)] || null;
}

function generateMemberId() {
  return "14F-" + Date.now().toString().slice(-8);
}

/*
  We create a short-lived signed verification token after
  successful OTP verification.

  The token proves:
  - which phone was verified
  - when it was verified

  It is NOT an OTP.
*/

const VERIFY_TOKEN_SECRET =
  process.env.VERIFY_TOKEN_SECRET ||
  "CHANGE_THIS_SECRET_IN_RENDER_ENV";

function createVerificationToken(phone) {
  const timestamp = Date.now().toString();

  const payload = `${phone}.${timestamp}`;

  const signature = crypto
    .createHmac("sha256", VERIFY_TOKEN_SECRET)
    .update(payload)
    .digest("hex");

  return Buffer.from(
    JSON.stringify({
      phone,
      timestamp,
      signature
    })
  ).toString("base64url");
}

function verifyVerificationToken(token, phone) {
  try {
    if (!token || !phone) return false;

    const decoded = JSON.parse(
      Buffer.from(token, "base64url").toString("utf8")
    );

    if (!decoded.phone || !decoded.timestamp || !decoded.signature) {
      return false;
    }

    if (decoded.phone !== phone) {
      return false;
    }

    const age = Date.now() - Number(decoded.timestamp);

    /*
      Verification token valid for 30 minutes.
    */
    if (!Number.isFinite(age) || age < 0 || age > 30 * 60 * 1000) {
      return false;
    }

    const payload = `${decoded.phone}.${decoded.timestamp}`;

    const expectedSignature = crypto
      .createHmac("sha256", VERIFY_TOKEN_SECRET)
      .update(payload)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(decoded.signature),
      Buffer.from(expectedSignature)
    );
  } catch (error) {
    return false;
  }
}

/* =========================================================
   TWILIO VERIFY
========================================================= */

function twilioConfigured() {
  return Boolean(
    TWILIO_ACCOUNT_SID &&
      TWILIO_AUTH_TOKEN &&
      TWILIO_VERIFY_SERVICE_SID
  );
}

function twilioBaseUrl() {
  return `https://verify.twilio.com/v2/Services/${encodeURIComponent(
    TWILIO_VERIFY_SERVICE_SID
  )}`;
}

function twilioAuthHeader() {
  const credentials = Buffer.from(
    `${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`
  ).toString("base64");

  return `Basic ${credentials}`;
}

async function sendTwilioVerification(phone) {
  const body = new URLSearchParams();

  body.set("To", phone);
  body.set("Channel", "sms");

  const response = await fetch(
    `${twilioBaseUrl()}/Verifications`,
    {
      method: "POST",
      headers: {
        Authorization: twilioAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      data?.message ||
      data?.detail ||
      "Twilio could not send the verification SMS.";

    const error = new Error(message);
    error.status = response.status;
    error.twilio = data;

    throw error;
  }

  return data;
}

async function checkTwilioVerification(phone, code) {
  const body = new URLSearchParams();

  body.set("To", phone);
  body.set("Code", code);

  const response = await fetch(
    `${twilioBaseUrl()}/VerificationCheck`,
    {
      method: "POST",
      headers: {
        Authorization: twilioAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      data?.message ||
      data?.detail ||
      "Twilio could not verify the OTP.";

    const error = new Error(message);
    error.status = response.status;
    error.twilio = data;

    throw error;
  }

  return data;
}

/* =========================================================
   RATE LIMITING
========================================================= */

function canSendOTP(phone) {
  const now = Date.now();

  const existing = otpRequests.get(phone);

  if (!existing) {
    otpRequests.set(phone, {
      firstRequest: now,
      lastRequest: now,
      count: 1
    });

    return {
      allowed: true,
      waitSeconds: 0
    };
  }

  if (now - existing.firstRequest > OTP_WINDOW_MS) {
    otpRequests.set(phone, {
      firstRequest: now,
      lastRequest: now,
      count: 1
    });

    return {
      allowed: true,
      waitSeconds: 0
    };
  }

  const secondsSinceLast =
    (now - existing.lastRequest) / 1000;

  if (secondsSinceLast < OTP_COOLDOWN_MS / 1000) {
    return {
      allowed: false,
      waitSeconds: Math.ceil(
        OTP_COOLDOWN_MS / 1000 - secondsSinceLast
      )
    };
  }

  if (existing.count >= MAX_OTP_REQUESTS_PER_WINDOW) {
    return {
      allowed: false,
      waitSeconds: Math.ceil(
        (OTP_WINDOW_MS -
          (now - existing.firstRequest)) /
          1000
      )
    };
  }

  existing.lastRequest = now;
  existing.count += 1;

  return {
    allowed: true,
    waitSeconds: 0
  };
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: GYM_NAME,
    time: new Date().toISOString(),
    smsConfigured: twilioConfigured()
  });
});

/* =========================================================
   SEND OTP
========================================================= */

app.post("/api/send-otp", async (req, res) => {
  try {
    const name = cleanName(req.body?.name);
    const phone = normalizeIndianPhone(req.body?.phone);

    if (!name || !validName(name)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid full name."
      });
    }

    if (!phone) {
      return res.status(400).json({
        success: false,
        message:
          "Please enter a valid 10-digit Indian mobile number."
      });
    }

    if (!twilioConfigured()) {
      console.error(
        "OTP ERROR: Twilio environment variables are missing."
      );

      return res.status(503).json({
        success: false,
        message:
          "SMS service is not configured on the server yet."
      });
    }

    const rate = canSendOTP(phone);

    if (!rate.allowed) {
      return res.status(429).json({
        success: false,
        message:
          `Please wait ${rate.waitSeconds} seconds before requesting another OTP.`,
        retryAfter: rate.waitSeconds
      });
    }

    const result = await sendTwilioVerification(phone);

    console.log(
      `[OTP] SMS verification started for ${phone}. Status: ${result.status || "unknown"}`
    );

    return res.json({
      success: true,
      message: "OTP sent successfully."
    });
  } catch (error) {
    console.error(
      "[OTP SEND ERROR]",
      error?.message || error
    );

    return res.status(502).json({
      success: false,
      message:
        "We could not send the OTP right now. Please try again."
    });
  }
});

/* =========================================================
   VERIFY OTP
========================================================= */

app.post("/api/verify-otp", async (req, res) => {
  try {
    const name = cleanName(req.body?.name);
    const phone = normalizeIndianPhone(req.body?.phone);
    const otp = String(req.body?.otp || "")
      .replace(/\D/g, "")
      .slice(0, 6);

    if (!name || !validName(name)) {
      return res.status(400).json({
        success: false,
        message: "Invalid name."
      });
    }

    if (!phone) {
      return res.status(400).json({
        success: false,
        message: "Invalid mobile number."
      });
    }

    if (!/^\d{4,6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "Please enter the OTP received by SMS."
      });
    }

    if (!twilioConfigured()) {
      return res.status(503).json({
        success: false,
        message:
          "SMS verification is not configured on the server."
      });
    }

    const result = await checkTwilioVerification(
      phone,
      otp
    );

    const approved =
      result?.status === "approved";

    if (!approved) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid or expired OTP. Please request a new OTP."
      });
    }

    /*
      Look for an ACTIVE member using the verified phone.
    */
    const existingMember = members.get(phone) || null;

    const verificationToken =
      createVerificationToken(phone);

    console.log(
      `[OTP VERIFIED] ${phone} | Existing member: ${Boolean(
        existingMember
      )}`
    );

    return res.json({
      success: true,
      message: "Mobile number verified successfully.",

      /*
        Frontend already expects these fields.
      */
      isExistingMember: Boolean(existingMember),
      member: existingMember,

      /*
        order.html can use this later when submitting
        the membership form.
      */
      verificationToken
    });
  } catch (error) {
    console.error(
      "[OTP VERIFY ERROR]",
      error?.message || error
    );

    return res.status(502).json({
      success: false,
      message:
        "OTP verification could not be completed. Please try again."
    });
  }
});

/* =========================================================
   MEMBERSHIP REGISTRATION
========================================================= */

app.post("/api/membership", (req, res) => {
  try {
    const {
      name,
      phone: rawPhone,
      age,
      gender,
      goal,
      plan,
      amount,
      verificationToken
    } = req.body || {};

    const cleanFullName = cleanName(name);
    const phone = normalizeIndianPhone(rawPhone);
    const selectedPlan = getPlan(plan);

    if (!cleanFullName || !validName(cleanFullName)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid full name."
      });
    }

    if (!phone) {
      return res.status(400).json({
        ok: false,
        error: "Invalid mobile number."
      });
    }

    if (!validAge(age)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid age."
      });
    }

    if (!gender || !goal) {
      return res.status(400).json({
        ok: false,
        error:
          "Gender and fitness goal are required."
      });
    }

    if (!selectedPlan) {
      return res.status(400).json({
        ok: false,
        error: "Invalid membership plan."
      });
    }

    if (Number(amount) !== selectedPlan.amount) {
      return res.status(400).json({
        ok: false,
        error:
          "Membership amount does not match the selected plan."
      });
    }

    /*
      The membership form should only be submitted after
      mobile verification.
    */
    if (
      !verificationToken ||
      !verifyVerificationToken(
        verificationToken,
        phone
      )
    ) {
      return res.status(401).json({
        ok: false,
        error:
          "Mobile verification required before membership registration."
      });
    }

    const memberId = generateMemberId();

    const member = {
      memberId,
      name: cleanFullName,
      phone,
      age: Number(age),
      gender: String(gender),
      goal: String(goal),
      plan: String(plan),
      amount: selectedPlan.amount,

      /*
        New registrations are NOT automatically ACTIVE.
        Payment still needs to be verified.
      */
      status: "PAYMENT_PENDING_VERIFICATION",

      createdAt: new Date().toISOString()
    };

    /*
      Store the member as pending.

      IMPORTANT:
      We do not treat pending members as existing ACTIVE
      members in /api/verify-otp.
    */
    members.set(phone, member);

    console.log(
      `[MEMBERSHIP] ${memberId} | ${phone} | ${selectedPlan.name}`
    );

    return res.status(201).json({
      ok: true,
      memberId,
      status: member.status,
      message:
        "Registration received. Verify payment before activating membership."
    });
  } catch (error) {
    console.error(
      "[MEMBERSHIP ERROR]",
      error?.message || error
    );

    return res.status(500).json({
      ok: false,
      error: "Could not process membership registration."
    });
  }
});

/* =========================================================
   ADMIN ACTIVATION
========================================================= */

/*
  This endpoint is intentionally protected.

  Later, when your payment verification/Telegram system
  confirms payment, it can activate the member.

  POST:
  /api/admin/activate-member

  Headers:
  x-admin-key: YOUR_ADMIN_KEY

  Body:
  {
    "phone": "+919876543210"
  }
*/

app.post("/api/admin/activate-member", (req, res) => {
  try {
    if (!ADMIN_KEY) {
      return res.status(503).json({
        ok: false,
        error:
          "ADMIN_KEY is not configured."
      });
    }

    const providedKey =
      req.headers["x-admin-key"];

    if (
      !providedKey ||
      providedKey !== ADMIN_KEY
    ) {
      return res.status(403).json({
        ok: false,
        error: "Unauthorized."
      });
    }

    const phone = normalizeIndianPhone(
      req.body?.phone
    );

    if (!phone) {
      return res.status(400).json({
        ok: false,
        error: "Invalid mobile number."
      });
    }

    const member = members.get(phone);

    if (!member) {
      return res.status(404).json({
        ok: false,
        error: "Member not found."
      });
    }

    member.status = "ACTIVE";
    member.activatedAt =
      new Date().toISOString();

    members.set(phone, member);

    return res.json({
      ok: true,
      message: "Membership activated.",
      member
    });
  } catch (error) {
    console.error(
      "[ACTIVATE ERROR]",
      error?.message || error
    );

    return res.status(500).json({
      ok: false,
      error: "Could not activate member."
    });
  }
});

/* =========================================================
   ADMIN MEMBER LOOKUP
========================================================= */

app.get("/api/admin/member", (req, res) => {
  try {
    if (!ADMIN_KEY) {
      return res.status(503).json({
        ok: false,
        error:
          "ADMIN_KEY is not configured."
      });
    }

    const providedKey =
      req.headers["x-admin-key"];

    if (
      !providedKey ||
      providedKey !== ADMIN_KEY
    ) {
      return res.status(403).json({
        ok: false,
        error: "Unauthorized."
      });
    }

    const phone = normalizeIndianPhone(
      req.query.phone
    );

    if (!phone) {
      return res.status(400).json({
        ok: false,
        error: "Invalid mobile number."
      });
    }

    const member = members.get(phone) || null;

    return res.json({
      ok: true,
      found: Boolean(member),
      member
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "Could not lookup member."
    });
  }
});

/* =========================================================
   CLEAN OLD RATE LIMIT ENTRIES
========================================================= */

setInterval(() => {
  const now = Date.now();

  for (const [phone, data] of otpRequests.entries()) {
    if (
      now - data.firstRequest >
      OTP_WINDOW_MS
    ) {
      otpRequests.delete(phone);
    }
  }
}, 5 * 60 * 1000);

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get(/.*/, (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, () => {
  console.log(
    `${GYM_NAME} server running on port ${PORT}`
  );

  console.log(
    `SMS/OTP configured: ${twilioConfigured() ? "YES" : "NO"}`
  );

  if (!VERIFY_TOKEN_SECRET) {
    console.warn(
      "WARNING: VERIFY_TOKEN_SECRET is missing."
    );
  }
});
