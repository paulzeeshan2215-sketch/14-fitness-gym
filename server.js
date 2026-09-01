[01-09-2026 11:53 AM] Paul Zeeshan: const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 10000;
const GYM_NAME = "14 FITNESS GYM";

/*
=========================================================
ENVIRONMENT VARIABLES
=========================================================

Render में ये variables रखें:

TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN
TWILIO_VERIFY_SERVICE_SID
VERIFY_TOKEN_SECRET
ADMIN_KEY

IMPORTANT:
Twilio Verify खुद OTP SMS का message/template संभालेगा.
हम कोई custom SMS body नहीं भेजेंगे.
*/

const TWILIO_ACCOUNT_SID =
  process.env.TWILIO_ACCOUNT_SID || "";

const TWILIO_AUTH_TOKEN =
  process.env.TWILIO_AUTH_TOKEN || "";

const TWILIO_VERIFY_SERVICE_SID =
  process.env.TWILIO_VERIFY_SERVICE_SID || "";

const VERIFY_TOKEN_SECRET =
  process.env.VERIFY_TOKEN_SECRET || "";

const ADMIN_KEY =
  process.env.ADMIN_KEY || "";


/*
=========================================================
MIDDLEWARE
=========================================================
*/

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb"
  })
);

app.use(express.static(__dirname));


/*
=========================================================
PLANS
=========================================================
*/

const NEW_PLANS = {
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
  }
};


const RENEWAL_PLANS = {
  "700": {
    name: "1 MONTH RENEWAL",
    months: 1,
    amount: 700
  },

  "1400": {
    name: "2 MONTHS RENEWAL",
    months: 2,
    amount: 1400
  },

  "2000": {
    name: "3 MONTHS RENEWAL",
    months: 3,
    amount: 2000
  },

  "4000": {
    name: "4 MONTHS RENEWAL",
    months: 4,
    amount: 4000
  },

  "5000": {
    name: "5 MONTHS RENEWAL",
    months: 5,
    amount: 5000
  }
};


/*
=========================================================
MEMBER STORAGE
=========================================================
*/

const MEMBERS_FILE =
  path.join(__dirname, "members.json");


function loadMembers() {
  try {
    if (!fs.existsSync(MEMBERS_FILE)) {
      return {};
    }

    const raw =
      fs.readFileSync(
        MEMBERS_FILE,
        "utf8"
      );

    const data =
      JSON.parse(raw);

    if (
      data &&
      typeof data === "object" &&
      !Array.isArray(data)
    ) {
      return data;
    }

    return {};

  } catch (error) {
    console.error(
      "[MEMBERS LOAD ERROR]",
      error.message
    );

    return {};
  }
}


let members = loadMembers();


function saveMembers() {
  try {
    const tempFile =
      MEMBERS_FILE + ".tmp";

    fs.writeFileSync(
      tempFile,
      JSON.stringify(
        members,
        null,
        2
      ),
      "utf8"
    );

    fs.renameSync(
      tempFile,
      MEMBERS_FILE
    );

  } catch (error) {
    console.error(
      "[MEMBERS SAVE ERROR]",
      error.message
    );

    throw error;
  }
}


/*
=========================================================
OTP RATE LIMITING
=========================================================
*/

const otpRequests = new Map();

const OTP_COOLDOWN_MS =
  60 * 1000;

const OTP_WINDOW_MS =
  10 * 60 * 1000;

const MAX_OTP_REQUESTS_PER_WINDOW =
  5;


/*
=========================================================
HELPERS
=========================================================
*/

function normalizeIndianPhone(value) {
  let phone =
    String(value || "")
      .replace(/\D/g, "");

  if (
    phone.startsWith("91") &&
    phone.length === 12
  ) {
    phone =
      phone.slice(2);
  }

  if (phone.length > 10) {
    phone =
      phone.slice(-10);
  }

  if (
    !/^[6-9][0-9]{9}$/.test(phone)
  ) {
    return null;
  }

  return "+91" + phone;
}


function cleanName(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}
[01-09-2026 11:53 AM] Paul Zeeshan: function validName(name) {
  return /^[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]{1,59}$/
    .test(name);
}


function validAge(age) {
  const n =
    Number(age);

  return (
    Number.isInteger(n) &&
    n >= 12 &&
    n <= 90
  );
}


function getNewPlan(plan) {
  return (
    NEW_PLANS[
      String(plan)
    ] || null
  );
}


function getRenewalPlan(plan) {
  return (
    RENEWAL_PLANS[
      String(plan)
    ] || null
  );
}


function generateMemberId() {
  return (
    "14F-" +
    Date.now()
      .toString()
      .slice(-8) +
    "-" +
    crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase()
  );
}


function generateRenewalId() {
  return (
    "REN-" +
    Date.now()
      .toString()
      .slice(-8) +
    "-" +
    crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase()
  );
}


function twilioConfigured() {
  return Boolean(
    TWILIO_ACCOUNT_SID &&
    TWILIO_AUTH_TOKEN &&
    TWILIO_VERIFY_SERVICE_SID
  );
}


/*
=========================================================
VERIFICATION TOKEN
=========================================================

Created only after Twilio confirms the OTP.

Valid for 30 minutes.
*/

function createVerificationToken(phone) {
  if (!VERIFY_TOKEN_SECRET) {
    throw new Error(
      "VERIFY_TOKEN_SECRET is not configured."
    );
  }

  const timestamp =
    Date.now().toString();

  const payload =
    ${phone}.${timestamp};

  const signature =
    crypto
      .createHmac(
        "sha256",
        VERIFY_TOKEN_SECRET
      )
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


function verifyVerificationToken(
  token,
  phone
) {
  try {
    if (
      !token ||
      !phone ||
      !VERIFY_TOKEN_SECRET
    ) {
      return false;
    }

    const decoded =
      JSON.parse(
        Buffer.from(
          token,
          "base64url"
        ).toString("utf8")
      );

    if (
      !decoded.phone ||
      !decoded.timestamp ||
      !decoded.signature
    ) {
      return false;
    }

    if (
      decoded.phone !== phone
    ) {
      return false;
    }

    const timestamp =
      Number(decoded.timestamp);

    if (
      !Number.isFinite(timestamp)
    ) {
      return false;
    }

    const age =
      Date.now() - timestamp;

    if (
      age < 0 ||
      age > 30 * 60 * 1000
    ) {
      return false;
    }

    const payload =
      ${decoded.phone}.${decoded.timestamp};

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          VERIFY_TOKEN_SECRET
        )
        .update(payload)
        .digest("hex");

    const actual =
      Buffer.from(
        String(decoded.signature),
        "utf8"
      );

    const expected =
      Buffer.from(
        expectedSignature,
        "utf8"
      );

    if (
      actual.length !==
      expected.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      actual,
      expected
    );

  } catch (error) {
    return false;
  }
}


/*
=========================================================
TWILIO VERIFY
=========================================================
*/

function twilioBaseUrl() {
  return (
    "https://verify.twilio.com/v2/Services/" +
    encodeURIComponent(
      TWILIO_VERIFY_SERVICE_SID
    )
  );
}


function twilioAuthHeader() {
  const credentials =
    Buffer.from(
      ${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}
    ).toString("base64");

  return Basic ${credentials};
}


/*
=========================================================
SEND OTP
=========================================================

IMPORTANT:
No custom SMS body is sent here.

Twilio Verify creates the verification message.
*/

async function sendTwilioVerification(
  phone
) {
  const body =
    new URLSearchParams();

  body.set(
    "To",
    phone
  );

  body.set(
    "Channel",
    "sms"
  );

  const response =
    await fetch(
      ${twilioBaseUrl()}/Verifications,
      {
        method: "POST",
[01-09-2026 11:53 AM] Paul Zeeshan: headers: {
          Authorization:
            twilioAuthHeader(),

          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  if (!response.ok) {
    const message =
      data?.message ||
      data?.detail ||
      "Twilio could not send the OTP.";

    const error =
      new Error(message);

    error.status =
      response.status;

    error.twilio =
      data;

    throw error;
  }

  return data;
}


/*
=========================================================
VERIFY OTP
=========================================================
*/

async function checkTwilioVerification(
  phone,
  code
) {
  const body =
    new URLSearchParams();

  body.set(
    "To",
    phone
  );

  body.set(
    "Code",
    code
  );

  const response =
    await fetch(
      ${twilioBaseUrl()}/VerificationCheck,
      {
        method: "POST",

        headers: {
          Authorization:
            twilioAuthHeader(),

          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  if (!response.ok) {
    const message =
      data?.message ||
      data?.detail ||
      "Twilio could not verify the OTP.";

    const error =
      new Error(message);

    error.status =
      response.status;

    error.twilio =
      data;

    throw error;
  }

  return data;
}


/*
=========================================================
OTP RATE LIMIT
=========================================================
*/

function canSendOTP(phone) {
  const now =
    Date.now();

  const existing =
    otpRequests.get(phone);

  if (!existing) {
    otpRequests.set(
      phone,
      {
        firstRequest: now,
        lastRequest: now,
        count: 1
      }
    );

    return {
      allowed: true,
      waitSeconds: 0
    };
  }

  if (
    now -
    existing.firstRequest >
    OTP_WINDOW_MS
  ) {
    otpRequests.set(
      phone,
      {
        firstRequest: now,
        lastRequest: now,
        count: 1
      }
    );

    return {
      allowed: true,
      waitSeconds: 0
    };
  }

  const secondsSinceLast =
    (
      now -
      existing.lastRequest
    ) / 1000;

  if (
    secondsSinceLast <
    OTP_COOLDOWN_MS / 1000
  ) {
    return {
      allowed: false,

      waitSeconds:
        Math.ceil(
          OTP_COOLDOWN_MS / 1000 -
          secondsSinceLast
        )
    };
  }

  if (
    existing.count >=
    MAX_OTP_REQUESTS_PER_WINDOW
  ) {
    return {
      allowed: false,

      waitSeconds:
        Math.ceil(
          (
            OTP_WINDOW_MS -
            (
              now -
              existing.firstRequest
            )
          ) / 1000
        )
    };
  }

  existing.lastRequest =
    now;

  existing.count += 1;

  return {
    allowed: true,
    waitSeconds: 0
  };
}


/*
=========================================================
HEALTH CHECK
=========================================================
*/

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,

      service:
        GYM_NAME,

      time:
        new Date().toISOString(),

      smsConfigured:
        twilioConfigured(),

      verificationSecretConfigured:
        Boolean(
          VERIFY_TOKEN_SECRET
        ),

      adminConfigured:
        Boolean(
          ADMIN_KEY
        ),

      memberStorage:
        "members.json",

      memberCount:
        Object.keys(members).length
    });
  }
);


/*
=========================================================
SEND OTP
=========================================================
*/

app.post(
  "/api/send-otp",
  async (req, res) => {
    try {
      const name =
        cleanName(
          req.body?.name
        );

      const phone =
        normalizeIndianPhone(
          req.body?.phone
        );
[01-09-2026 11:53 AM] Paul Zeeshan: if (
        !name ||
        !validName(name)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Please enter a valid full name."
          });
      }

      if (!phone) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Please enter a valid 10-digit Indian mobile number."
          });
      }

      if (!twilioConfigured()) {
        console.error(
          "[OTP] Twilio configuration missing."
        );

        return res
          .status(503)
          .json({
            success: false,
            message:
              "SMS service is not configured on the server yet."
          });
      }

      if (!VERIFY_TOKEN_SECRET) {
        console.error(
          "[OTP] VERIFY_TOKEN_SECRET missing."
        );

        return res
          .status(503)
          .json({
            success: false,
            message:
              "Verification security is not configured on the server."
          });
      }

      const rate =
        canSendOTP(phone);

      if (!rate.allowed) {
        return res
          .status(429)
          .json({
            success: false,

            message:
              Please wait ${rate.waitSeconds} seconds before requesting another OTP.,

            retryAfter:
              rate.waitSeconds
          });
      }

      const result =
        await sendTwilioVerification(
          phone
        );

      console.log(
        [OTP SENT] ${phone} | ${result.status || "unknown"}
      );

      return res.json({
        success: true,

        message:
          "OTP sent successfully."
      });

    } catch (error) {
      console.error(
        "[TWILIO ERROR]",
        {
          message:
            error?.message,
          status:
            error?.status,
          code:
            error?.twilio?.code,
          moreInfo:
            error?.twilio?.more_info
        }
      );

      /*
      Do not send Twilio credentials/details
      to the frontend.
      */

      return res
        .status(502)
        .json({
          success: false,

          message:
            "We could not send the OTP right now. Please try again."
        });
    }
  }
);


/*
=========================================================
VERIFY OTP
=========================================================
*/

app.post(
  "/api/verify-otp",
  async (req, res) => {
    try {
      const name =
        cleanName(
          req.body?.name
        );

      const phone =
        normalizeIndianPhone(
          req.body?.phone
        );

      const otp =
        String(
          req.body?.otp || ""
        )
          .replace(/\D/g, "")
          .slice(0, 6);

      if (
        !name ||
        !validName(name)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Invalid name."
          });
      }

      if (!phone) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Invalid mobile number."
          });
      }

      if (
        !/^\d{4,6}$/.test(otp)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Please enter the OTP received by SMS."
          });
      }

      if (!twilioConfigured()) {
        return res
          .status(503)
          .json({
            success: false,
            message:
              "SMS verification is not configured on the server."
          });
      }

      if (!VERIFY_TOKEN_SECRET) {
        return res
          .status(503)
          .json({
            success: false,
            message:
              "Verification security is not configured on the server."
          });
      }

      const result =
        await checkTwilioVerification(
          phone,
          otp
        );
[01-09-2026 11:53 AM] Paul Zeeshan: if (
        result?.status !==
        "approved"
      ) {
        return res
          .status(401)
          .json({
            success: false,
            message:
              "Invalid or expired OTP. Please request a new OTP."
          });
      }

      /*
      =====================================================
      EXISTING MEMBER CHECK
      =====================================================
      */

      const existingMember =
        members[phone] || null;

      const isExistingMember =
        Boolean(
          existingMember &&
          existingMember.status ===
            "ACTIVE"
        );

      /*
      Create token only after
      Twilio successfully approves OTP.
      */

      const verificationToken =
        createVerificationToken(
          phone
        );

      console.log(
        [OTP VERIFIED] ${phone} | Existing active member: ${isExistingMember}
      );

      const safeMember =
        existingMember
          ? {
              memberId:
                existingMember.memberId,

              name:
                existingMember.name,

              plan:
                existingMember.plan,

              planName:
                existingMember.planName,

              status:
                existingMember.status,

              expiresAt:
                existingMember.expiresAt ||
                null,

              createdAt:
                existingMember.createdAt
            }
          : null;

      return res.json({
        success: true,

        message:
          "Mobile number verified successfully.",

        isExistingMember,

        member:
          safeMember,

        verificationToken
      });

    } catch (error) {
      console.error(
        "[OTP VERIFY ERROR]",
        {
          message:
            error?.message,
          status:
            error?.status,
          code:
            error?.twilio?.code
        }
      );

      return res
        .status(502)
        .json({
          success: false,

          message:
            "OTP verification could not be completed. Please try again."
        });
    }
  }
);


/*
=========================================================
NEW MEMBERSHIP REGISTRATION
=========================================================
*/

app.post(
  "/api/membership",
  (req, res) => {
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

      const cleanFullName =
        cleanName(name);

      const phone =
        normalizeIndianPhone(
          rawPhone
        );

      const selectedPlan =
        getNewPlan(plan);

      if (
        !cleanFullName ||
        !validName(cleanFullName)
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid full name."
          });
      }

      if (!phone) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid mobile number."
          });
      }

      if (!validAge(age)) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid age."
          });
      }

      if (
        !gender ||
        !goal
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Gender and fitness goal are required."
          });
      }

      if (!selectedPlan) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid membership plan."
          });
      }

      if (
        Number(am
