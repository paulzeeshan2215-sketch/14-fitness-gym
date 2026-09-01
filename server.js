const express = require("express");
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

Required on Render:

TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN
TWILIO_VERIFY_SERVICE_SID
VERIFY_TOKEN_SECRET
ADMIN_KEY

Never put these secrets inside index.html.
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

Instead of keeping members only in RAM, we save them into
members.json so a Render restart does not immediately erase
the member list.

The file is automatically created if it doesn't exist.
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
      typeof data === "object"
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

    fs.writeFileSync(
      MEMBERS_FILE,
      JSON.stringify(
        members,
        null,
        2
      ),
      "utf8"
    );

  } catch (error) {

    console.error(
      "[MEMBERS SAVE ERROR]",
      error.message
    );

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


function validName(name) {

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

  return NEW_PLANS[
    String(plan)
  ] || null;

}


function getRenewalPlan(plan) {

  return RENEWAL_PLANS[
    String(plan)
  ] || null;

}


function generateMemberId() {

  return (
    "14F-" +
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

Created only AFTER Twilio confirms the OTP.

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
    `${phone}.${timestamp}`;

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

    const age =
      Date.now() -
      Number(decoded.timestamp);

    if (
      !Number.isFinite(age) ||
      age < 0 ||
      age > 30 * 60 * 1000
    ) {
      return false;
    }

    const payload =
      `${decoded.phone}.${decoded.timestamp}`;

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
        decoded.signature
      );

    const expected =
      Buffer.from(
        expectedSignature
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
      `${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`
    ).toString("base64");

  return `Basic ${credentials}`;

}


/*
=========================================================
SEND OTP
=========================================================
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
      `${twilioBaseUrl()}/Verifications`,
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
      `${twilioBaseUrl()}/VerificationCheck`,
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
    (now -
      existing.lastRequest) /
    1000;


  if (
    secondsSinceLast <
    OTP_COOLDOWN_MS / 1000
  ) {

    return {
      allowed: false,

      waitSeconds:
        Math.ceil(
          OTP_COOLDOWN_MS /
            1000 -
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
HEALTH
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

      memberStorage:
        "members.json"
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


      if (
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
              `Please wait ${rate.waitSeconds} seconds before requesting another OTP.`,

            retryAfter:
              rate.waitSeconds
          });

      }


      const result =
        await sendTwilioVerification(
          phone
        );


      console.log(
        `[OTP SENT] ${phone} | ${result.status || "unknown"}`
      );


      return res.json({

        success: true,

        message:
          "OTP sent successfully."

      });


    } catch (error) {

      console.error(
        "[OTP SEND ERROR]",
        error?.message ||
          error
      );

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


      const result =
        await checkTwilioVerification(
          phone,
          otp
        );


      if (
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
      -----------------------------------------------------
      EXISTING MEMBER CHECK
      -----------------------------------------------------
      */

      const existingMember =
        members[phone] || null;


      /*
      A member counts as an existing member only if
      their record is ACTIVE.

      PAYMENT_PENDING members are not treated as active.
      */

      const isExistingMember =
        Boolean(
          existingMember &&
          existingMember.status ===
            "ACTIVE"
        );


      const verificationToken =
        createVerificationToken(
          phone
        );


      console.log(
        `[OTP VERIFIED] ${phone} | Existing active member: ${isExistingMember}`
      );


      /*
      Return only the information the frontend needs.
      */

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
        error?.message ||
          error
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
        Number(amount) !==
        selectedPlan.amount
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Membership amount does not match the selected plan."
          });

      }


      /*
      Mobile MUST have been verified first.
      */

      if (
        !verifyVerificationToken(
          verificationToken,
          phone
        )
      ) {

        return res
          .status(401)
          .json({
            ok: false,
            error:
              "Mobile verification required before membership registration."
          });

      }


      /*
      Prevent creating a second active membership
      with the same verified phone.
      */

      const existing =
        members[phone];


      if (
        existing &&
        existing.status ===
          "ACTIVE"
      ) {

        return res
          .status(409)
          .json({
            ok: false,
            error:
              "An active membership already exists for this mobile number."
          });

      }


      const memberId =
        generateMemberId();


      const member = {

        memberId,

        name:
          cleanFullName,

        phone,

        age:
          Number(age),

        gender:
          String(gender),

        goal:
          String(goal),

        plan:
          String(plan),

        planName:
          selectedPlan.name,

        amount:
          selectedPlan.amount,

        months:
          selectedPlan.months,

        status:
          "PAYMENT_PENDING_VERIFICATION",

        createdAt:
          new Date().toISOString(),

        expiresAt:
          null

      };


      members[phone] =
        member;

      saveMembers();


      console.log(
        `[MEMBERSHIP] ${memberId} | ${phone} | ${selectedPlan.name}`
      );


      return res
        .status(201)
        .json({

          ok: true,

          memberId,

          status:
            member.status,

          message:
            "Registration received. Verify payment before activating membership."

        });


    } catch (error) {

      console.error(
        "[MEMBERSHIP ERROR]",
        error?.message ||
          error
      );

      return res
        .status(500)
        .json({

          ok: false,

          error:
            "Could not process membership registration."

        });

    }

  }
);


/*
=========================================================
RENEWAL
=========================================================

This endpoint is ready for order.html if you later connect
the renewal payment form directly to the backend.

Plans:

₹700  -> 1 month
₹1400 -> 2 months
₹2000 -> 3 months
₹4000 -> 4 months
₹5000 -> 5 months
*/

app.post(
  "/api/renewal",
  (req, res) => {

    try {

      const {
        phone: rawPhone,
        plan,
        amount,
        verificationToken
      } = req.body || {};


      const phone =
        normalizeIndianPhone(
          rawPhone
        );

      const selectedPlan =
        getRenewalPlan(plan);


      if (!phone) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid mobile number."
          });

      }


      if (!selectedPlan) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid renewal plan."
          });

      }


      if (
        Number(amount) !==
        selectedPlan.amount
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Renewal amount does not match the selected plan."
          });

      }


      if (
        !verifyVerificationToken(
          verificationToken,
          phone
        )
      ) {

        return res
          .status(401)
          .json({
            ok: false,
            error:
              "Mobile verification required."
          });

      }


      const member =
        members[phone];


      if (!member) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              "No member profile was found for this mobile number."
          });

      }


      if (
        member.status !==
        "ACTIVE"
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "This membership is not currently active."
          });

      }


      /*
      Renewal is initially payment pending.
      We do NOT extend the membership until payment
      is confirmed by admin.
      */

      const renewalId =
        "REN-" +
        Date.now()
          .toString()
          .slice(-8);


      member.pendingRenewal = {

        renewalId,

        plan:
          String(plan),

        planName:
          selectedPlan.name,

        amount:
          selectedPlan.amount,

        months:
          selectedPlan.months,

        status:
          "PAYMENT_PENDING_VERIFICATION",

        createdAt:
          new Date().toISOString()

      };


      saveMembers();


      console.log(
        `[RENEWAL] ${renewalId} | ${phone} | ${selectedPlan.name}`
      );


      return res
        .status(201)
        .json({

          ok: true,

          renewalId,

          status:
            "PAYMENT_PENDING_VERIFICATION",

          message:
            "Renewal request received. Verify payment before extending membership."

        });


    } catch (error) {

      console.error(
        "[RENEWAL ERROR]",
        error?.message ||
          error
      );

      return res
        .status(500)
        .json({

          ok: false,

          error:
            "Could not process renewal."

        });

    }

  }
);


/*
=========================================================
ADMIN AUTH HELPER
=========================================================
*/

function requireAdmin(req, res) {

  if (!ADMIN_KEY) {

    res
      .status(503)
      .json({
        ok: false,
        error:
          "ADMIN_KEY is not configured."
      });

    return false;
  }


  const providedKey =
    req.headers[
      "x-admin-key"
    ];


  if (
    !providedKey ||
    providedKey !== ADMIN_KEY
  ) {

    res
      .status(403)
      .json({
        ok: false,
        error:
          "Unauthorized."
      });

    return false;
  }


  return true;

}


/*
=========================================================
ADMIN MEMBER LOOKUP
=========================================================
*/

app.get(
  "/api/admin/member",
  (req, res) => {

    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }


    try {

      const phone =
        normalizeIndianPhone(
          req.query.phone
        );


      if (!phone) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid mobile number."
          });

      }


      const member =
        members[phone] ||
        null;


      return res.json({

        ok: true,

        found:
          Boolean(member),

        member

      });


    } catch (error) {

      return res
        .status(500)
        .json({

          ok: false,

          error:
            "Could not lookup member."

        });

    }

  }
);


/*
=========================================================
ADMIN: ACTIVATE NEW MEMBERSHIP
=========================================================
*/

app.post(
  "/api/admin/activate-member",
  (req, res) => {

    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }


    try {

      const phone =
        normalizeIndianPhone(
          req.body?.phone
        );


      if (!phone) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid mobile number."
          });

      }


      const member =
        members[phone];


      if (!member) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              "Member not found."
          });

      }


      /*
      Calculate membership expiry
      from activation date.
      */

      const now =
        new Date();


      const expires =
        new Date(now);


      expires.setMonth(
        expires.getMonth() +
        Number(
          member.months || 1
        )
      );


      member.status =
        "ACTIVE";

      member.activatedAt =
        now.toISOString();

      member.expiresAt =
        expires.toISOString();


      saveMembers();


      console.log(
        `[ACTIVATED] ${member.memberId} | ${phone}`
      );


      return res.json({

        ok: true,

        message:
          "Membership activated.",

        member

      });


    } catch (error) {

      console.error(
        "[ACTIVATE ERROR]",
        error?.message ||
          error
      );

      return res
        .status(500)
        .json({

          ok: false,

          error:
            "Could not activate member."

        });

    }

  }
);


/*
=========================================================
ADMIN: APPROVE RENEWAL
=========================================================
*/

app.post(
  "/api/admin/approve-renewal",
  (req, res) => {

    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }


    try {

      const phone =
        normalizeIndianPhone(
          req.body?.phone
        );


      if (!phone) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid mobile number."
          });

      }


      const member =
        members[phone];


      if (!member) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              "Member not found."
          });

      }


      if (
        !member.pendingRenewal
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "No pending renewal found."
          });

      }


      const renewal =
        member.pendingRenewal;


      /*
      If membership is still active,
      extend from the current expiry.

      Otherwise extend from today.
      */

      const baseDate =
        member.expiresAt &&
        new Date(
          member.expiresAt
        ) > new Date()

          ? new Date(
              member.expiresAt
            )

          : new Date();


      const newExpiry =
        new Date(baseDate);


      newExpiry.setMonth(
        newExpiry.getMonth() +
        Number(
          renewal.months
        )
      );


      member.status =
        "ACTIVE";

      member.expiresAt =
        newExpiry.toISOString();

      member.lastRenewal =
        {

          renewalId:
            renewal.renewalId,

          plan:
            renewal.plan,

          planName:
            renewal.planName,

          amount:
            renewal.amount,

          months:
            renewal.months,

          approvedAt:
            new Date().toISOString()

        };


      delete member.pendingRenewal;


      saveMembers();


      console.log(
        `[RENEWAL APPROVED] ${member.memberId} | ${phone} | ${renewal.renewalId}`
      );


      return res.json({

        ok: true,

        message:
          "Renewal approved and membership extended.",

        member

      });


    } catch (error) {

      console.error(
        "[RENEWAL APPROVE ERROR]",
        error?.message ||
          error
      );

      return res
        .status(500)
        .json({

          ok: false,

          error:
            "Could not approve renewal."

        });

    }

  }
);


/*
=========================================================
ADMIN: REJECT RENEWAL
=========================================================
*/

app.post(
  "/api/admin/reject-renewal",
  (req, res) => {

    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }


    try {

      const phone =
        normalizeIndianPhone(
          req.body?.phone
        );


      if (!phone) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid mobile number."
          });

      }


      const member =
        members[phone];


      if (!member) {

        return res
          .status(404)
          .json({
            ok: false,
            error:
              "Member not found."
          });

      }


      if (
        !member.pendingRenewal
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            error:
              "No pending renewal found."
          });

      }


      const rejectedRenewal =
        member.pendingRenewal;


      member.lastRejectedRenewal =
        {

          ...rejectedRenewal,

          rejectedAt:
            new Date().toISOString()

        };


      delete member.pendingRenewal;


      saveMembers();


      return res.json({

        ok: true,

        message:
          "Renewal rejected.",

        member

      });


    } catch (error) {

      console.error(
        "[RENEWAL REJECT ERROR]",
        error?.message ||
          error
      );

      return res
        .status(500)
        .json({

          ok: false,

          error:
            "Could not reject renewal."

        });

    }

  }
);


/*
=========================================================
ADMIN: LIST MEMBERS
=========================================================
*/

app.get(
  "/api/admin/members",
  (req, res) => {

    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }


    try {

      const list =
        Object.values(
          members
        );


      return res.json({

        ok: true,

        count:
          list.length,

        members:
          list

      });


    } catch (error) {

      return res
        .status(500)
        .json({

          ok: false,

          error:
            "Could not load members."

        });

    }

  }
);


/*
=========================================================
CLEAN OTP RATE LIMIT DATA
=========================================================
*/

setInterval(
  () => {

    const now =
      Date.now();


    for (
      const [
        phone,
        data
      ] of otpRequests.entries()
    ) {

      if (
        now -
        data.firstRequest >
        OTP_WINDOW_MS
      ) {

        otpRequests.delete(
          phone
        );

      }

    }

  },
  5 * 60 * 1000
);


/*
=========================================================
FRONTEND FALLBACK
=========================================================
*/

app.get(
  /.*/,
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );

  }
);


/*
=========================================================
START SERVER
=========================================================
*/

app.listen(
  PORT,
  () => {

    console.log(
      "========================================"
    );

    console.log(
      `${GYM_NAME} server running on port ${PORT}`
    );

    console.log(
      `Twilio OTP: ${
        twilioConfigured()
          ? "CONFIGURED"
          : "NOT CONFIGURED"
      }`
    );

    console.log(
      `Verification secret: ${
        VERIFY_TOKEN_SECRET
          ? "CONFIGURED"
          : "NOT CONFIGURED"
      }`
    );

    console.log(
      `Admin key: ${
        ADMIN_KEY
          ? "CONFIGURED"
          : "NOT CONFIGURED"
      }`
    );

    console.log(
      `Members loaded: ${
        Object.keys(members).length
      }`
    );

    console.log(
      "========================================"
    );

  }
);
