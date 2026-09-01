const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const app = express();

/*
=========================================================
CONFIGURATION
=========================================================
*/

const PORT =
  Number(process.env.PORT) || 10000;

const GYM_NAME =
  "14 FITNESS GYM";

/*
---------------------------------------------------------
TWILIO DIRECT SMS CONFIGURATION
---------------------------------------------------------

Required Render Environment Variables:

TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN
TWILIO_PHONE_NUMBER

No TWILIO_VERIFY_SERVICE_SID is required.
---------------------------------------------------------
*/

const TWILIO_ACCOUNT_SID =
  process.env.TWILIO_ACCOUNT_SID || "";

const TWILIO_AUTH_TOKEN =
  process.env.TWILIO_AUTH_TOKEN || "";

const TWILIO_PHONE_NUMBER =
  process.env.TWILIO_PHONE_NUMBER || "";

const VERIFY_TOKEN_SECRET =
  process.env.VERIFY_TOKEN_SECRET || "";

const ADMIN_KEY =
  process.env.ADMIN_KEY || "";


/*
=========================================================
MIDDLEWARE
=========================================================
*/

app.disable("x-powered-by");

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

app.use(
  express.static(__dirname)
);


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
  path.join(
    __dirname,
    "members.json"
  );


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

    if (!raw.trim()) {
      return {};
    }

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


let members =
  loadMembers();


function saveMembers() {
  const tempFile =
    MEMBERS_FILE + ".tmp";

  try {
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

    try {
      if (
        fs.existsSync(tempFile)
      ) {
        fs.unlinkSync(tempFile);
      }
    } catch (_) {}

    throw error;
  }
}


/*
=========================================================
OTP STORAGE
=========================================================

OTP is stored as a SHA-256 hash.

Plain OTP is NEVER stored in members.json.
=========================================================
*/

const otpStore =
  new Map();


const OTP_LENGTH =
  6;

const OTP_EXPIRY_MS =
  5 * 60 * 1000;

const OTP_COOLDOWN_MS =
  60 * 1000;

const OTP_WINDOW_MS =
  10 * 60 * 1000;

const MAX_OTP_REQUESTS_PER_WINDOW =
  5;

const MAX_OTP_ATTEMPTS =
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


function validGender(gender) {
  const allowed = [
    "Male",
    "Female",
    "Other"
  ];

  return allowed.includes(
    String(gender || "")
  );
}


function validGoal(goal) {
  const allowed = [
    "Weight Loss",
    "Muscle Gain",
    "General Fitness",
    "Bodybuilding",
    "Strength",
    "Fat Loss",
    "Fitness"
  ];

  return allowed.includes(
    String(goal || "")
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


/*
=========================================================
TWILIO CONFIG CHECK
=========================================================
*/

function twilioConfigured() {
  return Boolean(
    TWILIO_ACCOUNT_SID &&
    TWILIO_AUTH_TOKEN &&
    TWILIO_PHONE_NUMBER
  );
}


/*
=========================================================
VERIFY TOKEN
=========================================================
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

    const timestamp =
      Number(
        decoded.timestamp
      );

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
        String(
          decoded.signature
        ),
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
  } catch (_) {
    return false;
  }
}


/*
=========================================================
OTP GENERATION
=========================================================
*/

function generateOTP() {
  return String(
    crypto.randomInt(
      100000,
      1000000
    )
  );
}


function hashOTP(otp) {
  return crypto
    .createHash("sha256")
    .update(
      String(otp)
    )
    .digest("hex");
}


/*
=========================================================
TWILIO AUTH HEADER
=========================================================
*/

function twilioAuthHeader() {
  const credentials =
    Buffer.from(
      `${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`
    ).toString("base64");

  return `Basic ${credentials}`;
}


/*
=========================================================
SEND DIRECT SMS THROUGH TWILIO
=========================================================
*/

async function sendTwilioSMS(
  phone,
  message
) {
  if (!twilioConfigured()) {
    throw new Error(
      "Twilio SMS configuration is missing."
    );
  }

  const body =
    new URLSearchParams();

  body.set(
    "To",
    phone
  );

  body.set(
    "From",
    TWILIO_PHONE_NUMBER
  );

  body.set(
    "Body",
    message
  );

  const response =
    await fetch(
      "https://api.twilio.com/2010-04-01/Accounts/" +
        encodeURIComponent(
          TWILIO_ACCOUNT_SID
        ) +
        "/Messages.json",
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
    const messageText =
      data?.message ||
      data?.detail ||
      "Twilio could not send the SMS.";

    const error =
      new Error(
        messageText
      );

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
SEND OTP SMS
=========================================================
*/

async function sendOTP(phone) {
  const otp =
    generateOTP();

  const otpHash =
    hashOTP(otp);

  const now =
    Date.now();

  otpStore.set(
    phone,
    {
      hash: otpHash,

      createdAt:
        now,

      expiresAt:
        now +
        OTP_EXPIRY_MS,

      attempts: 0
    }
  );

  const smsText =
    `Your ${GYM_NAME} verification code is ${otp}. This code expires in 5 minutes. Do not share this code with anyone.`;

  try {
    const result =
      await sendTwilioSMS(
        phone,
        smsText
      );

    console.log(
      `[OTP SENT] ${phone} | ${result.sid || "no-sid"}`
    );

    return result;
  } catch (error) {
    /*
    If Twilio fails, remove the OTP
    so the user is not stuck with
    an unusable code.
    */

    otpStore.delete(phone);

    throw error;
  }
}


/*
=========================================================
VERIFY OTP
=========================================================
*/

function verifyOTP(
  phone,
  otp
) {
  const record =
    otpStore.get(phone);

  if (!record) {
    return {
      success: false,
      reason: "missing"
    };
  }

  if (
    Date.now() >
    record.expiresAt
  ) {
    otpStore.delete(phone);

    return {
      success: false,
      reason: "expired"
    };
  }

  if (
    record.attempts >=
    MAX_OTP_ATTEMPTS
  ) {
    otpStore.delete(phone);

    return {
      success: false,
      reason: "attempts"
    };
  }

  record.attempts += 1;

  const providedHash =
    hashOTP(otp);

  const actual =
    Buffer.from(
      providedHash,
      "utf8"
    );

  const expected =
    Buffer.from(
      record.hash,
      "utf8"
    );

  if (
    actual.length !==
    expected.length
  ) {
    return {
      success: false,
      reason: "invalid"
    };
  }

  const valid =
    crypto.timingSafeEqual(
      actual,
      expected
    );

  if (!valid) {
    return {
      success: false,
      reason: "invalid"
    };
  }

  otpStore.delete(phone);

  return {
    success: true
  };
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
        firstRequest:
          now,

        lastRequest:
          now,

        count:
          1
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
        firstRequest:
          now,

        lastRequest:
          now,

        count:
          1
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
AMOUNT
=========================================================
*/

function normalizeAmount(value) {
  const amount =
    Number(value);

  if (
    !Number.isFinite(amount) ||
    amount < 0
  ) {
    return null;
  }

  return amount;
}


/*
=========================================================
DATE HELPERS
=========================================================
*/

function addMonths(
  date,
  months
) {
  const result =
    new Date(date);

  const originalDay =
    result.getDate();

  result.setDate(1);

  result.setMonth(
    result.getMonth() +
      months
  );

  const lastDay =
    new Date(
      result.getFullYear(),
      result.getMonth() + 1,
      0
    ).getDate();

  result.setDate(
    Math.min(
      originalDay,
      lastDay
    )
  );

  return result;
}


function getMembershipStartDate(
  member
) {
  if (
    member &&
    member.expiresAt
  ) {
    const existingExpiry =
      new Date(
        member.expiresAt
      );

    if (
      !Number.isNaN(
        existingExpiry.getTime()
      ) &&
      existingExpiry.getTime() >
        Date.now()
    ) {
      return existingExpiry;
    }
  }

  return new Date();
}


/*
=========================================================
SAFE MEMBER RESPONSE
=========================================================
*/

function safeMemberData(member) {
  if (!member) {
    return null;
  }

  return {
    memberId:
      member.memberId ||
      null,

    name:
      member.name ||
      null,

    phone:
      member.phone ||
      null,

    age:
      member.age ??
      null,

    gender:
      member.gender ||
      null,

    goal:
      member.goal ||
      null,

    plan:
      member.plan ||
      null,

    planName:
      member.planName ||
      null,

    amount:
      member.amount ??
      null,

    status:
      member.status ||
      null,

    expiresAt:
      member.expiresAt ||
      null,

    createdAt:
      member.createdAt ||
      null,

    updatedAt:
      member.updatedAt ||
      null
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
        Object.keys(
          members
        ).length
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
  async (
    req,
    res
  ) => {
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

      if (
        !twilioConfigured()
      ) {
        console.error(
          "[OTP] Twilio SMS configuration missing."
        );

        return res
          .status(503)
          .json({
            success: false,

            message:
              "SMS service is not configured on the server yet."
          });
      }

      if (
        !VERIFY_TOKEN_SECRET
      ) {
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

      await sendOTP(phone);

      return res.json({
        success: true,

        message:
          "OTP sent successfully."
      });
    } catch (error) {
      console.error(
        "[TWILIO SEND ERROR]",
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
  async (
    req,
    res
  ) => {
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
        !/^\d{6}$/.test(otp)
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Please enter the 6-digit OTP received by SMS."
          });
      }

      if (
        !twilioConfigured()
      ) {
        return res
          .status(503)
          .json({
            success: false,

            message:
              "SMS verification is not configured on the server."
          });
      }

      if (
        !VERIFY_TOKEN_SECRET
      ) {
        return res
          .status(503)
          .json({
            success: false,

            message:
              "Verification security is not configured on the server."
          });
      }

      const result =
        verifyOTP(
          phone,
          otp
        );

      if (!result.success) {
        let message =
          "Invalid OTP. Please try again.";

        if (
          result.reason ===
          "missing"
        ) {
          message =
            "No active OTP found. Please request a new OTP.";
        }

        if (
          result.reason ===
          "expired"
        ) {
          message =
            "OTP expired. Please request a new OTP.";
        }

        if (
          result.reason ===
          "attempts"
        ) {
          message =
            "Too many incorrect attempts. Please request a new OTP.";
        }

        return res
          .status(401)
          .json({
            success: false,
            message
          });
      }

      const existingMember =
        members[phone] ||
        null;

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

      return res.json({
        success: true,

        message:
          "Mobile number verified successfully.",

        isExistingMember,

        member:
          safeMemberData(
            existingMember
          ),

        verificationToken
      });
    } catch (error) {
      console.error(
        "[OTP VERIFY ERROR]",
        error
      );

      return res
        .status(500)
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
  (
    req,
    res
  ) => {
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
        !validGender(gender)
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Invalid gender."
          });
      }

      if (
        !validGoal(goal)
      ) {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              "Invalid fitness goal."
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
              "Mobile verification expired or invalid. Please verify your mobile number again."
          });
      }

      /*
      -----------------------------------------------------
      SERVER-SIDE PRICE
      -----------------------------------------------------
      */

      const serverAmount =
        selectedPlan.amount;

      const requestedAmount =
        normalizeAmount(amount);

      if (
        requestedAmount !== null &&
        requestedAmount !==
          serverAmount
      ) {
        console.warn(
          `[MEMBERSHIP] Amount mismatch for ${phone}. Frontend: ${requestedAmount}, Server: ${serverAmount}`
        );
      }

      /*
      -----------------------------------------------------
      DUPLICATE ACTIVE MEMBERSHIP
      -----------------------------------------------------
      */

      const existing =
        members[phone] ||
        null;

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
              "An active membership already exists for this mobile number. Please use renewal instead.",

            member:
              safeMemberData(
                existing
              )
          });
      }

      const now =
        new Date();

      const memberId =
        generateMemberId();

      const expiresAt =
        addMonths(
          now,
          selectedPlan.months
        ).toISOString();

      const member = {
        memberId,

        phone,

        name:
          cleanFullName,

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
          serverAmount,

        months:
          selectedPlan.months,

        status:
          "ACTIVE",

        expiresAt,

        createdAt:
          now.toISOString(),

        updatedAt:
          now.toISOString(),

        renewals:
          []
      };

      members[phone] =
        member;

      saveMembers();

      console.log(
        `[NEW MEMBER] ${memberId} | ${phone} | ${selectedPlan.name}`
      );

      return res
        .status(201)
        .json({
          ok: true,

          message:
            "Membership registered successfully.",

          member:
            safeMemberData(
              member
            )
        });
    } catch (error) {
      console.error(
        "[MEMBERSHIP ERROR]",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Membership registration failed. Please try again."
        });
    }
  }
);


/*
=========================================================
RENEW MEMBERSHIP
=========================================================
*/

app.post(
  "/api/renew",
  (
    req,
    res
  ) => {
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
              "Mobile verification expired or invalid. Please verify your mobile number again."
          });
      }

      const member =
        members[phone] ||
        null;

      if (!member) {
        return res
          .status(404)
          .json({
            ok: false,

            error:
              "No membership found for this mobile number. Please register as a new member first."
          });
      }

      const serverAmount =
        selectedPlan.amount;

      const requestedAmount =
        normalizeAmount(amount);

      if (
        requestedAmount !== null &&
        requestedAmount !==
          serverAmount
      ) {
        console.warn(
          `[RENEWAL] Amount mismatch for ${phone}. Frontend: ${requestedAmount}, Server: ${serverAmount}`
        );
      }

      const oldExpiry =
        member.expiresAt
          ? new Date(
              member.expiresAt
            )
          : new Date();

      const validOldExpiry =
        !Number.isNaN(
          oldExpiry.getTime()
        ) &&
        oldExpiry.getTime() >
          Date.now();

      const startDate =
        validOldExpiry
          ? oldExpiry
          : new Date();

      const newExpiry =
        addMonths(
          startDate,
          selectedPlan.months
        );

      const renewalId =
        generateRenewalId();

      const renewal = {
        renewalId,

        plan:
          String(plan),

        planName:
          selectedPlan.name,

        months:
          selectedPlan.months,

        amount:
          serverAmount,

        previousExpiresAt:
          member.expiresAt ||
          null,

        newExpiresAt:
          newExpiry.toISOString(),

        createdAt:
          new Date().toISOString()
      };

      if (
        !Array.isArray(
          member.renewals
        )
      ) {
        member.renewals =
          [];
      }

      member.renewals.push(
        renewal
      );

      member.status =
        "ACTIVE";

      member.expiresAt =
        newExpiry.toISOString();

      member.plan =
        String(plan);

      member.planName =
        selectedPlan.name;

      member.amount =
        serverAmount;

      member.updatedAt =
        new Date().toISOString();

      saveMembers();

      console.log(
        `[RENEWAL] ${renewalId} | ${phone} | ${selectedPlan.name}`
      );

      return res.json({
        ok: true,

        message:
          "Membership renewed successfully.",

        renewal,

        member:
          safeMemberData(
            member
          )
      });
    } catch (error) {
      console.error(
        "[RENEWAL ERROR]",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Membership renewal failed. Please try again."
        });
    }
  }
);


/*
=========================================================
GET MEMBER
=========================================================
*/

app.get(
  "/api/member",
  (
    req,
    res
  ) => {
    try {
      const phone =
        normalizeIndianPhone(
          req.query?.phone
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

      if (!member) {
        return res
          .status(404)
          .json({
            ok: false,

            error:
              "Member not found."
          });
      }

      return res.json({
        ok: true,

        member:
          safeMemberData(
            member
          )
      });
    } catch (error) {
      console.error(
        "[GET MEMBER ERROR]",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not retrieve member."
        });
    }
  }
);


/*
=========================================================
ADMIN AUTHENTICATION
=========================================================
*/

function requireAdmin(
  req,
  res,
  next
) {
  if (!ADMIN_KEY) {
    return res
      .status(503)
      .json({
        ok: false,

        error:
          "ADMIN_KEY is not configured on the server."
      });
  }

  const providedKey =
    req.headers[
      "x-admin-key"
    ] ||
    req.body?.adminKey ||
    req.query?.adminKey ||
    "";

  if (
    typeof providedKey !==
      "string" ||
    providedKey.length === 0
  ) {
    return res
      .status(401)
      .json({
        ok: false,

        error:
          "Admin authentication required."
      });
  }

  const actual =
    Buffer.from(
      String(
        providedKey
      ),
      "utf8"
    );

  const expected =
    Buffer.from(
      String(
        ADMIN_KEY
      ),
      "utf8"
    );

  if (
    actual.length !==
    expected.length
  ) {
    return res
      .status(403)
      .json({
        ok: false,

        error:
          "Invalid admin credentials."
      });
  }

  if (
    !crypto.timingSafeEqual(
      actual,
      expected
    )
  ) {
    return res
      .status(403)
      .json({
        ok: false,

        error:
          "Invalid admin credentials."
      });
  }

  next();
}


/*
=========================================================
ADMIN - ALL MEMBERS
=========================================================
*/

app.get(
  "/api/admin/members",
  requireAdmin,
  (
    req,
    res
  ) => {
    try {
      const list =
        Object.values(
          members
        ).map(
          safeMemberData
        );

      return res.json({
        ok: true,

        count:
          list.length,

        members:
          list
      });
    } catch (error) {
      console.error(
        "[ADMIN MEMBERS ERROR]",
        error
      );

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
ADMIN - SINGLE MEMBER
=========================================================
*/

app.get(
  "/api/admin/member/:phone",
  requireAdmin,
  (
    req,
    res
  ) => {
    try {
      const phone =
        normalizeIndianPhone(
          req.params.phone
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

      if (!member) {
        return res
          .status(404)
          .json({
            ok: false,

            error:
              "Member not found."
          });
      }

      return res.json({
        ok: true,

        member:
          safeMemberData(
            member
          ),

        renewals:
          Array.isArray(
            member.renewals
          )
            ? member.renewals
            : []
      });
    } catch (error) {
      console.error(
        "[ADMIN MEMBER ERROR]",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not load member."
        });
    }
  }
);


/*
=========================================================
ADMIN - DELETE MEMBER
=========================================================
*/

app.delete(
  "/api/admin/member/:phone",
  requireAdmin,
  (
    req,
    res
  ) => {
    try {
      const phone =
        normalizeIndianPhone(
          req.params.phone
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

      if (!members[phone]) {
        return res
          .status(404)
          .json({
            ok: false,

            error:
              "Member not found."
          });
      }

      delete members[phone];

      saveMembers();

      console.log(
        `[ADMIN DELETE] ${phone}`
      );

      return res.json({
        ok: true,

        message:
          "Member deleted successfully."
      });
    } catch (error) {
      console.error(
        "[ADMIN DELETE ERROR]",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not delete member."
        });
    }
  }
);


/*
=========================================================
ADMIN - DASHBOARD STATS
=========================================================
*/

app.get(
  "/api/admin/stats",
  requireAdmin,
  (
    req,
    res
  ) => {
    try {
      const allMembers =
        Object.values(
          members
        );

      const activeMembers =
        allMembers.filter(
          (member) =>
            member.status ===
            "ACTIVE"
        );

      const expiredMembers =
        allMembers.filter(
          (member) => {
            if (
              !member.expiresAt
            ) {
              return false;
            }

            const expiry =
              new Date(
                member.expiresAt
              );

            return (
              !Number.isNaN(
                expiry.getTime()
              ) &&
              expiry.getTime() <
                Date.now()
            );
          }
        );

      let totalRevenue = 0;

      for (
        const member of
          allMembers
      ) {
        totalRevenue +=
          Number(
            member.amount ||
              0
          );

        if (
          Array.isArray(
            member.renewals
          )
        ) {
          for (
            const renewal of
              member.renewals
          ) {
            totalRevenue +=
              Number(
                renewal.amount ||
                  0
              );
          }
        }
      }

      return res.json({
        ok: true,

        stats: {
          totalMembers:
            allMembers.length,

          activeMembers:
            activeMembers.length,

          expiredMembers:
            expiredMembers.length,

          totalRevenue
        }
      });
    } catch (error) {
      console.error(
        "[ADMIN STATS ERROR]",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Could not calculate dashboard statistics."
        });
    }
  }
);


/*
=========================================================
404 API HANDLER
=========================================================
*/

app.use(
  "/api",
  (
    req,
    res
  ) => {
    res
      .status(404)
      .json({
        ok: false,

        error:
          "API endpoint not found."
      });
  }
);


/*
=========================================================
GLOBAL ERROR HANDLER
=========================================================
*/

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "[GLOBAL ERROR]",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    return res
      .status(500)
      .json({
        ok: false,

        error:
          "Internal server error."
      });
  }
);


/*
=========================================================
START SERVER
=========================================================
*/

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "================================================="
    );

    console.log(
      `${GYM_NAME} SERVER STARTED`
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      `Members: ${
        Object.keys(
          members
        ).length
      }`
    );

    console.log(
      `Twilio configured: ${
        twilioConfigured()
      }`
    );

    console.log(
      `Verification secret configured: ${
        Boolean(
          VERIFY_TOKEN_SECRET
        )
      }`
    );

    console.log(
      `Admin configured: ${
        Boolean(
          ADMIN_KEY
        )
      }`
    );

    console.log(
      "================================================="
    );
  }
);
