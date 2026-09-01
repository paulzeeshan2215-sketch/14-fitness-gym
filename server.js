const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 10000;
const GYM_NAME = "14 FITNESS GYM";

/* =========================================================
   TWILIO CONFIG
   Uses your EXISTING Render variables.
========================================================= */

const TWILIO_ACCOUNT_SID =
  process.env.TWILIO_ACCOUNT_SID || "";

const TWILIO_AUTH_TOKEN =
  process.env.TWILIO_AUTH_TOKEN || "";

const TWILIO_PHONE_NUMBER =
  process.env.TWILIO_PHONE_NUMBER || "";

const ADMIN_KEY =
  process.env.ADMIN_KEY || "";


/* =========================================================
   OPTIONAL SECURITY SECRET
========================================================= */

const VERIFY_TOKEN_SECRET =
  process.env.VERIFY_TOKEN_SECRET ||
  crypto.randomBytes(32).toString("hex");


/* =========================================================
   EXPRESS
========================================================= */

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "2mb"
  })
);

app.use(express.static(__dirname));


/* =========================================================
   MEMBERSHIP PLANS
========================================================= */

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


/* =========================================================
   MEMBER STORAGE
========================================================= */

const MEMBERS_FILE =
  path.join(__dirname, "members.json");


function loadMembers() {

  try {

    if (!fs.existsSync(MEMBERS_FILE)) {
      return {};
    }

    const data =
      fs.readFileSync(
        MEMBERS_FILE,
        "utf8"
      );

    return JSON.parse(data) || {};

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


/* =========================================================
   OTP STORAGE
========================================================= */

const otpStore =
  new Map();


const OTP_VALIDITY_MS =
  5 * 60 * 1000;


const OTP_COOLDOWN_MS =
  60 * 1000;


const MAX_OTP_ATTEMPTS =
  5;


/* =========================================================
   PHONE NORMALIZATION
========================================================= */

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

  if (
    phone.length !== 10
  ) {

    return null;

  }

  if (
    !/^[6-9]\d{9}$/.test(phone)
  ) {

    return null;

  }

  return "+91" + phone;

}


/* =========================================================
   NAME VALIDATION
========================================================= */

function cleanName(value) {

  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");

}


function validName(name) {

  return /^[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]{1,59}$/
    .test(name);

}


/* =========================================================
   AGE
========================================================= */

function validAge(age) {

  const number =
    Number(age);

  return (
    Number.isInteger(number) &&
    number >= 12 &&
    number <= 90
  );

}


/* =========================================================
   TWILIO CONFIG CHECK
========================================================= */

function twilioConfigured() {

  return Boolean(
    TWILIO_ACCOUNT_SID &&
    TWILIO_AUTH_TOKEN &&
    TWILIO_PHONE_NUMBER
  );

}


/* =========================================================
   SEND SMS USING TWILIO MESSAGING API

   This is the OLD/EXISTING style setup:
   ACCOUNT SID
   AUTH TOKEN
   PHONE NUMBER

   No Verify Service SID required.
========================================================= */

async function sendSMS(
  to,
  message
) {

  const credentials =
    Buffer.from(
      `${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`
    ).toString("base64");


  const body =
    new URLSearchParams();


  body.set(
    "To",
    to
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
      `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(
        TWILIO_ACCOUNT_SID
      )}/Messages.json`,
      {

        method: "POST",

        headers: {

          Authorization:
            `Basic ${credentials}`,

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

    console.error(
      "[TWILIO ERROR]",
      data
    );


    const error =
      new Error(
        data?.message ||
        "Twilio SMS failed."
      );


    error.status =
      response.status;

    error.twilio =
      data;


    throw error;

  }


  return data;

}


/* =========================================================
   GENERATE OTP
========================================================= */

function generateOTP() {

  return crypto
    .randomInt(
      100000,
      1000000
    )
    .toString();

}


/* =========================================================
   GENERATE VERIFICATION TOKEN
========================================================= */

function createVerificationToken(
  phone
) {

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
  ).toString(
    "base64url"
  );

}


/* =========================================================
   VERIFY TOKEN
========================================================= */

function verifyVerificationToken(
  token,
  phone
) {

  try {

    if (
      !token ||
      !phone
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
      decoded.phone !== phone
    ) {

      return false;

    }


    const age =
      Date.now() -
      Number(
        decoded.timestamp
      );


    if (
      age < 0 ||
      age >
        30 * 60 * 1000
    ) {

      return false;

    }


    const payload =
      `${decoded.phone}.${decoded.timestamp}`;


    const expected =
      crypto
        .createHmac(
          "sha256",
          VERIFY_TOKEN_SECRET
        )
        .update(payload)
        .digest("hex");


    return (
      decoded.signature ===
      expected
    );

  } catch {

    return false;

  }

}


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  "/api/health",
  (req, res) => {

    res.json({

      ok: true,

      service:
        GYM_NAME,

      twilioConfigured:
        twilioConfigured(),

      members:
        Object.keys(
          members
        ).length,

      time:
        new Date().toISOString()

    });

  }
);


/* =========================================================
   SEND OTP
========================================================= */

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


      /*
      Check your EXISTING Twilio variables.
      */

      if (
        !twilioConfigured()
      ) {

        console.error(
          "[OTP ERROR] Missing Twilio environment variables."
        );


        return res
          .status(503)
          .json({

            success: false,

            message:
              "SMS service is not configured on the server yet."

          });

      }


      const existing =
        otpStore.get(
          phone
        );


      /*
      Prevent repeated OTP requests
      within 60 seconds.
      */

      if (
        existing &&
        Date.now() -
          existing.sentAt <
          OTP_COOLDOWN_MS
      ) {

        const wait =
          Math.ceil(
            (
              OTP_COOLDOWN_MS -
              (
                Date.now() -
                existing.sentAt
              )
            ) / 1000
          );


        return res
          .status(429)
          .json({

            success: false,

            message:
              `Please wait ${wait} seconds before requesting another OTP.`

          });

      }


      const otp =
        generateOTP();


      /*
      Store only the OTP needed for verification.
      */

      otpStore.set(
        phone,
        {

          otp,

          name,

          sentAt:
            Date.now(),

          expiresAt:
            Date.now() +
            OTP_VALIDITY_MS,

          attempts: 0

        }
      );


      const message =
        `${GYM_NAME} verification code: ${otp}. ` +
        `This code is valid for 5 minutes. ` +
        `Do not share this code with anyone.`;


      const sms =
        await sendSMS(
          phone,
          message
        );


      console.log(
        `[OTP SENT] ${phone} | SID: ${sms.sid || "unknown"}`
      );


      return res.json({

        success: true,

        message:
          "OTP sent successfully."

      });


    } catch (error) {

      /*
      If Twilio fails, remove the OTP so
      the user can try again.
      */

      const phone =
        normalizeIndianPhone(
          req.body?.phone
        );


      if (phone) {
        otpStore.delete(
          phone
        );
      }


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


/* =========================================================
   VERIFY OTP
========================================================= */

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
        !/^\d{6}$/.test(otp)
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "Please enter the 6-digit OTP."

          });

      }


      const record =
        otpStore.get(
          phone
        );


      if (!record) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "OTP not found. Please request a new OTP."

          });

      }


      if (
        Date.now() >
        record.expiresAt
      ) {

        otpStore.delete(
          phone
        );


        return res
          .status(400)
          .json({

            success: false,

            message:
              "OTP has expired. Please request a new OTP."

          });

      }


      record.attempts += 1;


      if (
        record.attempts >
        MAX_OTP_ATTEMPTS
      ) {

        otpStore.delete(
          phone
        );


        return res
          .status(429)
          .json({

            success: false,

            message:
              "Too many incorrect attempts. Please request a new OTP."

          });

      }


      if (
        record.otp !== otp
      ) {

        return res
          .status(401)
          .json({

            success: false,

            message:
              "Invalid OTP. Please check the code and try again."

          });

      }


      /*
      OTP is correct.
      Delete it so the same OTP cannot be reused.
      */

      otpStore.delete(
        phone
      );


      /*
      Check whether this mobile belongs
      to an ACTIVE existing member.
      */

      const existingMember =
        members[phone] || null;


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
                null

            }
          : null;


      console.log(
        `[OTP VERIFIED] ${phone} | Existing: ${isExistingMember}`
      );


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
        .status(500)
        .json({

          success: false,

          message:
            "OTP verification failed. Please try again."

        });

    }

  }
);


/* =========================================================
   NEW MEMBERSHIP
========================================================= */

app.post(
  "/api/membership",
  (req, res) => {

    try {

      const {

        name,

        phone:
          rawPhone,

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
        NEW_PLANS[
          String(plan)
        ];


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


      if (
        !validAge(age)
      ) {

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
              "Invalid membership amount."

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
              "Please verify your mobile number first."

          });

      }


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
        "14F-" +
        Date.now()
          .toString()
          .slice(-8) +
        "-" +
        crypto
          .randomBytes(2)
          .toString("hex")
          .toUpperCase();


      members[phone] = {

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


      saveMembers();


      console.log(
        `[NEW MEMBERSHIP] ${memberId} | ${phone}`
      );


      return res
        .status(201)
        .json({

          ok: true,

          memberId,

          status:
            "PAYMENT_PENDING_VERIFICATION",

          message:
            "Registration received successfully."

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


/* =========================================================
   RENEWAL
========================================================= */

app.post(
  "/api/renewal",
  (req, res) => {

    try {

      const {

        phone:
          rawPhone,

        plan,

        amount,

        verificationToken

      } = req.body || {};


      const phone =
        normalizeIndianPhone(
          rawPhone
        );


      const selectedPlan =
        RENEWAL_PLANS[
          String(plan)
        ];


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
              "Invalid renewal amount."

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
              "Please verify your mobile number first."

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
        member.status !==
        "ACTIVE"
      ) {

        return res
          .status(400)
          .json({

            ok: false,

            error:
              "Membership is not active."

          });

      }


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


      return res
        .status(201)
        .json({

          ok: true,

          renewalId,

          status:
            "PAYMENT_PENDING_VERIFICATION",

          message:
            "Renewal request submitted successfully."

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


/* =========================================================
   ADMIN AUTH
========================================================= */

function requireAdmin(
  req,
  res
) {

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


  const key =
    req.headers[
      "x-admin-key"
    ];


  if (
    !key ||
    key !== ADMIN_KEY
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


/* =========================================================
   ADMIN MEMBER LOOKUP
========================================================= */

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


    return res.json({

      ok: true,

      found:
        Boolean(
          members[phone]
        ),

      member:
        members[phone] ||
        null

    });

  }
);


/* =========================================================
   ADMIN LIST MEMBERS
========================================================= */

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


    return res.json({

      ok: true,

      count:
        Object.keys(
          members
        ).length,

      members:
        Object.values(
          members
        )

    });

  }
);


/* =========================================================
   ADMIN ACTIVATE NEW MEMBER
========================================================= */

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


      const now =
        new Date();


      const expiry =
        new Date(
          now
        );


      expiry.setMonth(
        expiry.getMonth() +
        Number(
          member.months || 1
        )
      );


      member.status =
        "ACTIVE";


      member.activatedAt =
        now.toISOString();


      member.expiresAt =
        expiry.toISOString();


      saveMembers();


      return res.json({

        ok: true,

        message:
          "Membership activated successfully.",

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
            "Could not activate membership."

        });

    }

  }
);


/* =========================================================
   ADMIN APPROVE RENEWAL
========================================================= */

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


      const now =
        new Date();


      let baseDate =
        now;


      if (
        member.expiresAt
      ) {

        const currentExpiry =
          new Date(
            member.expiresAt
          );


        if (
          currentExpiry >
          now
        ) {

          baseDate =
            currentExpiry;

        }

      }


      const newExpiry =
        new Date(
          baseDate
        );


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


      member.lastRenewal = {

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
          now.toISOString()

      };


      delete member.pendingRenewal;


      saveMembers();


      return res.json({

        ok: true,

        message:
          "Renewal approved successfully.",

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


/* =========================================================
   ADMIN REJECT RENEWAL
========================================================= */

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


      member.lastRejectedRenewal = {

        ...member.pendingRenewal,

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


/* =========================================================
   CLEAN EXPIRED OTPs
========================================================= */

setInterval(
  () => {

    const now =
      Date.now();


    for (
      const [
        phone,
        record
      ] of otpStore.entries()
    ) {

      if (
        now >
        record.expiresAt
      ) {

        otpStore.delete(
          phone
        );

      }

    }

  },
  60 * 1000
);


/* =========================================================
   FRONTEND
========================================================= */

app.get(
  "/",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );

  }
);


/* =========================================================
   START
========================================================= */

app.listen(
  PORT,
  () => {

    console.log(
      "======================================"
    );

    console.log(
      `${GYM_NAME} server running on port ${PORT}`
    );

    console.log(
      "Twilio Account SID:",
      TWILIO_ACCOUNT_SID
        ? "CONFIGURED"
        : "MISSING"
    );

    console.log(
      "Twilio Auth Token:",
      TWILIO_AUTH_TOKEN
        ? "CONFIGURED"
        : "MISSING"
    );

    console.log(
      "Twilio Phone Number:",
      TWILIO_PHONE_NUMBER
        ? "CONFIGURED"
        : "MISSING"
    );

    console.log(
      "======================================"
    );

  }
);
