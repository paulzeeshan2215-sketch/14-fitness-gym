const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.static(__dirname));

app.get("/api/health", (req,res) => {
  res.json({ ok:true, service:"14 FITNESS GYM", time:new Date().toISOString() });
});

/*
  Telegram will be added here in the next backend phase.
  Keep TG_BOT_TOKEN and TG_CHAT_ID in Render Environment Variables.
  Never put the bot token in index.html/order.html.
*/

app.post("/api/membership", (req,res) => {
  const { name, phone, age, gender, goal, plan, amount } = req.body || {};

  if (!name || !/^[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]{2,59}$/.test(String(name).trim())) {
    return res.status(400).json({ ok:false, error:"Invalid full name." });
  }
  if (!phone || !/^[6-9][0-9]{9}$/.test(String(phone))) {
    return res.status(400).json({ ok:false, error:"Invalid mobile number." });
  }
  if (!age || Number(age) < 12 || Number(age) > 90) {
    return res.status(400).json({ ok:false, error:"Invalid age." });
  }
  if (!gender || !goal || !plan || !amount) {
    return res.status(400).json({ ok:false, error:"Missing required membership fields." });
  }

  // This endpoint validates the registration.
  // Payment must be verified server-side before a membership is marked ACTIVE.
  const memberId = "14F-" + Date.now().toString().slice(-8);

  res.status(201).json({
    ok:true,
    memberId,
    status:"PAYMENT_PENDING_VERIFICATION",
    message:"Registration received. Verify payment before activating membership."
  });
});

app.get("*", (req,res) => {
  res.sendFile(path.join(__dirname,"index.html"));
});

app.listen(PORT, () => {
  console.log(`14 FITNESS GYM server running on port ${PORT}`);
});
