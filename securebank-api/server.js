const express = require("express");
const axios   = require("axios");
const morgan  = require("morgan");
const cors    = require("cors");
const path    = require("path");

const app  = express();
const PORT = 8080;

// ══════════════════════════════════════════════════════════════
//  IN-MEMORY BANK DATABASE  (simulates a real SQL/NoSQL backend)
// ══════════════════════════════════════════════════════════════

const accounts = {
  "ayman.djioui": {
    password: "Djioui@2025",
    name: "Ayman Djioui",
    id: "ACC-001",
    avatar: "AD",
    balance: 15250.75,
    currency: "MAD",
    card: { number: "4532 •••• •••• 8821", full: "4532 1111 2222 8821", exp: "12/27", cvv: "421", type: "VISA", color: "#1a237e" },
    iban: "MA64 0119 1080 1234 5678 9101 112",
    email: "a.djioui@securebank.ma",
    phone: "+212 6 12 34 56 78",
    address: "12 Rue Hassan II, Casablanca",
    transactions: [
      { id:"TXN-9821", type:"credit", amount:5000.00, from:"ENSA Salary",      date:"2026-04-15", category:"salary",   note:"April 2026 Salary" },
      { id:"TXN-9820", type:"debit",  amount:850.00,  from:"Carrefour Market",date:"2026-04-14", category:"shopping",  note:"Monthly groceries" },
      { id:"TXN-9819", type:"debit",  amount:1200.00, from:"Apartment Rent",  date:"2026-04-10", category:"housing",   note:"April Rent" },
      { id:"TXN-9818", type:"credit", amount:300.00,  from:"Aymane Elouafi",  date:"2026-04-09", category:"transfer",  note:"Coffee reimbursement" },
      { id:"TXN-9817", type:"debit",  amount:200.00,  from:"Netflix MA",      date:"2026-04-05", category:"subscript",note:"Monthly subscription" },
      { id:"TXN-9816", type:"debit",  amount:450.00,  from:"Shell Station",   date:"2026-04-03", category:"transport",note:"Fuel" },
    ]
  },
  "aymane.elouafi": {
    password: "Elouafi@2025",
    name: "Aymane Elouafi",
    id: "ACC-002",
    avatar: "AE",
    balance: 8430.00,
    currency: "MAD",
    card: { number: "4916 •••• •••• 3342", full: "4916 5555 6666 3342", exp: "08/26", cvv: "193", type: "VISA", color: "#1b5e20" },
    iban: "MA64 0119 1080 2345 6789 1011 334",
    email: "a.elouafi@securebank.ma",
    phone: "+212 6 98 76 54 32",
    address: "7 Boulevard Zerktouni, Rabat",
    transactions: [
      { id:"TXN-8821", type:"credit", amount:4500.00, from:"ENSA Salary",      date:"2026-04-15", category:"salary",   note:"April 2026 Salary" },
      { id:"TXN-8820", type:"debit",  amount:300.00,  from:"Ayman Djioui",     date:"2026-04-09", category:"transfer",  note:"Coffee reimbursement" },
      { id:"TXN-8819", type:"debit",  amount:120.00,  from:"Spotify",          date:"2026-04-07", category:"subscript",note:"Premium Family" },
      { id:"TXN-8818", type:"credit", amount:1500.00, from:"Freelance Project",date:"2026-04-02", category:"income",   note:"Website development" },
      { id:"TXN-8817", type:"debit",  amount:680.00,  from:"Marjane Mall",     date:"2026-04-01", category:"shopping",  note:"Clothing" },
    ]
  },
  "badr.jakout": {
    password: "Jakout@2025",
    name: "Badr Jakout",
    id: "ACC-003",
    avatar: "BJ",
    balance: 22100.50,
    currency: "MAD",
    card: { number: "5399 •••• •••• 7761", full: "5399 3333 4444 7761", exp: "03/28", cvv: "882", type: "MASTERCARD", color: "#4a148c" },
    iban: "MA64 0119 1080 3456 7891 0112 558",
    email: "b.jakout@securebank.ma",
    phone: "+212 6 55 44 33 22",
    address: "23 Avenue Mohammed V, Fès",
    transactions: [
      { id:"TXN-7821", type:"credit", amount:8000.00, from:"Manager Salary",   date:"2026-04-15", category:"salary",   note:"April 2026 Salary" },
      { id:"TXN-7820", type:"debit",  amount:2500.00, from:"Toyota Morocco",   date:"2026-04-12", category:"transport",note:"Car installment" },
      { id:"TXN-7819", type:"debit",  amount:3200.00, from:"Real Estate Agency",date:"2026-04-11",category:"housing",   note:"Commercial property rent" },
      { id:"TXN-7818", type:"credit", amount:1200.00, from:"Amine Chaker",     date:"2026-04-08", category:"transfer",  note:"Project contribution" },
      { id:"TXN-7817", type:"debit",  amount:560.00,  from:"Zara Morocco",     date:"2026-04-06", category:"shopping",  note:"Shopping" },
    ]
  },
  "amine.chaker": {
    password: "Chaker@2025",
    name: "Amine Chaker",
    id: "ACC-004",
    avatar: "AC",
    balance: 5890.25,
    currency: "MAD",
    card: { number: "4532 •••• •••• 4471", full: "4532 7777 8888 4471", exp: "06/26", cvv: "305", type: "VISA", color: "#b71c1c" },
    iban: "MA64 0119 1080 4567 8910 1123 445",
    email: "a.chaker@securebank.ma",
    phone: "+212 6 11 22 33 44",
    address: "55 Rue de Paris, Marrakech",
    transactions: [
      { id:"TXN-6821", type:"credit", amount:3800.00, from:"ENSA Salary",       date:"2026-04-15", category:"salary",   note:"April 2026 Salary" },
      { id:"TXN-6820", type:"debit",  amount:1200.00, from:"Badr Jakout",        date:"2026-04-08", category:"transfer",  note:"Project contribution" },
      { id:"TXN-6819", type:"debit",  amount:250.00,  from:"General Practitioner",date:"2026-04-07",category:"health",   note:"Medical consultation" },
      { id:"TXN-6818", type:"credit", amount:500.00,  from:"CNSS Refund",        date:"2026-04-04", category:"income",   note:"Insurance reimbursement" },
      { id:"TXN-6817", type:"debit",  amount:180.00,  from:"Inwi Telecom",       date:"2026-04-02", category:"telecom",  note:"Phone bill" },
    ]
  },
  "admin": {
    password: "admin123",
    name: "Admin SecureBank",
    id: "ACC-000",
    avatar: "SB",
    balance: 999999.99,
    currency: "MAD",
    card: { number: "9999 •••• •••• 0000", full: "9999 0000 0000 0000", exp: "12/30", cvv: "000", type: "VISA", color: "#000" },
    iban: "MA64 0119 1080 0000 0000 0000 001",
    email: "admin@securebank.ma",
    phone: "+212 5 22 00 00 00",
    address: "27 Boulevard Anfa, Casablanca",
    transactions: []
  }
};

// map from ACC-ID → username for transfers
const accIdToUser = {};
Object.entries(accounts).forEach(([u, acc]) => { accIdToUser[acc.id] = u; });

// ══════════════════════════════════════════════════════════════
//  MIDDLEWARE
// ══════════════════════════════════════════════════════════════
app.use(cors());
app.use(express.json());
app.use(morgan("combined"));
app.use(express.static(path.join(__dirname, "public")));

// ── simple session store (token → username) ──────────────────
const sessions = {};
function mkToken(u){ const t = "tok-" + Date.now() + "-" + Math.random().toString(36).slice(2); sessions[t] = u; return t; }
function authMiddleware(req, res, next){
  const t = req.headers["authorization"]?.split(" ")[1];
  if (!t || !sessions[t]) return res.status(401).json({ error: "Unauthorized" });
  req.user = sessions[t];
  next();
}

// ══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  const acc = accounts[username];
  if (!acc || acc.password !== password) {
    console.warn(`[AUTH FAILED] user=${username} ip=${req.ip}`);
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }
  const token = mkToken(username);
  console.log(`[AUTH OK] user=${username} ip=${req.ip}`);
  const { password: _, ...safe } = acc;
  return res.json({ success: true, token, account: safe });
});

app.post("/api/auth/logout", authMiddleware, (req, res) => {
  const t = req.headers["authorization"].split(" ")[1];
  delete sessions[t];
  res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════
//  ACCOUNT ROUTES
// ══════════════════════════════════════════════════════════════

app.get("/api/account/me", authMiddleware, (req, res) => {
  const { password: _, ...safe } = accounts[req.user];
  res.json(safe);
});

app.get("/api/account/transactions", authMiddleware, (req, res) => {
  res.json({ transactions: accounts[req.user].transactions });
});

// ── Transfer money ───────────────────────────────────────────
app.post("/api/account/transfer", authMiddleware, (req, res) => {
  const { toIban, amount, note } = req.body;
  const sender = accounts[req.user];
  const amt    = parseFloat(amount);

  if (!toIban || !amt || amt <= 0)
    return res.status(400).json({ error: "Invalid data" });
  if (amt > sender.balance)
    return res.status(400).json({ error: "Insufficient balance" });

  // find recipient by IBAN
  const recipientEntry = Object.entries(accounts).find(([, a]) => a.iban === toIban.trim());
  if (!recipientEntry)
    return res.status(404).json({ error: "IBAN not found in our network" });

  const [recipientUser, recipient] = recipientEntry;

  // Execute transfer
  sender.balance   -= amt;
  recipient.balance += amt;

  const txId = "TXN-" + Math.floor(Math.random() * 90000 + 10000);
  const now  = new Date().toISOString().split("T")[0];

  sender.transactions.unshift({
    id: txId, type: "debit", amount: amt, from: recipient.name,
    date: now, category: "transfer", note: note || "Transfer"
  });
  recipient.transactions.unshift({
    id: txId + "R", type: "credit", amount: amt, from: sender.name,
    date: now, category: "transfer", note: note || "Transfer received"
  });

  console.log(`[TRANSFER] ${req.user} → ${recipientUser} amount=${amt} MAD`);
  res.json({ success: true, newBalance: sender.balance, txId });
});

// ══════════════════════════════════════════════════════════════
//  ⚠️  SSRF VULNERABILITY — Hidden as "Payment Verification"
//  This endpoint is intentionally vulnerable. It fetches any
//  URL the client provides without validation.
//  An attacker can use it to hit the AWS IMDS endpoint and
//  steal the server's IAM credentials.
// ══════════════════════════════════════════════════════════════
app.get("/api/payments/verify-gateway", authMiddleware, async (req, res) => {
  const { endpoint } = req.query;
  if (!endpoint)
    return res.status(400).json({ error: "Missing endpoint parameter" });

  console.log(`[PAY-VERIFY] user=${req.user} endpoint=${endpoint} ip=${req.ip}`);

  try {
    // ⚠️ NO VALIDATION — fetches any URL including internal metadata service
    const response = await axios.get(endpoint, { timeout: 5000 });
    return res.json({ success: true, status: "gateway_reachable", data: response.data });
  } catch (err) {
    return res.status(502).json({ success: false, status: "gateway_unreachable", error: err.message });
  }
});

// ── Health ───────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ status: "ok", uptime: process.uptime() }));

// ── SPA fallback ─────────────────────────────────────────────
app.get("*", (_, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅  SecureBank API  →  http://0.0.0.0:${PORT}`);
});
