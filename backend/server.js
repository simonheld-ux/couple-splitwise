"use strict";
const express   = require("express");
const cors      = require("cors");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const http      = require("http");
const WebSocket = require("ws");
const { Pool }  = require("pg");

const PORT       = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "csw-dev-secret-change-in-prod";
const SALT_ROUNDS = 10;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || undefined,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  host:     process.env.DATABASE_URL ? undefined : (process.env.DB_HOST     || "localhost"),
  port:     process.env.DATABASE_URL ? undefined : (process.env.DB_PORT     || 5432),
  database: process.env.DATABASE_URL ? undefined : (process.env.DB_NAME     || "csw"),
  user:     process.env.DATABASE_URL ? undefined : (process.env.DB_USER     || "postgres"),
  password: process.env.DATABASE_URL ? undefined : (process.env.DB_PASSWORD || ""),
});

const db = { query: (t,p) => pool.query(t,p) };

async function initSchema() {
  await db.query(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, avatar TEXT NOT NULL DEFAULT '🧑',
    email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
    couple_id TEXT, currency TEXT NOT NULL DEFAULT 'EUR',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
  )`);
  await db.query(`CREATE TABLE IF NOT EXISTS groups_table (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, icon TEXT NOT NULL DEFAULT '👥',
    color TEXT NOT NULL DEFAULT '#5bffc8', created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
  )`);
  await db.query(`CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL, user_id TEXT NOT NULL,
    joined_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT,
    PRIMARY KEY (group_id, user_id)
  )`);
  await db.query(`CREATE TABLE IF NOT EXISTS expenses (
    id TEXT PRIMARY KEY, description TEXT NOT NULL,
    amount NUMERIC(12,2) NOT NULL, paid_by TEXT NOT NULL,
    group_id TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'other',
    date TEXT NOT NULL, split_type TEXT NOT NULL DEFAULT 'equal',
    participants JSONB NOT NULL DEFAULT '[]', splits JSONB NOT NULL DEFAULT '{}',
    settled BOOLEAN NOT NULL DEFAULT FALSE, note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT,
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
  )`);
  await db.query(`CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, message TEXT NOT NULL,
    read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
  )`);
  await db.query(`CREATE TABLE IF NOT EXISTS joint_accounts (
    id TEXT PRIMARY KEY,
    couple_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    partner1_id TEXT NOT NULL,
    partner2_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
  )`);
  console.log("Schema ready");
}

const userSockets = new Map();

function broadcastToUsers(userIds, event, data) {
  const msg = JSON.stringify({ event, data });
  userIds.forEach(uid => {
    const sockets = userSockets.get(uid);
    if (sockets) sockets.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(msg); });
  });
}

async function broadcastToGroup(groupId, event, data, exclude) {
  const { rows } = await db.query("SELECT user_id FROM group_members WHERE group_id = $1", [groupId]);
  broadcastToUsers(rows.map(r=>r.user_id).filter(id=>id!==exclude), event, data);
}

function signToken(uid) { return jwt.sign({ sub: uid }, JWT_SECRET, { expiresIn: "30d" }); }

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "No token" });
  try { req.userId = jwt.verify(t, JWT_SECRET).sub; next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

function safeUser(u) {
  if (!u) return null;
  return { id:u.id, name:u.name, avatar:u.avatar, email:u.email, coupleId:u.couple_id||null, currency:u.currency||"EUR", createdAt:Number(u.created_at) };
}

function parseExp(e) {
  if (!e) return null;
  return {
    id:e.id, description:e.description, amount:parseFloat(e.amount),
    paidBy:e.paid_by, groupId:e.group_id, category:e.category, date:e.date,
    splitType:e.split_type,
    participants:Array.isArray(e.participants)?e.participants:JSON.parse(e.participants||"[]"),
    splits:typeof e.splits==="object"?e.splits:JSON.parse(e.splits||"{}"),
    settled:Boolean(e.settled), note:e.note||"",
    createdBy:e.created_by, createdAt:Number(e.created_at), updatedAt:Number(e.updated_at)
  };
}

async function getGroup(id) {
  const {rows:[g]} = await db.query("SELECT * FROM groups_table WHERE id=$1",[id]);
  if (!g) return null;
  const {rows:m} = await db.query("SELECT u.* FROM users u JOIN group_members gm ON u.id=gm.user_id WHERE gm.group_id=$1 ORDER BY gm.joined_at",[id]);
  return { id:g.id, name:g.name, icon:g.icon, color:g.color, createdBy:g.created_by, createdAt:Number(g.created_at), members:m.map(safeUser) };
}

const app = express();
app.use(cors({ origin:"*" }));
app.use(express.json());

// Auth
app.post("/api/auth/register", async (req,res)=>{
  try {
    const {name,email,password,avatar} = req.body;
    if (!name||!email||!password) return res.status(400).json({error:"name, email and password required"});
    if (password.length<6) return res.status(400).json({error:"Password must be at least 6 characters"});
    if (!email.includes("@")) return res.status(400).json({error:"Invalid email"});
    const {rows:[ex]} = await db.query("SELECT id FROM users WHERE LOWER(email)=LOWER($1)",[email]);
    if (ex) return res.status(409).json({error:"Email already registered"});
    const id=uuidv4(), now=Date.now(), hash=await bcrypt.hash(password,SALT_ROUNDS);
    await db.query("INSERT INTO users(id,name,avatar,email,password_hash,created_at) VALUES($1,$2,$3,$4,$5,$6)",
      [id,name.trim(),avatar||"🧑",email.toLowerCase(),hash,now]);
    const {rows:[u]} = await db.query("SELECT * FROM users WHERE id=$1",[id]);
    res.json({token:signToken(id),user:safeUser(u)});
  } catch(e){console.error("Register:",e.message);res.status(500).json({error:"Server error"});}
});

app.post("/api/auth/login", async (req,res)=>{
  try {
    const {email,password} = req.body;
    if (!email||!password) return res.status(400).json({error:"email and password required"});
    const {rows:[u]} = await db.query("SELECT * FROM users WHERE LOWER(email)=LOWER($1)",[email]);
    if (!u) return res.status(401).json({error:"Invalid email or password"});
    if (!await bcrypt.compare(password,u.password_hash)) return res.status(401).json({error:"Invalid email or password"});
    res.json({token:signToken(u.id),user:safeUser(u)});
  } catch(e){console.error("Login:",e.message);res.status(500).json({error:"Server error"});}
});

app.get("/api/auth/me", auth, async (req,res)=>{
  const {rows:[u]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  if (!u) return res.status(404).json({error:"Not found"});
  res.json({user:safeUser(u)});
});

// Users
app.get("/api/users/search", auth, async (req,res)=>{
  const q=(req.query.q||"").toLowerCase().trim();
  if (q.length<1) return res.json({users:[]});
  const {rows} = await db.query("SELECT * FROM users WHERE id!=$1 AND (LOWER(name) LIKE $2 OR LOWER(email) LIKE $2) LIMIT 20",[req.userId,`%${q}%`]);
  res.json({users:rows.map(safeUser)});
});

app.patch("/api/users/me", auth, async (req,res)=>{
  const {name,avatar,currency} = req.body;
  if (name) await db.query("UPDATE users SET name=$1 WHERE id=$2",[name.trim(),req.userId]);
  if (avatar) await db.query("UPDATE users SET avatar=$1 WHERE id=$2",[avatar,req.userId]);
  if (currency) await db.query("UPDATE users SET currency=$1 WHERE id=$2",[currency,req.userId]);
  const {rows:[u]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  const updated=safeUser(u);
  const {rows:myGroups} = await db.query("SELECT DISTINCT group_id FROM group_members WHERE user_id=$1",[req.userId]);
  for (const {group_id} of myGroups) await broadcastToGroup(group_id,"user_updated",{user:updated});
  res.json({user:updated});
});

app.post("/api/users/couple", auth, async (req,res)=>{
  const {partnerId} = req.body;
  if (!partnerId) return res.status(400).json({error:"partnerId required"});
  const {rows:[partner]} = await db.query("SELECT * FROM users WHERE id=$1",[partnerId]);
  if (!partner) return res.status(404).json({error:"User not found"});
  const coupleId=uuidv4(), now=Date.now();
  await db.query("UPDATE users SET couple_id=$1 WHERE id=ANY($2)",[coupleId,[req.userId,partnerId]]);
  const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  const nid=uuidv4();
  await db.query("INSERT INTO notifications(id,user_id,message,created_at) VALUES($1,$2,$3,$4)",[nid,partnerId,`${me.name} linked you as a couple 💑`,now]);
  broadcastToUsers([partnerId],"couple_linked",{coupleId,partner:safeUser(me)});
  broadcastToUsers([partnerId],"notification",{id:nid,message:`${me.name} linked you as a couple 💑`,read:false,createdAt:now});
  res.json({coupleId,me:safeUser(me),partner:safeUser(partner)});
});

app.delete("/api/users/couple", auth, async (req,res)=>{
  const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  if (me.couple_id) {
    const {rows:[p]} = await db.query("SELECT * FROM users WHERE couple_id=$1 AND id!=$2",[me.couple_id,req.userId]);
    await db.query("UPDATE users SET couple_id=NULL WHERE couple_id=$1",[me.couple_id]);
    if (p) broadcastToUsers([p.id],"couple_unlinked",{});
  }
  res.json({ok:true});
});

// Groups
app.get("/api/groups", auth, async (req,res)=>{
  const {rows} = await db.query("SELECT DISTINCT g.* FROM groups_table g JOIN group_members gm ON g.id=gm.group_id WHERE gm.user_id=$1 ORDER BY g.created_at DESC",[req.userId]);
  const groups = await Promise.all(rows.map(g=>getGroup(g.id)));
  res.json({groups});
});

app.post("/api/groups", auth, async (req,res)=>{
  const {name,icon,color,members} = req.body;
  if (!name) return res.status(400).json({error:"name required"});
  const allMembers=[...new Set([req.userId,...(members||[])])];
  const id=uuidv4(), now=Date.now();
  await db.query("INSERT INTO groups_table(id,name,icon,color,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6)",
    [id,name.trim(),icon||"👥",color||"#5bffc8",req.userId,now]);
  for (const uid of allMembers) await db.query("INSERT INTO group_members(group_id,user_id,joined_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",[id,uid,now]);
  const group=await getGroup(id);
  const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  for (const uid of allMembers.filter(u=>u!==req.userId)) {
    const nid=uuidv4();
    await db.query("INSERT INTO notifications(id,user_id,message,created_at) VALUES($1,$2,$3,$4)",[nid,uid,`${me.name} added you to the group "${name}"`,now]);
    broadcastToUsers([uid],"group_created",{group});
    broadcastToUsers([uid],"notification",{id:nid,message:`${me.name} added you to the group "${name}"`,read:false,createdAt:now});
  }
  res.json({group});
});

app.patch("/api/groups/:id", auth, async (req,res)=>{
  const gid=req.params.id;
  const {rows:[m]} = await db.query("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[gid,req.userId]);
  if (!m) return res.status(403).json({error:"Not a member"});
  const {name,icon,color,members} = req.body;
  const now=Date.now();
  if (name) await db.query("UPDATE groups_table SET name=$1 WHERE id=$2",[name.trim(),gid]);
  if (icon) await db.query("UPDATE groups_table SET icon=$1 WHERE id=$2",[icon,gid]);
  if (color) await db.query("UPDATE groups_table SET color=$1 WHERE id=$2",[color,gid]);
  if (members) {
    const all=[...new Set([req.userId,...members])];
    const {rows:ex} = await db.query("SELECT user_id FROM group_members WHERE group_id=$1",[gid]);
    const exIds=ex.map(r=>r.user_id);
    const newOnes=all.filter(u=>!exIds.includes(u));
    const removed=exIds.filter(u=>!all.includes(u)&&u!==req.userId);
    for (const u of newOnes) await db.query("INSERT INTO group_members(group_id,user_id,joined_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",[gid,u,now]);
    for (const u of removed) await db.query("DELETE FROM group_members WHERE group_id=$1 AND user_id=$2",[gid,u]);
    const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
    const {rows:[g2]} = await db.query("SELECT name FROM groups_table WHERE id=$1",[gid]);
    for (const u of newOnes.filter(x=>x!==req.userId)) {
      const nid=uuidv4();
      await db.query("INSERT INTO notifications(id,user_id,message,created_at) VALUES($1,$2,$3,$4)",[nid,u,`${me.name} added you to "${name||g2.name}"`,now]);
      broadcastToUsers([u],"notification",{id:nid,message:`${me.name} added you to "${name||g2.name}"`,read:false,createdAt:now});
    }
  }
  const group=await getGroup(gid);
  await broadcastToGroup(gid,"group_updated",{group},req.userId);
  res.json({group});
});

app.delete("/api/groups/:id", auth, async (req,res)=>{
  const {rows:[g]} = await db.query("SELECT * FROM groups_table WHERE id=$1 AND created_by=$2",[req.params.id,req.userId]);
  if (!g) return res.status(403).json({error:"Not owner"});
  await broadcastToGroup(req.params.id,"group_deleted",{groupId:req.params.id},req.userId);
  await db.query("DELETE FROM expenses WHERE group_id=$1",[req.params.id]);
  await db.query("DELETE FROM group_members WHERE group_id=$1",[req.params.id]);
  await db.query("DELETE FROM groups_table WHERE id=$1",[req.params.id]);
  res.json({ok:true});
});

// Expenses
app.get("/api/expenses", auth, async (req,res)=>{
  const {groupId} = req.query;
  let rows;
  if (groupId) {
    const {rows:[m]} = await db.query("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[groupId,req.userId]);
    if (!m) return res.status(403).json({error:"Not a member"});
    ({rows}=await db.query("SELECT * FROM expenses WHERE group_id=$1 ORDER BY date DESC, created_at DESC",[groupId]));
  } else {
    ({rows}=await db.query("SELECT DISTINCT e.* FROM expenses e JOIN group_members gm ON e.group_id=gm.group_id WHERE gm.user_id=$1 ORDER BY e.date DESC, e.created_at DESC",[req.userId]));
  }
  res.json({expenses:rows.map(parseExp)});
});

app.post("/api/expenses", auth, async (req,res)=>{
  const {description,amount,paidBy,groupId,category,date,splitType,participants,splits,note} = req.body;
  if (!description||!amount||!groupId) return res.status(400).json({error:"description, amount, groupId required"});
  const {rows:[m]} = await db.query("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[groupId,req.userId]);
  if (!m) return res.status(403).json({error:"Not a member"});
  const id=uuidv4(), now=Date.now();
  await db.query(
    "INSERT INTO expenses(id,description,amount,paid_by,group_id,category,date,split_type,participants,splits,settled,note,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,FALSE,$11,$12,$13,$14)",
    [id,description.trim(),amount,paidBy||req.userId,groupId,category||"other",date||new Date().toISOString().split("T")[0],splitType||"equal",JSON.stringify(participants||[]),JSON.stringify(splits||{}),note||"",req.userId,now,now]
  );
  const {rows:[e]} = await db.query("SELECT * FROM expenses WHERE id=$1",[id]);
  const expense=parseExp(e);
  await broadcastToGroup(groupId,"expense_created",{expense},req.userId);
  res.json({expense});
});

app.patch("/api/expenses/:id", auth, async (req,res)=>{
  const {rows:[e]} = await db.query("SELECT * FROM expenses WHERE id=$1",[req.params.id]);
  if (!e) return res.status(404).json({error:"Not found"});
  const {rows:[m]} = await db.query("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[e.group_id,req.userId]);
  if (!m) return res.status(403).json({error:"Not a member"});
  const now=Date.now();
  const {description,amount,paidBy,category,date,splitType,participants,splits,settled,note} = req.body;
  if (description!==undefined) await db.query("UPDATE expenses SET description=$1,updated_at=$2 WHERE id=$3",[description.trim(),now,req.params.id]);
  if (amount!==undefined)      await db.query("UPDATE expenses SET amount=$1,updated_at=$2 WHERE id=$3",[amount,now,req.params.id]);
  if (paidBy!==undefined)      await db.query("UPDATE expenses SET paid_by=$1,updated_at=$2 WHERE id=$3",[paidBy,now,req.params.id]);
  if (category!==undefined)    await db.query("UPDATE expenses SET category=$1,updated_at=$2 WHERE id=$3",[category,now,req.params.id]);
  if (date!==undefined)        await db.query("UPDATE expenses SET date=$1,updated_at=$2 WHERE id=$3",[date,now,req.params.id]);
  if (splitType!==undefined)   await db.query("UPDATE expenses SET split_type=$1,updated_at=$2 WHERE id=$3",[splitType,now,req.params.id]);
  if (participants!==undefined) await db.query("UPDATE expenses SET participants=$1,updated_at=$2 WHERE id=$3",[JSON.stringify(participants),now,req.params.id]);
  if (splits!==undefined)      await db.query("UPDATE expenses SET splits=$1,updated_at=$2 WHERE id=$3",[JSON.stringify(splits),now,req.params.id]);
  if (settled!==undefined)     await db.query("UPDATE expenses SET settled=$1,updated_at=$2 WHERE id=$3",[settled,now,req.params.id]);
  if (note!==undefined)        await db.query("UPDATE expenses SET note=$1,updated_at=$2 WHERE id=$3",[note,now,req.params.id]);
  const {rows:[updated]} = await db.query("SELECT * FROM expenses WHERE id=$1",[req.params.id]);
  const expense=parseExp(updated);
  await broadcastToGroup(e.group_id,"expense_updated",{expense},req.userId);
  res.json({expense});
});

app.delete("/api/expenses/:id", auth, async (req,res)=>{
  const {rows:[e]} = await db.query("SELECT * FROM expenses WHERE id=$1",[req.params.id]);
  if (!e) return res.status(404).json({error:"Not found"});
  const {rows:[m]} = await db.query("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[e.group_id,req.userId]);
  if (!m) return res.status(403).json({error:"Not a member"});
  await broadcastToGroup(e.group_id,"expense_deleted",{expenseId:req.params.id,groupId:e.group_id},req.userId);
  await db.query("DELETE FROM expenses WHERE id=$1",[req.params.id]);
  res.json({ok:true});
});

app.post("/api/expenses/settle-batch", auth, async (req,res)=>{
  const {debts} = req.body;
  if (!Array.isArray(debts)) return res.status(400).json({error:"debts array required"});
  const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  const affected=new Set(), now=Date.now();
  for (const d of debts) {
    // d.to may be a user id or a joint account id (ja_...)
    const isJA = d.to && d.to.startsWith("ja_");
    const {rows:exps} = await db.query("SELECT * FROM expenses WHERE settled=FALSE AND paid_by=$1",[d.to]);
    for (const e of exps) {
      const splits=typeof e.splits==="object"?e.splits:JSON.parse(e.splits||"{}");
      if (splits[d.from]!=null) { await db.query("UPDATE expenses SET settled=TRUE,updated_at=$1 WHERE id=$2",[now,e.id]); affected.add(e.group_id); }
    }
    if (isJA) {
      // notify both partners of the joint account
      const {rows:[ja]} = await db.query("SELECT * FROM joint_accounts WHERE id=$1",[d.to]);
      if (ja) {
        const msg=`${me.name} settled ${ja.name} debt`;
        for (const pid of [ja.partner1_id,ja.partner2_id].filter(p=>p!==req.userId)) {
          const nid=uuidv4();
          await db.query("INSERT INTO notifications(id,user_id,message,created_at) VALUES($1,$2,$3,$4)",[nid,pid,msg,now]);
          broadcastToUsers([pid],"notification",{id:nid,message:msg,read:false,createdAt:now});
        }
      }
    } else if (d.to!==req.userId) {
      const nid=uuidv4(), msg=`${me.name} settled a debt with you`;
      await db.query("INSERT INTO notifications(id,user_id,message,created_at) VALUES($1,$2,$3,$4)",[nid,d.to,msg,now]);
      broadcastToUsers([d.to],"notification",{id:nid,message:msg,read:false,createdAt:now});
    }
  }
  for (const gid of affected) {
    const {rows} = await db.query("SELECT * FROM expenses WHERE group_id=$1",[gid]);
    await broadcastToGroup(gid,"expenses_batch_updated",{groupId:gid,expenses:rows.map(parseExp)});
  }
  res.json({ok:true});
});


// Joint Accounts
app.get("/api/joint-accounts/mine", auth, async (req,res)=>{
  const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  if (!me.couple_id) return res.json({account:null});
  const {rows:[ja]} = await db.query("SELECT * FROM joint_accounts WHERE couple_id=$1",[me.couple_id]);
  res.json({account:ja?{id:ja.id,coupleId:ja.couple_id,name:ja.name,partner1Id:ja.partner1_id,partner2Id:ja.partner2_id,createdAt:Number(ja.created_at)}:null});
});

app.post("/api/joint-accounts", auth, async (req,res)=>{
  const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  if (!me.couple_id) return res.status(400).json({error:"You must be linked as a couple first"});
  const {rows:[existing]} = await db.query("SELECT id FROM joint_accounts WHERE couple_id=$1",[me.couple_id]);
  if (existing) return res.status(409).json({error:"Joint account already exists"});
  const {rows:[partner]} = await db.query("SELECT * FROM users WHERE couple_id=$1 AND id!=$2",[me.couple_id,req.userId]);
  if (!partner) return res.status(400).json({error:"Partner not found"});
  const id="ja_"+uuidv4(), now=Date.now();
  const name=`${me.name} & ${partner.name}`;
  await db.query("INSERT INTO joint_accounts(id,couple_id,name,partner1_id,partner2_id,created_at) VALUES($1,$2,$3,$4,$5,$6)",
    [id,me.couple_id,name,req.userId,partner.id,now]);
  const account={id,coupleId:me.couple_id,name,partner1Id:req.userId,partner2Id:partner.id,createdAt:now};
  // Notify partner
  const nid=uuidv4();
  await db.query("INSERT INTO notifications(id,user_id,message,created_at) VALUES($1,$2,$3,$4)",[nid,partner.id,`${me.name} created your joint account 💳`,now]);
  broadcastToUsers([partner.id],"joint_account_created",{account});
  broadcastToUsers([partner.id],"notification",{id:nid,message:`${me.name} created your joint account 💳`,read:false,createdAt:now});
  res.json({account});
});

app.delete("/api/joint-accounts/mine", auth, async (req,res)=>{
  const {rows:[me]} = await db.query("SELECT * FROM users WHERE id=$1",[req.userId]);
  if (!me.couple_id) return res.status(400).json({error:"Not in a couple"});
  await db.query("DELETE FROM joint_accounts WHERE couple_id=$1",[me.couple_id]);
  const {rows:[partner]} = await db.query("SELECT * FROM users WHERE couple_id=$1 AND id!=$2",[me.couple_id,req.userId]);
  if (partner) broadcastToUsers([partner.id],"joint_account_deleted",{});
  res.json({ok:true});
});

// Notifications
app.get("/api/notifications", auth, async (req,res)=>{
  const {rows} = await db.query("SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50",[req.userId]);
  res.json({notifications:rows.map(n=>({id:n.id,message:n.message,read:Boolean(n.read),createdAt:Number(n.created_at)}))});
});

app.post("/api/notifications/read-all", auth, async (req,res)=>{
  await db.query("UPDATE notifications SET read=TRUE WHERE user_id=$1",[req.userId]);
  res.json({ok:true});
});


// TEMPORARY DEBUG ENDPOINT - remove after investigation
app.get("/api/debug/data", async (req,res)=>{
  try {
    const {rows:users} = await db.query("SELECT id, name, email, couple_id FROM users ORDER BY created_at");
    const {rows:jas} = await db.query("SELECT * FROM joint_accounts");
    res.json({ users, joint_accounts: jas });
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get("/api/health", async (req,res)=>{
  try { await db.query("SELECT 1"); res.json({ok:true,ts:Date.now(),db:"connected"}); }
  catch(e) { res.status(503).json({ok:false,error:e.message}); }
});

// Start
async function start() {
  for (let i=0;i<10;i++) {
    try { await db.query("SELECT 1"); console.log("Database connected"); break; }
    catch(e) { console.log(`Waiting for DB... (${i+1}/10): ${e.message}`); await new Promise(r=>setTimeout(r,2000)); }
  }
  await initSchema();
  const server=http.createServer(app);
  const wss=new WebSocket.Server({server,path:"/ws"});
  wss.on("connection",ws=>{
    let uid=null;
    ws.on("message",raw=>{
      try {
        const msg=JSON.parse(raw);
        if (msg.type==="auth") {
          try {
            uid=jwt.verify(msg.token,JWT_SECRET).sub;
            if (!userSockets.has(uid)) userSockets.set(uid,new Set());
            userSockets.get(uid).add(ws);
            ws.send(JSON.stringify({event:"auth_ok",data:{userId:uid}}));
          } catch { ws.send(JSON.stringify({event:"auth_error",data:{}})); }
        } else if (msg.type==="ping") ws.send(JSON.stringify({event:"pong"}));
      } catch {}
    });
    ws.on("close",()=>{ if (uid&&userSockets.has(uid)) { userSockets.get(uid).delete(ws); if (!userSockets.get(uid).size) userSockets.delete(uid); } });
    ws.on("error",()=>{});
  });
  server.listen(PORT,"0.0.0.0",()=>{
    console.log(`\nCouple SplitWise API running on port ${PORT}`);
    console.log(`WebSocket on ws://0.0.0.0:${PORT}/ws`);
  });
}

start().catch(e=>{console.error("Fatal:",e);process.exit(1);});

// Get all joint accounts relevant to a group
app.get("/api/joint-accounts/group/:groupId", auth, async (req,res)=>{
  const {groupId} = req.params;
  const {rows:[m]} = await db.query("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[groupId,req.userId]);
  if (!m) return res.status(403).json({error:"Not a member"});
  // Find all couple_ids in this group
  const {rows:members} = await db.query("SELECT couple_id FROM users WHERE id IN (SELECT user_id FROM group_members WHERE group_id=$1) AND couple_id IS NOT NULL",[groupId]);
  const coupleIds=[...new Set(members.map(r=>r.couple_id))];
  if (coupleIds.length===0) return res.json({accounts:[]});
  const placeholders=coupleIds.map((_,i)=>`$${i+1}`).join(',');
  const {rows:accounts} = await db.query(`SELECT * FROM joint_accounts WHERE couple_id IN (${placeholders})`,coupleIds);
  res.json({accounts:accounts.map(a=>({id:a.id,coupleId:a.couple_id,name:a.name,partner1Id:a.partner1_id,partner2Id:a.partner2_id}))});
});
