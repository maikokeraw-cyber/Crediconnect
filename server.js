// ================================================================
//  Credinova v4.8 — Express + PostgreSQL Server
// ================================================================

require('dotenv').config();
const express   = require('express');
const { Pool }  = require('pg');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const path      = require('path');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app         = express();
const PORT        = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'crediconnect-dev-secret-change-in-production';
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '8h';

app.use(cors());

// ── Rate Limiters ────────────────────────────────────────────────
// Login: max 5 attempts per IP per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max: 5,
  message: { error: 'Too many login attempts. Please wait 15 minutes and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // only count failed attempts
});

// General API: max 200 requests per IP per minute (prevents scraping)
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,         // 1 minute
  max: 200,
  message: { error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(express.json({ limit: '10mb' }));
// Serve static files — no cache on HTML so updates always load fresh
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// Apply general rate limit to all API routes
app.use('/api', apiLimiter);

// ── PostgreSQL Pool ──────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => console.error('PostgreSQL pool error:', err.message));

let dbConnected = false;
(async () => {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    dbConnected = true;
    console.log('✅  PostgreSQL connected');
  } catch (err) {
    console.warn('⚠️  PostgreSQL connection failed:', err.message);
  }
})();

// ── Middleware ───────────────────────────────────────────────────
function requireDB(req, res, next) {
  if (!dbConnected) return res.status(503).json({ error: 'Database not connected', offline: true });
  next();
}

async function requireAuth(req, res, next) {
  const h = req.headers['authorization'];
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    // If JWT was issued before branchId was added (old token), fetch it from DB now
    if (!req.user.branchId && !req.user.branch_id && req.user.role !== 'super_admin') {
      try {
        const { rows } = await pool.query(
          'SELECT branch_id FROM users WHERE id=$1 AND active=true', [req.user.id]
        );
        req.user.branchId = rows[0]?.branch_id || null;
        req.user.branch_id = req.user.branchId;
      } catch(e) { /* pool may not be ready, continue without branch */ }
    }
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalid or expired' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    // super_admin bypasses all role checks
    if (req.user?.role === 'super_admin') { next(); return; }
    if (!roles.includes(req.user?.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

// Returns branch filter clause for SQL queries
// super_admin can pass ?branch=id to filter, or gets all
// other roles always see only their branch
function getBranchFilter(user, query) {
  if (user.role === 'super_admin') {
    const b = query?.branch;
    return b ? { value: b } : { value: null };
  }
  // Non-super-admin: ALWAYS filter by their own branch from JWT
  // Never trust query params — always use token branch
  const branchId = user.branchId || user.branch_id;
  if (!branchId) {
    // No branch assigned — return impossible condition so they see nothing
    // This prevents accidental exposure of all data
    return { value: 'NO_BRANCH_ASSIGNED' };
  }
  return { value: branchId };
}

async function audit(userId, username, action, entity, entityId, detail, branchId) {
  try {
    await pool.query(
      `INSERT INTO audit_log (user_id, username, branch_id, action, entity, entity_id, detail)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [userId||null, username||null, branchId||null, action, entity||null, entityId||null, detail||null]
    );
  } catch (_) {}
}

// ── Row mappers ──────────────────────────────────────────────────
const mapClient = r => ({ id:r.id, name:r.name, phone:r.phone, nationalId:r.national_id||'', email:r.email||'', address:r.address||'', occupation:r.occupation||'', dob:r.dob?r.dob.toISOString().slice(0,10):'', dateAdded:r.date_added?r.date_added.toISOString().slice(0,10):'', addedBy:r.added_by||'', branchId:r.branch_id||'' });
const mapLoan = (r, totalPaid) => {
  const amount      = Number(r.amount);
  const rate        = Number(r.interest_rate);
  const totalOwed   = amount + amount * rate / 100;
  const paid        = totalPaid !== undefined ? totalPaid : Number(r.total_paid || 0);
  let computedStatus = r.status || 'active';
  if (computedStatus !== 'defaulted') {
    computedStatus = paid >= totalOwed - 0.005 ? 'completed' : 'active';
  }
  return {
    id: r.id, clientId: r.client_id, amount, interestRate: rate,
    term: Number(r.term), termFrequency: r.term_frequency || 'monthly',
    startDate: r.start_date ? r.start_date.toISOString().slice(0,10) : '',
    purpose: r.purpose || '', notes: r.notes || '',
    adminFees: Number(r.admin_fees || 0),
    adminFeesStatus: r.admin_fees_status || 'none',
    status: computedStatus, addedBy: r.added_by || '', branchId: r.branch_id || '',
    repaymentStartDate: r.repayment_start_date ? r.repayment_start_date.toISOString().slice(0,10) : ''
  };
};
const mapAdminFee = r => ({ id:r.id, loanId:r.loan_id, amount:Number(r.amount), date:r.date?r.date.toISOString().slice(0,10):'', notes:r.notes||'', addedBy:r.added_by||'' });
const mapRepay  = r => ({ id:r.id, loanId:r.loan_id, amount:Number(r.amount), date:r.date?r.date.toISOString().slice(0,10):'', notes:r.notes||'', addedBy:r.added_by||'' });
const mapExp    = r => ({ id:r.id, amount:Number(r.amount), category:r.category||'', description:r.description||'', date:r.date?r.date.toISOString().slice(0,10):'', addedBy:r.added_by||'', branchId:r.branch_id||'' });

// ================================================================
//  BRANCHES
// ================================================================
app.get('/api/branches', requireAuth, requireDB, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM branches ORDER BY name ASC');
    res.json(rows.map(b => ({ id:b.id, name:b.name, active:b.active, createdAt:b.created_at })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/branches', requireAuth, requireDB, requireRole('super_admin'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Branch name required' });
    const id = uuidv4();
    await pool.query('INSERT INTO branches (id,name) VALUES ($1,$2)', [id, name]);
    await audit(req.user.id, req.user.username, 'CREATE_BRANCH', 'Branch', id, `Created branch ${name}`);
    res.status(201).json({ id, name, active: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/branches/:id', requireAuth, requireDB, requireRole('super_admin'), async (req, res) => {
  try {
    const { name, active } = req.body;
    await pool.query('UPDATE branches SET name=$1,active=$2 WHERE id=$3', [name, active !== false, req.params.id]);
    await audit(req.user.id, req.user.username, 'UPDATE_BRANCH', 'Branch', req.params.id, `Updated to ${name}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Transfer client to another branch
app.put('/api/clients/:id/branch', requireAuth, requireDB, requireRole('super_admin'), async (req, res) => {
  try {
    const { branchId } = req.body;
    if (!branchId) return res.status(400).json({ error: 'branchId required' });
    await pool.query('UPDATE clients SET branch_id=$1,updated_at=NOW() WHERE id=$2', [branchId, req.params.id]);
    // Also transfer all their loans and expenses to new branch
    await pool.query('UPDATE loans SET branch_id=$1,updated_at=NOW() WHERE client_id=$2', [branchId, req.params.id]);
    await audit(req.user.id, req.user.username, 'TRANSFER_CLIENT', 'Client', req.params.id, `Transferred to branch ${branchId}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  STATUS
// ================================================================
app.get('/api/status', (req, res) => {
  res.json({ connected: dbConnected, timestamp: new Date().toISOString() });
});

// ================================================================
//  AUTH
// ================================================================
app.post('/api/auth/login', loginLimiter, requireDB, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const { rows } = await pool.query('SELECT * FROM users WHERE LOWER(username)=$1 AND active=TRUE', [username.toLowerCase().trim()]);
    const user = rows[0];
    if (!user || !await bcrypt.compare(password, user.password_hash))
      return res.status(401).json({ error: 'Invalid username or password' });
    await pool.query('UPDATE users SET last_login=NOW() WHERE id=$1', [user.id]);
    await audit(user.id, user.username, 'LOGIN', 'User', user.id, 'Signed in');
    const token = jwt.sign(
      { id:user.id, username:user.username, fullName:user.full_name, role:user.role, branchId:user.branch_id||null },
      JWT_SECRET, { expiresIn: JWT_EXPIRES }
    );
    res.json({ token, user: { id:user.id, username:user.username, fullName:user.full_name, role:user.role, branchId:user.branch_id||null } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/me', requireAuth, requireDB, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id,username,full_name,role,last_login FROM users WHERE id=$1 AND active=TRUE', [req.user.id]);
    if (!rows.length) return res.status(401).json({ error: 'User not found' });
    const u = rows[0];
    res.json({ id:u.id, username:u.username, fullName:u.full_name, role:u.role, branchId:u.branch_id||null, lastLogin:u.last_login });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/verify', (req, res) => {
  const h = req.headers['authorization'];
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ valid: false });
  try { res.json({ valid: true, user: jwt.verify(h.slice(7), JWT_SECRET) }); }
  catch (e) { res.status(401).json({ valid: false, error: 'Token expired' }); }
});

app.post('/api/auth/change-password', requireAuth, requireDB, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!rows[0] || !await bcrypt.compare(currentPassword, rows[0].password_hash))
      return res.status(400).json({ error: 'Current password is incorrect' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(newPassword, 10), req.user.id]);
    await audit(req.user.id, req.user.username, 'CHANGE_PASSWORD', 'User', req.user.id, '');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  USERS
// ================================================================
app.get('/api/users', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT u.id,u.username,u.full_name,u.role,u.branch_id,u.active,u.last_login,u.created_at,b.name as branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id ORDER BY u.created_at DESC`);
    res.json(rows.map(u => ({ id:u.id, username:u.username, fullName:u.full_name, role:u.role, branchId:u.branch_id||null, branchName:u.branch_name||null, active:u.active, lastLogin:u.last_login, createdAt:u.created_at })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const { username, fullName, role, password, branchId } = req.body;
    if (!username || !fullName || !role || !password) return res.status(400).json({ error: 'All fields required' });
    if (role !== 'super_admin' && !branchId) return res.status(400).json({ error: 'Branch is required for non-super-admin users' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const exists = await pool.query('SELECT 1 FROM users WHERE LOWER(username)=$1', [username.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: 'Username already exists' });
    const id = uuidv4();
    await pool.query(
      `INSERT INTO users (id,username,full_name,role,branch_id,password_hash,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, username.toLowerCase().trim(), fullName, role, branchId||null, await bcrypt.hash(password, 10), req.user.id]
    );
    await audit(req.user.id, req.user.username, 'CREATE_USER', 'User', id, `Created ${username} role=${role}`);
    res.status(201).json({ id, username: username.toLowerCase(), fullName, role, active: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const { fullName, role, active, password, branchId } = req.body;
    if (req.params.id === req.user.id && active === false) return res.status(400).json({ error: 'Cannot deactivate your own account' });
    if (password) {
      if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      await pool.query('UPDATE users SET full_name=$1,role=$2,active=$3,branch_id=$4,password_hash=$5 WHERE id=$6', [fullName, role, active !== false, branchId||null, await bcrypt.hash(password, 10), req.params.id]);
    } else {
      await pool.query('UPDATE users SET full_name=$1,role=$2,active=$3,branch_id=$4 WHERE id=$5', [fullName, role, active !== false, branchId||null, req.params.id]);
    }
    await audit(req.user.id, req.user.username, 'UPDATE_USER', 'User', req.params.id, `role=${role} active=${active}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    await audit(req.user.id, req.user.username, 'DELETE_USER', 'User', req.params.id, '');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  CLIENTS
// ================================================================
app.get('/api/clients', requireAuth, requireDB, async (req, res) => {
  try {
    const bf = getBranchFilter(req.user, req.query);
    const qry = bf.value
      ? 'SELECT * FROM clients WHERE branch_id=$1 ORDER BY date_added DESC'
      : 'SELECT * FROM clients ORDER BY date_added DESC';
    const { rows } = await pool.query(qry, bf.value ? [bf.value] : []);
    res.json(rows.map(mapClient));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/clients', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { name, phone, nationalId, email, address, occupation, dob, dateAdded, branchId } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });
    const id = uuidv4();
    // Use provided branchId, or user's branch, or null for super_admin with no selection
    const clientBranch = branchId || req.user.branchId || req.user.branch_id || null;
    await pool.query(
      `INSERT INTO clients (id,name,phone,national_id,email,address,occupation,dob,date_added,branch_id,added_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [id, name, phone, nationalId||null, email||null, address||null, occupation||null, dob||null, dateAdded||new Date(), clientBranch, req.user.id]
    );
    await audit(req.user.id, req.user.username, 'ADD_CLIENT', 'Client', id, `Added ${name}`);
    const { rows } = await pool.query('SELECT * FROM clients WHERE id=$1', [id]);
    res.status(201).json(mapClient(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/clients/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM clients WHERE id=$1', [req.params.id]);
    await audit(req.user.id, req.user.username, 'DELETE_CLIENT', 'Client', req.params.id, '');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/clients/:id', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { name, phone, nationalId, email, address, occupation, dob } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });
    await pool.query(
      `UPDATE clients SET name=$1,phone=$2,national_id=$3,email=$4,address=$5,occupation=$6,dob=$7,updated_at=NOW() WHERE id=$8`,
      [name, phone, nationalId||null, email||null, address||null, occupation||null, dob||null, req.params.id]
    );
    await audit(req.user.id, req.user.username, 'EDIT_CLIENT', 'Client', req.params.id, `Updated ${name}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  LOANS
// ================================================================
app.get('/api/loans', requireAuth, requireDB, async (req, res) => {
  try {
    const bfL = getBranchFilter(req.user, req.query);
    const branchWhere  = bfL.value ? 'WHERE l.branch_id=$1' : '';
    const branchParams = bfL.value ? [bfL.value] : [];
    // Join with repayments to calculate actual paid amount per loan
    // This ensures status is always correct regardless of what is stored
    const { rows } = await pool.query(`
      SELECT l.*,
        COALESCE(p.total_paid, 0) AS total_paid
      FROM loans l
      LEFT JOIN (
        SELECT loan_id, SUM(amount) AS total_paid
        FROM repayments
        GROUP BY loan_id
      ) p ON p.loan_id = l.id
      ${branchWhere}
      ORDER BY l.start_date DESC
    `, branchParams);
    // Also fix any wrong statuses in DB silently in the background
    const fixes = rows.filter(r => {
      if (r.status === 'defaulted') return false;
      const owed = Number(r.amount) + Number(r.amount) * Number(r.interest_rate) / 100;
      const paid = Number(r.total_paid || 0);
      const shouldBeCompleted = paid >= owed - 0.005;
      return (shouldBeCompleted && r.status !== 'completed') ||
             (!shouldBeCompleted && r.status === 'completed');
    });
    if (fixes.length > 0) {
      for (const r of fixes) {
        const owed = Number(r.amount) + Number(r.amount) * Number(r.interest_rate) / 100;
        const paid = Number(r.total_paid || 0);
        const correctStatus = paid >= owed - 0.005 ? 'completed' : 'active';
        pool.query("UPDATE loans SET status=$1,updated_at=NOW() WHERE id=$2", [correctStatus, r.id]).catch(()=>{});
      }
      console.log(`✅ Auto-corrected status for ${fixes.length} loan(s)`);
    }
    res.json(rows.map(r => mapLoan(r, Number(r.total_paid || 0))));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/loans', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { clientId, amount, interestRate, term, termFrequency, startDate, repaymentStartDate, purpose, notes, adminFees, adminFeesPaid, branchId } = req.body;
    if (!clientId || !amount || !interestRate || !term || !startDate) return res.status(400).json({ error: 'Missing required fields' });
    const id = uuidv4();
    const adminFeesStatus = adminFees > 0 ? 'paid' : 'none'; // Always retained at disbursement
    await pool.query(
      `INSERT INTO loans (id,client_id,amount,interest_rate,term,term_frequency,start_date,repayment_start_date,purpose,notes,admin_fees,admin_fees_status,branch_id,added_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [id, clientId, amount, interestRate, term, termFrequency||'monthly', startDate, repaymentStartDate||null, purpose||null, notes||null, adminFees||0, adminFeesStatus, branchId||req.user.branchId||req.user.branch_id||null, req.user.id]
    );
    // Always record admin fee as retained at disbursement
    if (adminFees > 0) {
      await pool.query(
        `INSERT INTO admin_fee_payments (id,loan_id,amount,date,notes,added_by) VALUES ($1,$2,$3,$4,$5,$6)`,
        [uuidv4(), id, adminFees, startDate, 'Deducted at disbursement', req.user.id]
      );
    }
    await audit(req.user.id, req.user.username, 'DISBURSE_LOAN', 'Loan', id, `$${amount} to ${clientId}${adminFees>0?' +$'+adminFees+' admin fee ('+adminFeesStatus+')':''}`);
    const { rows } = await pool.query('SELECT * FROM loans WHERE id=$1', [id]);
    res.status(201).json(mapLoan(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/loans/:id', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { amount, interestRate, term, termFrequency, startDate, status, purpose, adminFees, notes } = req.body;
    if(amount){
      // Full edit (admin)
      await pool.query(
        `UPDATE loans SET amount=$1,interest_rate=$2,term=$3,term_frequency=$4,start_date=$5,
         status=$6,purpose=$7,admin_fees=$8,notes=$9,updated_at=NOW() WHERE id=$10`,
        [amount, interestRate||0, term||1, termFrequency||'monthly',
         startDate, status||'active', purpose||null, adminFees||0, notes||null, req.params.id]
      );
      await audit(req.user.id, req.user.username, 'EDIT_LOAN', 'Loan', req.params.id, `Edited loan $${amount}`);
    } else {
      // Status/notes update only
      await pool.query('UPDATE loans SET status=$1,notes=$2,updated_at=NOW() WHERE id=$3', [status, notes||null, req.params.id]);
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/loans/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM loans WHERE id=$1', [req.params.id]);
    await audit(req.user.id, req.user.username, 'DELETE_LOAN', 'Loan', req.params.id, '');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  REPAYMENTS
// ================================================================
app.get('/api/repayments', requireAuth, requireDB, async (req, res) => {
  try {
    const bfR = getBranchFilter(req.user, req.query);
    const qry = bfR.value
      ? 'SELECT r.* FROM repayments r JOIN loans l ON l.id=r.loan_id WHERE l.branch_id=$1 ORDER BY r.date DESC'
      : 'SELECT r.* FROM repayments r ORDER BY r.date DESC';
    const { rows } = await pool.query(qry, bfR.value ? [bfR.value] : []);
    res.json(rows.map(mapRepay));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/repayments', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { loanId, amount, date, notes } = req.body;
    if (!loanId || !amount || !date) return res.status(400).json({ error: 'loanId, amount and date required' });
    const id = uuidv4();
    await pool.query(
      `INSERT INTO repayments (id,loan_id,amount,date,notes,added_by) VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, loanId, amount, date, notes||null, req.user.id]
    );
    // Recalculate status — defaulted loans revert to active when caught up
    const loanRes = await pool.query('SELECT * FROM loans WHERE id=$1', [loanId]);
    const loan    = loanRes.rows[0];
    if (loan) {
      const totalOwed   = Number(loan.amount) + Number(loan.amount) * Number(loan.interest_rate) / 100;
      const paidRes     = await pool.query('SELECT COALESCE(SUM(amount),0) AS paid FROM repayments WHERE loan_id=$1', [loanId]);
      const totalPaid   = Number(paidRes.rows[0].paid);
      // Check if overdue based on amortisation schedule
      const startDate   = new Date(loan.start_date);
      const repayStart  = loan.repayment_start_date ? new Date(loan.repayment_start_date) : null;
      const baseDate    = repayStart || startDate;
      const freq        = loan.term_frequency || 'monthly';
      const term        = Number(loan.term);
      const periodicPay = totalOwed / term;
      let duePeriods    = 0;
      const skipSun     = (d) => { if(d.getDay()===0) d.setDate(d.getDate()+1); return d; };
      // Zimbabwe time UTC+2
      const nowZW       = new Date(new Date().getTime() + 2*60*60*1000);
      const todayZWStr  = nowZW.toISOString().slice(0,10);

      if(freq === 'daily'){
        // Daily: step day by day, skip Sundays
        const cursor = new Date(baseDate);
        if(!repayStart) cursor.setDate(cursor.getDate()+1);
        for(let i=1; i<=term; i++){
          if(i>1) cursor.setDate(cursor.getDate()+1);
          while(cursor.getDay()===0) cursor.setDate(cursor.getDate()+1);
          if(cursor.toISOString().slice(0,10) < todayZWStr) duePeriods++;
        }
      } else {
        for(let i=1; i<=term; i++){
          const due = new Date(baseDate);
          if(repayStart){
            if(freq==='monthly') due.setMonth(due.getMonth()+(i-1));
            else                 due.setDate(due.getDate()+((i-1)*7));
          } else {
            if(freq==='monthly') due.setMonth(due.getMonth()+i);
            else                 due.setDate(due.getDate()+(i*7));
          }
          skipSun(due);
          if(due.toISOString().slice(0,10) < todayZWStr) duePeriods++;
        }
      }
      const isOverdue = duePeriods > 0 && totalPaid < (duePeriods * periodicPay) - 0.005;
      let newStatus;
      if(totalPaid >= totalOwed - 0.005) newStatus = 'completed';
      else if(isOverdue)                  newStatus = 'defaulted';
      else                                newStatus = 'active';
      if(newStatus !== loan.status){
        await pool.query('UPDATE loans SET status=$1,updated_at=NOW() WHERE id=$2', [newStatus, loanId]);
      }
    }
    await audit(req.user.id, req.user.username, 'RECORD_REPAYMENT', 'Repayment', id, `$${amount} for loan ${loanId}`);
    const { rows } = await pool.query('SELECT * FROM repayments WHERE id=$1', [id]);
    res.status(201).json(mapRepay(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/repayments/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const { amount, date, notes } = req.body;
    if(!amount||!date) return res.status(400).json({ error: 'amount and date required' });
    await pool.query('UPDATE repayments SET amount=$1,date=$2,notes=$3 WHERE id=$4',
      [amount, date, notes||null, req.params.id]);
    // Recalculate loan status after edit
    const repRes = await pool.query('SELECT loan_id FROM repayments WHERE id=$1', [req.params.id]);
    const loanId = repRes.rows[0]?.loan_id;
    if(loanId){
      const loanRes = await pool.query('SELECT * FROM loans WHERE id=$1', [loanId]);
      const loan = loanRes.rows[0];
      if(loan && loan.status !== 'defaulted'){
        const totalOwed = Number(loan.amount) + Number(loan.amount) * Number(loan.interest_rate) / 100;
        const paidRes  = await pool.query('SELECT COALESCE(SUM(amount),0) AS paid FROM repayments WHERE loan_id=$1', [loanId]);
        const paid     = Number(paidRes.rows[0].paid);
        const newStatus= paid >= totalOwed - 0.005 ? 'completed' : 'active';
        if(newStatus !== loan.status)
          await pool.query('UPDATE loans SET status=$1,updated_at=NOW() WHERE id=$2', [newStatus, loanId]);
      }
    }
    await audit(req.user.id, req.user.username, 'EDIT_REPAYMENT', 'Repayment', req.params.id, `Updated to $${amount}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/repayments/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    // Get loan id before deleting
    const repRes = await pool.query('SELECT loan_id FROM repayments WHERE id=$1', [req.params.id]);
    const loanId = repRes.rows[0]?.loan_id;
    await pool.query('DELETE FROM repayments WHERE id=$1', [req.params.id]);
    // Recalculate loan status after deletion
    if (loanId) {
      const loanRes = await pool.query('SELECT * FROM loans WHERE id=$1', [loanId]);
      const loan    = loanRes.rows[0];
      if (loan && loan.status !== 'defaulted') {
        const totalOwed = Number(loan.amount) + Number(loan.amount) * Number(loan.interest_rate) / 100;
        const paidRes   = await pool.query('SELECT COALESCE(SUM(amount),0) AS paid FROM repayments WHERE loan_id=$1', [loanId]);
        const paid      = Number(paidRes.rows[0].paid);
        const newStatus = paid >= totalOwed - 0.005 ? 'completed' : 'active';
        if (newStatus !== loan.status)
          await pool.query('UPDATE loans SET status=$1,updated_at=NOW() WHERE id=$2', [newStatus, loanId]);
      }
    }
    await audit(req.user.id, req.user.username, 'DELETE_REPAYMENT', 'Repayment', req.params.id, '');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  ADMIN FEE PAYMENTS
// ================================================================
app.get('/api/admin-fees', requireAuth, requireDB, async (req, res) => {
  try {
    const bfA = getBranchFilter(req.user, req.query);
    const whereClause = bfA.value ? 'WHERE l.branch_id=$1' : '';
    const { rows } = await pool.query(`
      SELECT af.*, l.amount AS loan_amount, l.client_id,
             c.name AS client_name
      FROM admin_fee_payments af
      JOIN loans l ON l.id = af.loan_id
      JOIN clients c ON c.id = l.client_id
      ${whereClause}
      ORDER BY af.date DESC
    `, bfA.value ? [bfA.value] : []);
    res.json(rows.map(r => ({
      ...mapAdminFee(r),
      loanAmount: Number(r.loan_amount),
      clientId: r.client_id,
      clientName: r.client_name
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin-fees', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { loanId, amount, date, notes } = req.body;
    if (!loanId || !amount || !date) return res.status(400).json({ error: 'loanId, amount and date required' });
    const id = uuidv4();
    const isPenalty = (notes||'').toLowerCase().includes('auto penalty');
    await pool.query(
      `INSERT INTO admin_fee_payments (id,loan_id,amount,date,notes,added_by) VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, loanId, amount, date, notes||null, req.user.id]
    );
    // Only update admin_fees_status for actual admin fees — not auto penalties
    if(!isPenalty){
      await pool.query(`UPDATE loans SET admin_fees_status='paid',updated_at=NOW() WHERE id=$1`, [loanId]);
    }
    // Use different audit action for penalties vs admin fees
    const auditAction = isPenalty ? 'AUTO_PENALTY' : 'RECORD_ADMIN_FEE';
    await audit(req.user.id, req.user.username, auditAction, 'AdminFee', id, notes||`$${amount} for loan ${loanId}`);
    const { rows } = await pool.query('SELECT * FROM admin_fee_payments WHERE id=$1', [id]);
    res.status(201).json(mapAdminFee(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin-fees/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const rep = await pool.query('SELECT loan_id FROM admin_fee_payments WHERE id=$1', [req.params.id]);
    const loanId = rep.rows[0]?.loan_id;
    await pool.query('DELETE FROM admin_fee_payments WHERE id=$1', [req.params.id]);
    if (loanId) await pool.query(`UPDATE loans SET admin_fees_status='pending',updated_at=NOW() WHERE id=$1`, [loanId]);
    await audit(req.user.id, req.user.username, 'DELETE_ADMIN_FEE', 'AdminFee', req.params.id, '');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  EXPENSES
// ================================================================
app.get('/api/expenses', requireAuth, requireDB, async (req, res) => {
  try {
    const bfe = getBranchFilter(req.user, req.query);
    const qry = bfe.value ? 'SELECT * FROM expenses WHERE branch_id=$1 ORDER BY date DESC' : 'SELECT * FROM expenses ORDER BY date DESC';
    const { rows } = await pool.query(qry, bfe.value ? [bfe.value] : []);
    res.json(rows.map(mapExp));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/expenses', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { amount, category, description, date, branchId } = req.body;
    if (!amount || !category || !date) return res.status(400).json({ error: 'amount, category and date required' });
    const id = uuidv4();
    const expBranch = branchId || req.user.branchId || req.user.branch_id || null;
    await pool.query(
      `INSERT INTO expenses (id,amount,category,description,date,branch_id,added_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, amount, category, description||null, date, expBranch, req.user.id]
    );
    await audit(req.user.id, req.user.username, 'ADD_EXPENSE', 'Expense', id, `$${amount} — ${category}`);
    const { rows } = await pool.query('SELECT * FROM expenses WHERE id=$1', [id]);
    res.status(201).json(mapExp(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/expenses/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM expenses WHERE id=$1', [req.params.id]);
    await audit(req.user.id, req.user.username, 'DELETE_EXPENSE', 'Expense', req.params.id, '');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  AUDIT LOG
// ================================================================
app.get('/api/audit', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200');
    res.json(rows.map(r => ({ id:r.id, userId:r.user_id, username:r.username, action:r.action, entity:r.entity, entityId:r.entity_id, detail:r.detail, createdAt:r.created_at })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  APPLICATIONS (Mobile App + Manual Loan Applications)
// ================================================================
const mapMobileApp = r => ({
  id: r.id, customerId: r.customer_id, customerName: r.customer_name,
  customerPhone: r.customer_phone, customerNationalId: r.customer_national_id||'',
  customerEmail: r.customer_email||'', amount: Number(r.amount),
  interestRate: Number(r.interest_rate), term: Number(r.term),
  termFrequency: r.term_frequency||'monthly', purpose: r.purpose||'', notes: r.notes||'',
  status: r.status, reviewerNotes: r.reviewer_notes||'', reviewedBy: r.reviewed_by||'',
  reviewedAt: r.reviewed_at?r.reviewed_at.toISOString():'',
  disbursedAt: r.disbursed_at?r.disbursed_at.toISOString():'',
  applicationFee: Number(r.application_fee||0), adminFees: Number(r.admin_fees||0),
  source: r.source||'mobile', createdBy: r.created_by||'', branchId: r.branch_id||'',
  linkedClientId: r.linked_client_id||'', linkedLoanId: r.linked_loan_id||'',
  createdAt: r.created_at?r.created_at.toISOString():''
});

const MOBILE_APP_JOIN = `
  SELECT l.*, c.name AS customer_name, c.phone AS customer_phone,
         c.national_id AS customer_national_id, c.email AS customer_email,
         c.expo_push_token AS customer_push_token
  FROM mobile_loan_requests l
  JOIN mobile_customers c ON c.id = l.customer_id
`;

// List — branch filtered, pending first
app.get('/api/mobile-applications', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { status } = req.query;
    const bf = getBranchFilter(req.user, req.query);
    let sql = MOBILE_APP_JOIN;
    const params = [], where = [];
    if (status) { params.push(status); where.push(`l.status = $${params.length}`); }
    if (bf.value) {
      params.push(bf.value);
      where.push(`(l.branch_id = $${params.length} OR l.branch_id IS NULL)`);
    }
    if (where.length) sql += ' WHERE ' + where.join(' AND ');
    sql += ` ORDER BY CASE l.status WHEN 'pending' THEN 0 ELSE 1 END, l.created_at DESC`;
    const { rows } = await pool.query(sql, params);
    res.json(rows.map(mapMobileApp));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Single application detail with documents
app.get('/api/mobile-applications/:id', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { rows } = await pool.query(MOBILE_APP_JOIN + ' WHERE l.id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = mapMobileApp(rows[0]);
    const { rows: docs } = await pool.query('SELECT id,doc_type,filename,url FROM mobile_documents WHERE loan_id=$1 ORDER BY created_at DESC', [req.params.id]);
    app_.documents = docs.map(d=>({id:d.id,docType:d.doc_type,filename:d.filename,url:d.url}));
    res.json(app_);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Search mobile customers
app.get('/api/mobile-customers/search', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const q = (req.query.q||'').trim();
    if (q.length < 2) return res.json([]);
    const { rows } = await pool.query(`SELECT id,name,phone,national_id,email FROM mobile_customers WHERE name ILIKE $1 OR phone ILIKE $1 LIMIT 10`, [`%${q}%`]);
    res.json(rows.map(c=>({id:c.id,name:c.name,phone:c.phone,nationalId:c.national_id||'',email:c.email||''})));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create manual application
app.post('/api/mobile-applications', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  const conn = await pool.connect();
  try {
    const { customerId, newCustomer, amount, interestRate, term, termFrequency, purpose, notes, applicationFee, branchId } = req.body;
    if (!amount||!interestRate||!term) return res.status(400).json({ error: 'Loan amount, rate and term are required' });
    if (!customerId&&!newCustomer) return res.status(400).json({ error: 'A customer must be selected or created' });
    await conn.query('BEGIN');
    let custId = customerId;
    if (!custId && newCustomer) {
      if (!newCustomer.name||!newCustomer.phone) { await conn.query('ROLLBACK'); return res.status(400).json({ error: 'New customer name and phone required' }); }
      const ex = await conn.query('SELECT id FROM mobile_customers WHERE phone=$1', [newCustomer.phone]);
      if (ex.rows.length) { custId = ex.rows[0].id; }
      else {
        const ins = await conn.query(`INSERT INTO mobile_customers (name,phone,national_id,email,status) VALUES ($1,$2,$3,$4,'active') RETURNING id`, [newCustomer.name,newCustomer.phone,newCustomer.nationalId||null,newCustomer.email||null]);
        custId = ins.rows[0].id;
      }
    }
    const ins = await conn.query(`INSERT INTO mobile_loan_requests (customer_id,amount,interest_rate,term,term_frequency,purpose,notes,status,application_fee,source,created_by,branch_id) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,'manual',$9,$10) RETURNING id`,
      [custId,amount,interestRate,term,termFrequency||'monthly',purpose||null,notes||null,applicationFee||0,req.user.username,branchId||null]);
    await conn.query('COMMIT');
    await audit(req.user.id,req.user.username,'ADD_MOBILE_LOAN','MobileLoan',ins.rows[0].id,`$${amount} manual application`,branchId);
    const { rows } = await pool.query(MOBILE_APP_JOIN+' WHERE l.id=$1',[ins.rows[0].id]);
    res.status(201).json(mapMobileApp(rows[0]));
  } catch (err) { await conn.query('ROLLBACK').catch(()=>{}); res.status(500).json({ error: err.message }); }
  finally { conn.release(); }
});

// Approve — creates real client + loan, records admin fee
app.put('/api/mobile-applications/:id/approve', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  const conn = await pool.connect();
  let clientId, loanId, isNewClient, branchId, fee, startDate, appRow;
  try {
    const { adminFees, startDate: reqStartDate, reviewerNotes, branchId: reqBranchId } = req.body;
    const id = req.params.id;
    const { rows: ex } = await pool.query(MOBILE_APP_JOIN+' WHERE l.id=$1',[id]);
    if (!ex.length) return res.status(404).json({ error: 'Application not found' });
    appRow = ex[0];
    if (appRow.status!=='pending') return res.status(400).json({ error: 'Already reviewed' });
    fee = Number(adminFees)||0;
    if (fee<0) return res.status(400).json({ error: 'Admin fee cannot be negative' });
    startDate = reqStartDate;
    if (!startDate) return res.status(400).json({ error: 'Start date is required' });
    branchId = reqBranchId||appRow.branch_id||req.user.branchId||req.user.branch_id||null;
    if (!branchId) return res.status(400).json({ error: 'A branch must be selected' });
    await conn.query('BEGIN');
    const { rows: ec } = await conn.query('SELECT id FROM clients WHERE phone=$1 LIMIT 1',[appRow.customer_phone]);
    isNewClient = ec.length===0;
    clientId = isNewClient ? uuidv4() : ec[0].id;
    if (isNewClient) await conn.query(`INSERT INTO clients (id,name,phone,national_id,email,date_added,branch_id,added_by) VALUES ($1,$2,$3,$4,$5,CURRENT_DATE,$6,$7)`,[clientId,appRow.customer_name,appRow.customer_phone,appRow.customer_national_id||null,appRow.customer_email||null,branchId,req.user.id]);
    loanId = uuidv4();
    await conn.query(`INSERT INTO loans (id,client_id,amount,interest_rate,term,term_frequency,start_date,purpose,notes,admin_fees,admin_fees_status,branch_id,added_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [loanId,clientId,appRow.amount,appRow.interest_rate,appRow.term,appRow.term_frequency||'monthly',startDate,appRow.purpose||null,appRow.notes||null,fee,fee>0?'paid':'none',branchId,req.user.id]);
    if (fee>0) await conn.query(`INSERT INTO admin_fee_payments (id,loan_id,amount,date,notes,added_by) VALUES ($1,$2,$3,$4,$5,$6)`,[uuidv4(),loanId,fee,startDate,`Admin fee — ${appRow.customer_name} (Mobile App)`,req.user.id]);
    await conn.query(`UPDATE mobile_loan_requests SET status='active',reviewed_by=$1,reviewed_at=NOW(),disbursed_at=NOW(),admin_fees=$2,reviewer_notes=COALESCE($3,reviewer_notes),branch_id=$4,linked_client_id=$5,linked_loan_id=$6,updated_at=NOW() WHERE id=$7`,
      [req.user.username,fee,reviewerNotes||null,branchId,clientId,loanId,id]);
    await conn.query(`INSERT INTO mobile_notifications (customer_id,title,body,type) VALUES ($1,$2,$3,'loan_approved')`,[appRow.customer_id,'🎉 Loan Approved!',`Your loan of $${Number(appRow.amount).toFixed(2)} has been approved.`]);
    await conn.query('COMMIT');
  } catch (err) { await conn.query('ROLLBACK').catch(()=>{}); return res.status(500).json({ error: err.message }); }
  finally { conn.release(); }
  if (isNewClient) await audit(req.user.id,req.user.username,'ADD_CLIENT','Client',clientId,`${appRow.customer_name} — added via App approval`,branchId);
  await audit(req.user.id,req.user.username,'DISBURSE_LOAN','Loan',loanId,`${appRow.customer_name} — $${Number(appRow.amount).toFixed(2)} — from App (start ${startDate})`,branchId);
  await audit(req.user.id,req.user.username,'APPROVE_MOBILE_LOAN','MobileLoan',req.params.id,`$${Number(appRow.amount).toFixed(2)} approved — fee $${fee}${isNewClient?' — new client':''}`,branchId);
  try { const { rows } = await pool.query(MOBILE_APP_JOIN+' WHERE l.id=$1',[req.params.id]); res.json(mapMobileApp(rows[0])); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// Reject
app.put('/api/mobile-applications/:id/reject', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const { reason } = req.body;
    if (!reason||!reason.trim()) return res.status(400).json({ error: 'A rejection reason is required' });
    const id = req.params.id;
    const { rows: ex } = await pool.query('SELECT * FROM mobile_loan_requests WHERE id=$1',[id]);
    if (!ex.length) return res.status(404).json({ error: 'Application not found' });
    if (ex[0].status!=='pending') return res.status(400).json({ error: 'Already reviewed' });
    await pool.query(`UPDATE mobile_loan_requests SET status='rejected',reviewed_by=$1,reviewed_at=NOW(),reviewer_notes=$2,updated_at=NOW() WHERE id=$3`,[req.user.username,reason.trim(),id]);
    await pool.query(`INSERT INTO mobile_notifications (customer_id,title,body,type) VALUES ($1,$2,$3,'loan_rejected')`,[ex[0].customer_id,'Loan Application Update',`Your loan application was not approved. Reason: ${reason.trim()}`]);
    await audit(req.user.id,req.user.username,'REJECT_MOBILE_LOAN','MobileLoan',id,`Rejected — ${reason.trim()}`,ex[0].branch_id);
    const { rows } = await pool.query(MOBILE_APP_JOIN+' WHERE l.id=$1',[id]);
    res.json(mapMobileApp(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete (pending/rejected only)
app.delete('/api/mobile-applications/:id', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const { rows: ex } = await pool.query('SELECT status FROM mobile_loan_requests WHERE id=$1',[req.params.id]);
    if (!ex.length) return res.status(404).json({ error: 'Not found' });
    if (!['pending','rejected'].includes(ex[0].status)) return res.status(400).json({ error: 'Only pending or rejected applications can be deleted' });
    await pool.query('DELETE FROM mobile_loan_requests WHERE id=$1',[req.params.id]);
    await audit(req.user.id,req.user.username,'DELETE_MOBILE_LOAN','MobileLoan',req.params.id,'Deleted');
    res.json({ ok:true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ================================================================
//  CRON — Daily auto-penalty (called by external cron at 8am ZW)
//  Secured with CRON_SECRET env variable
// ================================================================

// Server-side amortisation (mirrors frontend buildAmortisation)
function serverBuildAmortisation(loan){
  const amount      = Number(loan.amount);
  const rate        = Number(loan.interest_rate);
  const term        = Number(loan.term);
  const freq        = loan.term_frequency || 'monthly';
  const periodicPay = (amount + amount * rate / 100) / term;
  const rows        = [];

  const baseStr = loan.repayment_start_date
    ? loan.repayment_start_date.toISOString().slice(0,10)
    : loan.start_date.toISOString().slice(0,10);
  const base    = new Date(baseStr + 'T00:00:00');
  const hasRS   = !!loan.repayment_start_date;

  const toLD = d => d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
  const skipSun = d => { if(d.getDay()===0) d.setDate(d.getDate()+1); return d; };

  if(freq==='daily'){
    const cur = new Date(base);
    if(!hasRS) cur.setDate(cur.getDate()+1);
    for(let m=1;m<=term;m++){
      if(m>1) cur.setDate(cur.getDate()+1);
      while(cur.getDay()===0) cur.setDate(cur.getDate()+1);
      rows.push({ month:m, dueDate:toLD(new Date(cur)), payment:periodicPay });
    }
  } else {
    for(let m=1;m<=term;m++){
      const due = new Date(base);
      if(hasRS){
        if(freq==='monthly') due.setMonth(due.getMonth()+(m-1));
        else                 due.setDate(due.getDate()+((m-1)*7));
      } else {
        if(freq==='monthly') due.setMonth(due.getMonth()+m);
        else                 due.setDate(due.getDate()+(m*7));
      }
      skipSun(due);
      rows.push({ month:m, dueDate:toLD(due), payment:periodicPay });
    }
  }
  return rows;
}

app.post('/api/cron/penalties', async (req, res) => {
  // Verify secret — must match CRON_SECRET env var on Render
  const secret = req.headers['x-cron-secret'] || req.query.secret;
  if(!secret || secret !== process.env.CRON_SECRET){
    return res.status(401).json({ error: 'Unauthorized — invalid cron secret' });
  }
  if(!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const BRANCH_RATES   = { 'Harare':0.05, 'Bulawayo':0.035, 'Kwekwe':0.035 };
  const DEFAULT_RATE   = 0.05;
  // Zimbabwe UTC+2
  const nowZW          = new Date(new Date().getTime() + 2*60*60*1000);
  const todayStr       = nowZW.toISOString().slice(0,10);

  let applied=0, skipped=0, errors=0;
  const details=[];

  try{
    // Fetch all non-completed loans with branch name and client name
    const { rows: loans } = await pool.query(`
      SELECT l.*, b.name AS branch_name, c.name AS client_name
      FROM loans l
      LEFT JOIN branches b ON b.id = l.branch_id
      LEFT JOIN clients  c ON c.id = l.client_id
      WHERE l.status != 'completed'
    `);

    for(const loan of loans){
      try{
        // Total repayments for this loan
        const { rows: reps } = await pool.query(
          `SELECT COALESCE(SUM(amount),0)::float AS total FROM repayments WHERE loan_id=$1`, [loan.id]
        );
        const totalPaid   = Number(reps[0].total);
        const amort       = serverBuildAmortisation(loan);
        const periodicPay = amort[0]?.payment || 0;

        // Past-due periods only
        const pastDue     = amort.filter(r => r.dueDate < todayStr);
        if(!pastDue.length){ skipped++; continue; }

        const currentMissed = pastDue[pastDue.length-1];
        const amountDueNow  = pastDue.length * periodicPay;

        // Client on good schedule — skip
        if(totalPaid >= amountDueNow - 0.005){ skipped++; continue; }

        // Already penalised this period?
        const { rows: existing } = await pool.query(
          `SELECT id FROM admin_fee_payments WHERE loan_id=$1 AND notes ILIKE $2`,
          [loan.id, `%Auto penalty period ${currentMissed.month}%`]
        );
        if(existing.length){ skipped++; continue; }

        // Apply penalty
        const rate       = BRANCH_RATES[loan.branch_name] || DEFAULT_RATE;
        const penaltyAmt = Math.round(periodicPay * rate * 10000) / 10000;
        const noteText   = `Auto penalty period ${currentMissed.month} — ${+(rate*100).toFixed(2)}% of $${periodicPay.toFixed(2)} (${loan.client_name||''})`;
        const penaltyId  = uuidv4();

        await pool.query(
          `INSERT INTO admin_fee_payments (id,loan_id,amount,date,notes,added_by) VALUES ($1,$2,$3,$4,$5,$6)`,
          [penaltyId, loan.id, penaltyAmt, currentMissed.dueDate, noteText, 'cron']
        );
        await pool.query(
          `INSERT INTO audit_log (id,user_id,username,branch_id,action,entity,entity_id,detail)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [uuidv4(), null, 'cron', loan.branch_id, 'AUTO_PENALTY', 'AdminFee', penaltyId,
           `Auto penalty period ${currentMissed.month} — ${loan.client_name||''} — $${penaltyAmt}`]
        );
        applied++;
        details.push({ client:loan.client_name, amount:penaltyAmt, period:currentMissed.month });
      }catch(e){ errors++; console.error('Penalty error loan',loan.id,e.message); }
    }

    console.log(`[CRON] ${todayStr} — Penalties applied:${applied} skipped:${skipped} errors:${errors}`);
    res.json({ ok:true, date:todayStr, applied, skipped, errors, details });
  }catch(err){
    console.error('[CRON] penalties error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ================================================================
//  FALLBACK → serve frontend
// ================================================================
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ================================================================
//  START
// ================================================================
app.listen(PORT, () => {
  console.log(`\n🚀  CrediConnect v3.0 running on port ${PORT}`);
  console.log(`    DB: ${dbConnected ? '✅ PostgreSQL connected' : '⚠️  Not connected'}`);
  console.log(`    Default login: admin / Admin@1234\n`);
});
