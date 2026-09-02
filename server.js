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
const mapClient = r => ({ id:r.id, name:r.name, phone:r.phone, phone2:r.phone2||'', nationalId:r.national_id||'', email:r.email||'', address:r.address||'', occupation:r.occupation||'', dob:r.dob?r.dob.toISOString().slice(0,10):'', dateAdded:r.date_added?r.date_added.toISOString().slice(0,10):'', addedBy:r.added_by||'', branchId:r.branch_id||'' });
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
    id: r.id, clientId: r.client_id, clientName: r.client_name||'', clientPhone: r.client_phone||'', amount, interestRate: rate,
    term: Number(r.term), termFrequency: r.term_frequency || 'monthly',
    startDate: r.start_date ? r.start_date.toISOString().slice(0,10) : '',
    purpose: r.purpose || '', notes: r.notes || '',
    adminFees: Number(r.admin_fees || 0),
    adminFeesStatus: r.admin_fees_status || 'none',
    status: computedStatus, addedBy: r.added_by || '', branchId: r.branch_id || '',
    repaymentStartDate: r.repayment_start_date ? r.repayment_start_date.toISOString().slice(0,10) : ''
  };
};
const mapAdminFee = r => ({ id:r.id, loanId:r.loan_id, amount:Number(r.amount), date:r.date?r.date.toISOString().slice(0,10):'', notes:r.notes||'', addedBy:r.added_by||'', collected:r.collected||false, waived:r.waived||false, waiveReason:r.waive_reason||'', waivedBy:r.waived_by||'', settled:r.settled||false });
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
    const { name, phone, phone2, nationalId, email, address, occupation, dob, dateAdded, branchId } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });
    // Server-side duplicate check — normalise phone for comparison
    const normP = phone.replace(/\D/g,'').replace(/^(263|971|0)/,'');
    const normP2 = phone2 ? phone2.replace(/\D/g,'').replace(/^(263|971|0)/,'') : null;
    const { rows: dupRows } = await pool.query(
      `SELECT id,name,phone FROM clients WHERE
        regexp_replace(phone,'\\D','','g') ILIKE $1 OR
        (national_id IS NOT NULL AND national_id<>'' AND national_id=COALESCE($2,''))
        OR ($3::text IS NOT NULL AND regexp_replace(phone,'\\D','','g') ILIKE $3)`,
      [`%${normP}`, nationalId||null, normP2?`%${normP2}`:null]
    );
    if (dupRows.length) return res.status(409).json({ error: `A client already exists with this phone or ID: ${dupRows[0].name} (${dupRows[0].phone})` });
    const id = uuidv4();
    const clientBranch = branchId || req.user.branchId || req.user.branch_id || null;
    await pool.query(
      `INSERT INTO clients (id,name,phone,phone2,national_id,email,address,occupation,dob,date_added,branch_id,added_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, name, phone, phone2||null, nationalId||null, email||null, address||null, occupation||null, dob||null, dateAdded||new Date(), clientBranch, req.user.id]
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
    const { name, phone, phone2, nationalId, email, address, occupation, dob } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });
    await pool.query(
      `UPDATE clients SET name=$1,phone=$2,phone2=$3,national_id=$4,email=$5,address=$6,occupation=$7,dob=$8,updated_at=NOW() WHERE id=$9`,
      [name, phone, phone2||null, nationalId||null, email||null, address||null, occupation||null, dob||null, req.params.id]
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
        COALESCE(p.total_paid, 0) AS total_paid,
        c.name AS client_name,
        c.phone AS client_phone
      FROM loans l
      LEFT JOIN clients c ON c.id = l.client_id
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
      // Overdue if installments not paid OR has unsettled auto-penalty
      const { rows: unsettledRows } = await pool.query(
        `SELECT COUNT(*) AS cnt FROM admin_fee_payments
         WHERE loan_id=$1 AND notes ILIKE '%auto penalty%' AND settled=FALSE AND waived=FALSE`, [loanId]
      );
      const hasUnsettledPenalty = Number(unsettledRows[0].cnt) > 0;
      const isOverdue = (duePeriods > 0 && totalPaid < (duePeriods * periodicPay) - 0.005) || hasUnsettledPenalty;
      let newStatus;
      if(totalPaid >= totalOwed - 0.005) newStatus = 'completed';
      else if(isOverdue)                  newStatus = 'defaulted';
      else                                newStatus = 'active';
      if(newStatus !== loan.status){
        await pool.query('UPDATE loans SET status=$1,updated_at=NOW() WHERE id=$2', [newStatus, loanId]);
      }
      // Mark auto-penalties as collected if total payments now cover installments + penalties
      // Penalties are counted from oldest to newest — excess beyond installments covers them in order
      const { rows: penaltyRows } = await pool.query(
        `SELECT id, amount, notes FROM admin_fee_payments
         WHERE loan_id=$1 AND notes ILIKE '%auto penalty%' AND collected=FALSE AND waived=FALSE
         ORDER BY created_at ASC`, [loanId]
      );
      if(penaltyRows.length){
        const installmentsDue = duePeriods * periodicPay;
        let excess = Math.max(0, totalPaid - installmentsDue);
        for(const p of penaltyRows){
          if(excess >= Number(p.amount) - 0.005){
            await pool.query('UPDATE admin_fee_payments SET collected=TRUE WHERE id=$1',[p.id]);
            excess -= Number(p.amount);
          } else break;
        }
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
    const isPenalty = (notes||'').toLowerCase().includes('auto penalty');
    const isFine    = (notes||'').toLowerCase().includes('fine');

    // SERVER-SIDE DEDUPLICATION for auto-penalties
    // Extract period number from notes e.g. "Auto penalty period 2 — ..."
    if(isPenalty){
      const periodMatch = (notes||'').match(/period\s+(\d+)/i);
      if(periodMatch){
        const { rows: existing } = await pool.query(
          `SELECT id FROM admin_fee_payments
           WHERE loan_id=$1 AND notes ILIKE $2 AND waived=FALSE`,
          [loanId, `%auto penalty period ${periodMatch[1]}%`]
        );
        if(existing.length){
          // Already exists — return the existing record silently (idempotent)
          const { rows } = await pool.query('SELECT * FROM admin_fee_payments WHERE id=$1',[existing[0].id]);
          return res.status(200).json(mapAdminFee(rows[0]));
        }
      }
    }

    const id = uuidv4();
    await pool.query(
      `INSERT INTO admin_fee_payments (id,loan_id,amount,date,notes,added_by) VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, loanId, amount, date, notes||null, req.user.id]
    );
    if(!isPenalty && !isFine){
      await pool.query(`UPDATE loans SET admin_fees_status='paid',updated_at=NOW() WHERE id=$1`, [loanId]);
    }
    if(isFine && loanId){
      await pool.query(
        `UPDATE admin_fee_payments SET settled=TRUE
         WHERE loan_id=$1 AND notes ILIKE '%auto penalty%' AND settled=FALSE AND waived=FALSE`,
        [loanId]
      );
    }
    const auditAction = isPenalty ? 'AUTO_PENALTY' : 'RECORD_ADMIN_FEE';
    await audit(req.user.id, req.user.username, auditAction, 'AdminFee', id, notes||`$${amount} for loan ${loanId}`);
    const { rows } = await pool.query('SELECT * FROM admin_fee_payments WHERE id=$1', [id]);
    res.status(201).json(mapAdminFee(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Waive penalty — requires reason, keeps record for audit trail
app.put('/api/admin-fees/:id/waive', requireAuth, requireDB, requireRole('admin'), async (req, res) => {
  try {
    const { reason } = req.body;
    if(!reason||!reason.trim()) return res.status(400).json({ error: 'A reason is required to waive a penalty' });
    const { rows: ex } = await pool.query('SELECT * FROM admin_fee_payments WHERE id=$1',[req.params.id]);
    if(!ex.length) return res.status(404).json({ error: 'Penalty not found' });
    if(ex[0].waived) return res.status(400).json({ error: 'Already waived' });
    if(!(ex[0].notes||'').toLowerCase().includes('auto penalty')) return res.status(400).json({ error: 'Only auto-penalties can be waived' });
    await pool.query(
      `UPDATE admin_fee_payments SET waived=TRUE,waive_reason=$1,waived_by=$2 WHERE id=$3`,
      [reason.trim(), req.user.username, req.params.id]
    );
    const loan = ex[0].loan_id ? (await pool.query('SELECT client_id,amount FROM loans WHERE id=$1',[ex[0].loan_id])).rows[0] : null;
    const client = loan ? (await pool.query('SELECT name FROM clients WHERE id=$1',[loan.client_id])).rows[0] : null;
    await audit(req.user.id, req.user.username, 'WAIVE_PENALTY', 'AdminFee', req.params.id,
      `$${ex[0].amount} waived${client?' — '+client.name:''} — Reason: ${reason.trim()}`);
    const { rows } = await pool.query('SELECT * FROM admin_fee_payments WHERE id=$1',[req.params.id]);
    res.json(mapAdminFee(rows[0]));
  } catch(err){ res.status(500).json({ error: err.message }); }
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

// Search customers — checks BOTH mobile_customers (app registrations) AND
// the main clients table, so walk-in clients can be found too.
app.get('/api/mobile-customers/search', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const q = (req.query.q||'').trim();
    if (q.length < 2) return res.json([]);
    const like = `%${q}%`;

    // Mobile app customers
    const { rows: mobileRows } = await pool.query(
      `SELECT id, name, phone, national_id, email, 'mobile' AS source
       FROM mobile_customers WHERE name ILIKE $1 OR phone ILIKE $1 LIMIT 8`, [like]
    );

    // Main clients — only those NOT already in mobile_customers (match by phone)
    const { rows: clientRows } = await pool.query(
      `SELECT c.id, c.name, c.phone, c.national_id, c.email, 'client' AS source
       FROM clients c
       WHERE (c.name ILIKE $1 OR c.phone ILIKE $1)
         AND NOT EXISTS (
           SELECT 1 FROM mobile_customers mc WHERE mc.phone = c.phone
         )
       LIMIT 8`, [like]
    );

    const results = [...mobileRows, ...clientRows].slice(0, 10).map(r => ({
      id: r.id,
      name: r.name,
      phone: r.phone,
      nationalId: r.national_id||'',
      email: r.email||'',
      source: r.source  // 'mobile' or 'client' — used to know if we need to create in mobile_customers
    }));
    res.json(results);
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
        const ins = await conn.query(`INSERT INTO mobile_customers (name,phone,national_id,email,address,status) VALUES ($1,$2,$3,$4,$5,'active') RETURNING id`, [newCustomer.name,newCustomer.phone,newCustomer.nationalId||null,newCustomer.email||null,newCustomer.address||null]);
        custId = ins.rows[0].id;
      }
    }
    // If a main-system client was selected (source='client'), we need a mobile_customers record
    if (req.body.customerSource === 'client') {
      // Look up the client from main system first
      const cl = await conn.query('SELECT name,phone,national_id,email FROM clients WHERE id=$1',[custId]);
      if (!cl.rows.length) { await conn.query('ROLLBACK'); return res.status(400).json({ error: 'Client not found in main system' }); }
      const client = cl.rows[0];
      // Check if already in mobile_customers by phone
      const ex = await conn.query('SELECT id FROM mobile_customers WHERE phone=$1',[client.phone]);
      if (ex.rows.length) {
        custId = ex.rows[0].id;
      } else {
        // Create in mobile_customers
        const mc = await conn.query(
          `INSERT INTO mobile_customers (name,phone,national_id,email,status) VALUES ($1,$2,$3,$4,'active') RETURNING id`,
          [client.name, client.phone, client.national_id||null, client.email||null]
        );
        custId = mc.rows[0].id;
      }
    }
    // Verify we have a valid mobile_customers id before inserting
    const custCheck = await conn.query('SELECT id FROM mobile_customers WHERE id=$1',[custId]);
    if (!custCheck.rows.length) { await conn.query('ROLLBACK'); return res.status(400).json({ error: 'Could not resolve customer. Please try searching again.' }); }
    const ins = await conn.query(`INSERT INTO mobile_loan_requests (customer_id,amount,interest_rate,term,term_frequency,purpose,notes,status,application_fee,source,created_by,branch_id) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,'manual',$9,$10) RETURNING id`,
      [custId,amount,interestRate,term,termFrequency||'monthly',purpose||null,notes||null,applicationFee||0,req.user.username,branchId||null]);
    // Record application fee inside the transaction — if fee insert fails, whole application rolls back
    if((applicationFee||0) > 0){
      const cust = await conn.query('SELECT name FROM mobile_customers WHERE id=$1',[custId]);
      const custName = cust.rows[0]?.name||'';
      await conn.query(
        `INSERT INTO application_fee_payments (application_id,customer_name,amount,date,notes,added_by)
         VALUES ($1,$2,$3,CURRENT_DATE,$4,$5)`,
        [ins.rows[0].id, custName, applicationFee, `Application fee — ${custName}`, req.user.username]
      );
    }
    await conn.query('COMMIT');
    await audit(req.user.id,req.user.username,'ADD_MOBILE_LOAN','MobileLoan',ins.rows[0].id,`$${amount} manual application${applicationFee>0?' — application fee $'+applicationFee:''}`,branchId);
    const { rows } = await pool.query(MOBILE_APP_JOIN+' WHERE l.id=$1',[ins.rows[0].id]);
    res.status(201).json(mapMobileApp(rows[0]));
  } catch (err) { await conn.query('ROLLBACK').catch(()=>{}); res.status(500).json({ error: err.message }); }
  finally { conn.release(); }
});

// Application fee payments — recorded at intake
app.get('/api/application-fees', requireAuth, requireDB, requireRole('admin','loan_officer'), async (req, res) => {
  try {
    const bf = getBranchFilter(req.user, req.query);
    let sql = `SELECT af.*, lr.branch_id FROM application_fee_payments af
               LEFT JOIN mobile_loan_requests lr ON lr.id = af.application_id`;
    const params = [];
    if(bf.value){ params.push(bf.value); sql += ` WHERE (lr.branch_id = $${params.length} OR lr.branch_id IS NULL)`; }
    sql += ' ORDER BY af.created_at DESC';
    const { rows } = await pool.query(sql, params);
    res.json(rows.map(r=>({ id:r.id, applicationId:r.application_id, customerName:r.customer_name||'', amount:Number(r.amount||0), date:(r.date||'').slice?.(0,10)||'', notes:r.notes||'', addedBy:r.added_by||'', createdAt:r.created_at?.toISOString()||'' })));
  } catch(err){ res.status(500).json({ error: err.message }); }
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

  const PENALTY_RATE   = 0.04; // 4% flat for all branches — v5.1
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
        const rate       = PENALTY_RATE;
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
//  MONTHLY REPORT GENERATOR — ExcelJS server-side
// ================================================================
const _REPORT_TPL_B64 = "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";

app.get('/api/reports/monthly', requireAuth, requireDB, requireRole('admin','super_admin'), async (req, res) => {
  try {
    const ExcelJS = require('exceljs');
    const { month, branch } = req.query;
    if (!month || !/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: 'month must be YYYY-MM' });
    const [year, mNum] = month.split('-').map(Number);
    const monthName = new Date(year, mNum-1, 1).toLocaleString('en', {month:'long'});
    const effectiveBranch = branch || (req.user.role !== 'super_admin' ? (req.user.branchId || req.user.branch_id || null) : null);
    const bParam = effectiveBranch ? [effectiveBranch] : [];
    const lBW = effectiveBranch ? 'WHERE l.branch_id=$1' : '';
    const cBW = effectiveBranch ? 'WHERE branch_id=$1' : '';
    const eBW = effectiveBranch ? 'WHERE branch_id=$1' : '';

    const [branchRows,userRows,loanRows,clientRows,repRows,expRows,adminFeeRows,appFeeRows] = await Promise.all([
      pool.query('SELECT * FROM branches ORDER BY name'),
      pool.query('SELECT id,username,full_name,role,branch_id FROM users ORDER BY full_name'),
      pool.query(`SELECT l.*,COALESCE(p.total_paid,0) AS total_paid FROM loans l LEFT JOIN (SELECT loan_id,SUM(amount) AS total_paid FROM repayments GROUP BY loan_id) p ON p.loan_id=l.id ${lBW} ORDER BY l.start_date`, bParam),
      pool.query(`SELECT * FROM clients ${cBW} ORDER BY name`, bParam),
      pool.query(`SELECT r.* FROM repayments r JOIN loans l ON l.id=r.loan_id ${lBW} ORDER BY r.date`, bParam),
      pool.query(`SELECT * FROM expenses ${eBW} ORDER BY date`, bParam),
      pool.query(`SELECT af.* FROM admin_fee_payments af JOIN loans l ON l.id=af.loan_id ${lBW} AND (af.notes IS NULL OR LOWER(af.notes) NOT LIKE '%auto penalty%') ORDER BY af.date`, bParam),
      pool.query(`SELECT af.* FROM application_fee_payments af LEFT JOIN mobile_loan_requests lr ON lr.id=af.application_id ${effectiveBranch ? 'WHERE (lr.branch_id=$1 OR lr.branch_id IS NULL)' : ''} ORDER BY af.created_at`, bParam),
    ]);

    const AL=loanRows.rows, AC=clientRows.rows, AR=repRows.rows, AE=expRows.rows;
    const AAF=adminFeeRows.rows, AAPF=appFeeRows.rows, ABR=branchRows.rows, AU=userRows.rows;

    // Convert raw pg Date objects → 'YYYY-MM-DD' strings safely
    function toDS(d){ if(!d) return ''; if(d instanceof Date) return d.toISOString().slice(0,10); return String(d).slice(0,10); }

    function glTotal(l){ return Number(l.amount)*(1+Number(l.interest_rate)/100); }
    function glPaid(id){ return AR.filter(r=>r.loan_id===id).reduce((s,r)=>s+Number(r.amount),0); }
    function glBal(l){ return Math.max(0,glTotal(l)-glPaid(l.id)); }
    function glStatus(l){ if(l.status==='defaulted')return'defaulted'; return glBal(l)<=0.005?'completed':'active'; }
    function buildAmort(l){
      const rows=[],tot=Number(l.amount),rate=Number(l.interest_rate),term=Number(l.term),freq=l.term_frequency||'monthly';
      const pp=tot/term,ip=tot*rate/100/term;
      const start=new Date((toDS(l.repayment_start_date)||toDS(l.start_date))+'T00:00:00');
      for(let i=1;i<=term;i++){
        const d=new Date(start);
        if(freq==='weekly')d.setDate(d.getDate()+i*7);
        else if(freq==='daily')d.setDate(d.getDate()+i);
        else{d.setDate(1);d.setMonth(d.getMonth()+i);}
        rows.push({dueDate:d.toISOString().slice(0,10),principal:pp,interest:ip,month:i});
      }
      return rows;
    }
    function isOvd(l){
      if(glStatus(l)==='completed')return false;
      const a=buildAmort(l),td=new Date().toISOString().slice(0,10);
      const ovd=a.filter(r=>r.dueDate<td);
      if(!ovd.length)return false;
      return glPaid(l.id)<ovd.length*(glTotal(l)/Number(l.term))-0.005;
    }
    function daysOvd(l){
      const a=buildAmort(l),td=new Date().toISOString().slice(0,10);
      const ovd=a.filter(r=>r.dueDate<td);
      if(!ovd.length)return 0;
      if(glPaid(l.id)>=ovd.length*(glTotal(l)/Number(l.term))-0.005)return 0;
      return Math.floor((new Date()-new Date(ovd[ovd.length-1].dueDate+'T00:00:00'))/86400000);
    }
    function matDate(l){
      const s=new Date((toDS(l.repayment_start_date||'')||toDS(l.start_date))+'T00:00:00');
      const t=Number(l.term),f=l.term_frequency||'monthly';
      if(f==='weekly')s.setDate(s.getDate()+t*7);
      else if(f==='daily')s.setDate(s.getDate()+t);
      else s.setMonth(s.getMonth()+t);
      return s.toISOString().slice(0,10);
    }
    function nextPay(l){
      const a=buildAmort(l),td=new Date().toISOString().slice(0,10);
      const nx=a.find(r=>r.dueDate>=td);return nx?nx.dueDate:'';
    }
    function bname(id){return ABR.find(b=>b.id===id)?.name||'—';}
    function oname(uid){const u=AU.find(u=>String(u.id)===String(uid));return u?(u.full_name||u.username):'—';}
    function shortL(id){return 'CR-'+id.slice(0,8).toUpperCase();}
    function shortC(id){return 'CLT-'+id.slice(0,6).toUpperCase();}
    function $n(v){return Math.round((Number(v)||0)*100)/100;}

    const activeLoans=AL.filter(l=>glStatus(l)!=='completed');
    const overdueLoans=activeLoans.filter(l=>isOvd(l));
    const branchObj=effectiveBranch?ABR.find(b=>b.id===effectiveBranch):null;
    const branchLabel=branchObj?branchObj.name:'All Branches';
    const mLoans=AL.filter(l=>toDS(l.start_date).startsWith(month));
    const mRep=AR.filter(r=>toDS(r.date).startsWith(month));
    const mExp=AE.filter(e=>toDS(e.date).startsWith(month));
    const mAF=AAF.filter(a=>toDS(a.date).startsWith(month));
    const mFines=mAF.filter(a=>(a.notes||'').toLowerCase().includes('fine'));
    const mStd=mAF.filter(a=>!(a.notes||'').toLowerCase().includes('fine'));
    const mApp=AAPF.filter(a=>toDS(a.created_at).startsWith(month));

    const totalOut=$n(activeLoans.reduce((s,l)=>s+glBal(l),0));
    const stdFeesM=$n(mStd.reduce((s,a)=>s+Number(a.amount),0));
    const finesM=$n(mFines.reduce((s,a)=>s+Number(a.amount),0));
    const appFeesM=$n(mApp.reduce((s,a)=>s+Number(a.amount),0));
    const totalIncM=$n(stdFeesM+finesM+appFeesM);
    const totalExpM=$n(mExp.reduce((s,e)=>s+Number(e.amount),0));
    const lastMD=new Date(year,mNum-2,1);
    const lastMS=lastMD.getFullYear()+'-'+String(lastMD.getMonth()+1).padStart(2,'0');
    const lastInc=$n(AAF.filter(a=>toDS(a.date).startsWith(lastMS)).reduce((s,a)=>s+Number(a.amount),0));
    const lastExp=$n(AE.filter(e=>toDS(e.date).startsWith(lastMS)).reduce((s,e)=>s+Number(e.amount),0));
    const ytdStr=String(year)+'-';
    const ytdInc=$n(AAF.filter(a=>toDS(a.date).startsWith(ytdStr)).reduce((s,a)=>s+Number(a.amount),0));
    const ytdExp=$n(AE.filter(e=>toDS(e.date).startsWith(ytdStr)).reduce((s,e)=>s+Number(e.amount),0));
    const par30=$n(overdueLoans.filter(l=>daysOvd(l)>30).reduce((s,l)=>s+glBal(l),0));
    const par90=$n(overdueLoans.filter(l=>daysOvd(l)>90).reduce((s,l)=>s+glBal(l),0));
    const par30pct=totalOut>0?((par30/totalOut)*100).toFixed(1)+'%':'0.0%';
    const par90pct=totalOut>0?((par90/totalOut)*100).toFixed(1)+'%':'0.0%';

    const wb=new ExcelJS.Workbook();
    await wb.xlsx.load(Buffer.from(_REPORT_TPL_B64,'base64'));

    // Guide
    const wsG=wb.getWorksheet('📋 Guide');
    if(wsG) wsG.getCell('B6').value=`Branch: ${branchLabel}          Month: ${monthName}          Year: ${year}`;

    // Dashboard
    const wsD=wb.getWorksheet('📊 Dashboard');
    if(wsD){
      wsD.getCell('B6').value=totalOut; wsD.getCell('C6').value=activeLoans.length;
      wsD.getCell('D6').value=activeLoans.length?$n(totalOut/activeLoans.length):0;
      wsD.getCell('E6').value=AC.length;
      wsD.getCell('F6').value=$n(mLoans.reduce((s,l)=>s+Number(l.amount),0));
      wsD.getCell('G6').value=$n(mRep.reduce((s,r)=>s+Number(r.amount),0));
      wsD.getCell('H6').value=par30pct; wsD.getCell('I6').value=par90pct; wsD.getCell('J6').value='0.0%';
      for(let i=0;i<12;i++){
        const ms=year+'-'+String(i+1).padStart(2,'0');
        const ml=AL.filter(l=>toDS(l.start_date).startsWith(ms));
        const mr=AR.filter(r=>toDS(r.date).startsWith(ms));
        const maf2=AAF.filter(a=>toDS(a.date).startsWith(ms));
        const me2=AE.filter(e=>toDS(e.date).startsWith(ms));
        const row=12+i;
        wsD.getCell(`C${row}`).value=$n(ml.reduce((s,l)=>s+Number(l.amount),0))||null;
        wsD.getCell(`D${row}`).value=$n(mr.reduce((s,r)=>s+Number(r.amount),0))||null;
        wsD.getCell(`F${row}`).value=ml.length||null;
        const net=$n(maf2.reduce((s,a)=>s+Number(a.amount),0)-me2.reduce((s,e)=>s+Number(e.amount),0));
        wsD.getCell(`J${row}`).value=net||null;
      }
    }

    // Loan Book
    const wsLB=wb.getWorksheet('📋 Loan Book');
    if(wsLB){
      activeLoans.forEach((l,i)=>{
        const c=AC.find(c=>c.id===l.client_id);
        const days=daysOvd(l);
        const status=days>90?'NPL (>90 days)':days>60?'At Risk (61-90 days)':days>30?'Watch (31-60 days)':days>0?'Watch (1-30 days)':'Active - Current';
        const r=6+i;
        wsLB.getCell(`A${r}`).value=shortL(l.id); wsLB.getCell(`B${r}`).value=shortC(l.client_id);
        wsLB.getCell(`C${r}`).value=c?.name||'—'; wsLB.getCell(`D${r}`).value=bname(l.branch_id);
        wsLB.getCell(`E${r}`).value=oname(l.added_by); wsLB.getCell(`F${r}`).value=toDS(l.start_date);
        wsLB.getCell(`G${r}`).value=matDate(l); wsLB.getCell(`H${r}`).value=$n(Number(l.amount));
        wsLB.getCell(`I${r}`).value=l.interest_rate+'%';
        wsLB.getCell(`J${r}`).value=`${l.term} ${l.term_frequency||'monthly'}`;
        wsLB.getCell(`K${r}`).value=$n(glBal(l)); wsLB.getCell(`L${r}`).value=$n(glPaid(l.id));
        wsLB.getCell(`M${r}`).value=nextPay(l);
        if(days>0) wsLB.getCell(`N${r}`).value=days;
        wsLB.getCell(`O${r}`).value=status;
      });
    }

    // Disbursements
    const wsDisb=wb.getWorksheet('💰 Disbursements');
    if(wsDisb){
      mLoans.forEach((l,i)=>{
        const c=AC.find(c=>c.id===l.client_id); const r=5+i;
        wsDisb.getCell(`A${r}`).value=i+1; wsDisb.getCell(`B${r}`).value=shortL(l.id);
        wsDisb.getCell(`C${r}`).value=c?.name||'—'; wsDisb.getCell(`D${r}`).value=shortC(l.client_id);
        wsDisb.getCell(`E${r}`).value=bname(l.branch_id); wsDisb.getCell(`F${r}`).value=oname(l.added_by);
        wsDisb.getCell(`G${r}`).value=$n(Number(l.amount)); wsDisb.getCell(`H${r}`).value=l.interest_rate+'%';
        wsDisb.getCell(`I${r}`).value=`${l.term} ${l.term_frequency||'monthly'}`;
        wsDisb.getCell(`J${r}`).value=l.purpose||'';
      });
      wsDisb.getCell('G35').value=$n(mLoans.reduce((s,l)=>s+Number(l.amount),0));
    }

    // Collections
    const wsCol=wb.getWorksheet('✅ Collections');
    if(wsCol){
      mRep.forEach((r2,i)=>{
        const l=AL.find(l=>l.id===r2.loan_id); const c=l?AC.find(c=>c.id===l.client_id):null; const r=5+i;
        wsCol.getCell(`A${r}`).value=i+1; wsCol.getCell(`B${r}`).value=l?shortL(l.id):'—';
        wsCol.getCell(`C${r}`).value=c?.name||'—'; wsCol.getCell(`D${r}`).value=l?bname(l.branch_id):'—';
        wsCol.getCell(`E${r}`).value=toDS(r2.date); wsCol.getCell(`F${r}`).value=$n(Number(r2.amount));
      });
    }

    // Arrears
    const wsArr=wb.getWorksheet('⚠ Arrears');
    if(wsArr){
      const arrDetail=overdueLoans.map(l=>{
        const days=daysOvd(l),c=AC.find(c=>c.id===l.client_id),bal=glBal(l);
        const bucket=days>90?'>90 Days (NPL)':days>60?'61-90 Days':days>30?'31-60 Days':'1-30 Days';
        return{l,c,days,bal,bucket};
      }).sort((a,b)=>b.days-a.days);
      const b1=arrDetail.filter(x=>x.days<=30),b2=arrDetail.filter(x=>x.days>30&&x.days<=60);
      const b3=arrDetail.filter(x=>x.days>60&&x.days<=90),b4=arrDetail.filter(x=>x.days>90);
      const bStr=arr=>`${arr.length} / $${$n(arr.reduce((s,x)=>s+x.bal,0))}`;
      wsArr.getCell('C5').value=bStr(b1); wsArr.getCell('D5').value=bStr(b2);
      wsArr.getCell('E5').value=bStr(b3); wsArr.getCell('F5').value=bStr(b4);
      arrDetail.forEach((x,i)=>{
        const r=8+i;
        wsArr.getCell(`A${r}`).value=i+1; wsArr.getCell(`B${r}`).value=shortL(x.l.id);
        wsArr.getCell(`C${r}`).value=x.c?.name||'—'; wsArr.getCell(`D${r}`).value=bname(x.l.branch_id);
        wsArr.getCell(`E${r}`).value=oname(x.l.added_by); wsArr.getCell(`F${r}`).value=$n(x.bal);
        wsArr.getCell(`G${r}`).value=$n(x.bal); wsArr.getCell(`H${r}`).value=x.days;
        wsArr.getCell(`I${r}`).value=x.bucket;
      });
    }

    // Clients
    const wsCli=wb.getWorksheet('👤 Clients');
    if(wsCli){
      AC.forEach((c,i)=>{
        const cL=AL.filter(l=>l.client_id===c.id),cA=cL.filter(l=>glStatus(l)!=='completed');
        const r=5+i;
        wsCli.getCell(`A${r}`).value=i+1; wsCli.getCell(`B${r}`).value=shortC(c.id);
        wsCli.getCell(`C${r}`).value=c.name; wsCli.getCell(`F${r}`).value=c.phone||'';
        wsCli.getCell(`G${r}`).value=bname(c.branch_id); wsCli.getCell(`H${r}`).value=oname(c.added_by);
        wsCli.getCell(`I${r}`).value=c.national_id||''; wsCli.getCell(`J${r}`).value=cL.length;
        wsCli.getCell(`K${r}`).value=cA.length; wsCli.getCell(`L${r}`).value=cA.length>0?'Active':'Completed';
      });
    }

    // Branch Summary
    const wsBr=wb.getWorksheet('🏢 Branch Summary');
    if(wsBr){
      const branchRowMap={'Harare':5,'Bulawayo':6,'Kwekwe':7};
      ABR.forEach(b=>{
        const brow=branchRowMap[b.name]; if(!brow) return;
        const bl=AL.filter(l=>l.branch_id===b.id),ba=bl.filter(l=>glStatus(l)!=='completed');
        const bOut=$n(ba.reduce((s,l)=>s+glBal(l),0));
        const bDisb=$n(bl.filter(l=>toDS(l.start_date).startsWith(month)).reduce((s,l)=>s+Number(l.amount),0));
        const bColl=$n(AR.filter(r=>bl.find(l=>l.id===r.loan_id)&&toDS(r.date).startsWith(month)).reduce((s,r)=>s+Number(r.amount),0));
        const bNew=bl.filter(l=>toDS(l.start_date).startsWith(month)).length;
        const bCli=AC.filter(c=>c.branch_id===b.id).length;
        const bP30=ba.filter(l=>daysOvd(l)>30);
        const bPar=$n(bOut>0?bP30.reduce((s,l)=>s+glBal(l),0)/bOut*100:0);
        const bExp=$n(AE.filter(e=>e.branch_id===b.id&&toDS(e.date).startsWith(month)).reduce((s,e)=>s+Number(e.amount),0));
        const bInc=$n(AAF.filter(a=>bl.find(l=>l.id===a.loan_id)&&toDS(a.date).startsWith(month)).reduce((s,a)=>s+Number(a.amount),0));
        wsBr.getCell(`B${brow}`).value=bOut; wsBr.getCell(`C${brow}`).value=bDisb;
        wsBr.getCell(`D${brow}`).value=bColl; wsBr.getCell(`E${brow}`).value=bNew;
        wsBr.getCell(`F${brow}`).value=bCli; wsBr.getCell(`G${brow}`).value=bPar;
        wsBr.getCell(`H${brow}`).value=bExp; wsBr.getCell(`I${brow}`).value=$n(bInc-bExp);
      });
    }

    // Officer Performance
    const wsOff=wb.getWorksheet('👔 Officer Performance');
    if(wsOff){
      const officers=AU.filter(u=>u.role==='loan_officer'||u.role==='admin');
      officers.slice(0,15).forEach((u,i)=>{
        const uL=AL.filter(l=>String(l.added_by)===String(u.id));
        const uA=uL.filter(l=>glStatus(l)!=='completed');
        const uPort=$n(uA.reduce((s,l)=>s+glBal(l),0));
        const uCli=AC.filter(c=>String(c.added_by)===String(u.id)).length;
        const uNew=uL.filter(l=>toDS(l.start_date).startsWith(month)).length;
        let uDue=0;
        uA.forEach(l=>{buildAmort(l).filter(r=>r.dueDate.startsWith(month)).forEach(r=>{uDue+=r.principal+r.interest;});});
        const uColl=$n(AR.filter(r=>uL.find(l=>l.id===r.loan_id)&&toDS(r.date).startsWith(month)).reduce((s,r)=>s+Number(r.amount),0));
        const uP30=uA.filter(l=>daysOvd(l)>30);
        const uPar=$n(uPort>0?uP30.reduce((s,l)=>s+glBal(l),0)/uPort*100:0);
        const r=5+i;
        wsOff.getCell(`A${r}`).value=u.full_name||u.username; wsOff.getCell(`B${r}`).value=u.branch_id?bname(u.branch_id):'—';
        wsOff.getCell(`C${r}`).value=uPort; wsOff.getCell(`D${r}`).value=uCli;
        wsOff.getCell(`E${r}`).value=uNew; wsOff.getCell(`F${r}`).value=$n(uDue);
        wsOff.getCell(`G${r}`).value=uColl; wsOff.getCell(`I${r}`).value=uPar;
      });
    }

    // P&L
    const wsPL=wb.getWorksheet('💹 P&L');
    if(wsPL){
      wsPL.getCell('B6').value=stdFeesM; wsPL.getCell('B7').value=appFeesM;
      wsPL.getCell('B8').value=finesM; wsPL.getCell('C6').value=lastInc;
      wsPL.getCell('D6').value=ytdInc; wsPL.getCell('B21').value=totalExpM;
      wsPL.getCell('C21').value=lastExp; wsPL.getCell('D21').value=ytdExp;
    }

    const fname=`Credinova_Monthly_Report_${month}${effectiveBranch?'_'+branchLabel:''}.xlsx`;
    res.setHeader('Content-Disposition',`attachment; filename="${fname}"`);
    res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    await wb.xlsx.write(res);

  }catch(err){
    console.error('[REPORT]',err.message);
    res.status(500).json({error:err.message});
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
