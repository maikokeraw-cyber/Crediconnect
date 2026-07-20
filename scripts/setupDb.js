// ================================================================
//  CrediConnect v4.0 — Database Setup Script
//  Runs automatically on every Render deploy (safe — uses IF NOT EXISTS)
// ================================================================

require('dotenv').config();
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

async function setup() {
  const client = await pool.connect();
  console.log('🔧  Running database setup…');

  try {
    await client.query('BEGIN');

    // ── Branches ─────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS branches (
        id         VARCHAR(50)  PRIMARY KEY,
        name       VARCHAR(200) NOT NULL UNIQUE,
        active     BOOLEAN      NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      )
    `);

    // ── Users ────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id           VARCHAR(50)  PRIMARY KEY,
        username     VARCHAR(100) NOT NULL UNIQUE,
        full_name    VARCHAR(200) NOT NULL,
        role         VARCHAR(20)  NOT NULL DEFAULT 'viewer'
                     CHECK (role IN ('super_admin','admin','loan_officer','viewer')),
        branch_id    VARCHAR(50)  NULL REFERENCES branches(id),
        password_hash VARCHAR(200) NOT NULL,
        active       BOOLEAN      NOT NULL DEFAULT TRUE,
        last_login   TIMESTAMPTZ  NULL,
        created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        created_by   VARCHAR(50)  NULL
      )
    `);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS branch_id VARCHAR(50) REFERENCES branches(id)`);
    await client.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check`);
    await client.query(`ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('super_admin','admin','loan_officer','viewer'))`);

    // ── Clients ──────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS clients (
        id          VARCHAR(50)  PRIMARY KEY,
        name        VARCHAR(200) NOT NULL,
        phone       VARCHAR(50)  NOT NULL,
        national_id VARCHAR(100) NULL,
        email       VARCHAR(200) NULL,
        address     VARCHAR(500) NULL,
        occupation  VARCHAR(200) NULL,
        dob         DATE         NULL,
        date_added  DATE         NOT NULL DEFAULT CURRENT_DATE,
        branch_id   VARCHAR(50)  NULL REFERENCES branches(id),
        added_by    VARCHAR(50)  NULL,
        created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS branch_id VARCHAR(50) REFERENCES branches(id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_clients_branch ON clients(branch_id)`);

    // ── Loans ────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS loans (
        id             VARCHAR(50)    PRIMARY KEY,
        client_id      VARCHAR(50)    NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        branch_id      VARCHAR(50)    NULL REFERENCES branches(id),
        amount         NUMERIC(18,2)  NOT NULL,
        interest_rate  NUMERIC(5,2)   NOT NULL,
        term           INTEGER        NOT NULL,
        term_frequency VARCHAR(10)    NOT NULL DEFAULT 'monthly',
        start_date     DATE           NOT NULL,
        purpose        VARCHAR(500)   NULL,
        notes          VARCHAR(1000)  NULL,
        admin_fees     NUMERIC(18,2)  NOT NULL DEFAULT 0,
        admin_fees_status VARCHAR(10) NOT NULL DEFAULT 'none',
        status         VARCHAR(20)    NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','completed','defaulted')),
        added_by       VARCHAR(50)    NULL,
        created_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
        updated_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`ALTER TABLE loans ADD COLUMN IF NOT EXISTS term_frequency VARCHAR(10) NOT NULL DEFAULT 'monthly'`);
    await client.query(`ALTER TABLE loans ADD COLUMN IF NOT EXISTS admin_fees NUMERIC(18,2) NOT NULL DEFAULT 0`);
    await client.query(`ALTER TABLE loans ADD COLUMN IF NOT EXISTS admin_fees_status VARCHAR(10) NOT NULL DEFAULT 'none'`);
    await client.query(`ALTER TABLE loans ADD COLUMN IF NOT EXISTS repayment_start_date DATE`);
    await client.query(`ALTER TABLE admin_fee_payments ADD COLUMN IF NOT EXISTS collected BOOLEAN NOT NULL DEFAULT FALSE`);
    await client.query(`ALTER TABLE admin_fee_payments ADD COLUMN IF NOT EXISTS waived BOOLEAN NOT NULL DEFAULT FALSE`);
    await client.query(`ALTER TABLE admin_fee_payments ADD COLUMN IF NOT EXISTS waive_reason TEXT`);
    await client.query(`ALTER TABLE admin_fee_payments ADD COLUMN IF NOT EXISTS waived_by VARCHAR(100)`);
    await client.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS phone2 VARCHAR(20)`);
    await client.query(`ALTER TABLE loans ADD COLUMN IF NOT EXISTS branch_id VARCHAR(50) REFERENCES branches(id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_loans_client_id ON loans(client_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_loans_status    ON loans(status)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_loans_branch    ON loans(branch_id)`);

    // ── Repayments ───────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS repayments (
        id         VARCHAR(50)   PRIMARY KEY,
        loan_id    VARCHAR(50)   NOT NULL REFERENCES loans(id) ON DELETE CASCADE,
        amount     NUMERIC(18,2) NOT NULL,
        date       DATE          NOT NULL,
        notes      VARCHAR(500)  NULL,
        added_by   VARCHAR(50)   NULL,
        created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_repayments_loan_id ON repayments(loan_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_repayments_date    ON repayments(date)`);
    await client.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);

    // ── Expenses ─────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS expenses (
        id          VARCHAR(50)   PRIMARY KEY,
        amount      NUMERIC(18,2) NOT NULL,
        category    VARCHAR(100)  NOT NULL,
        description VARCHAR(500)  NULL,
        date        DATE          NOT NULL,
        branch_id   VARCHAR(50)   NULL REFERENCES branches(id),
        added_by    VARCHAR(50)   NULL,
        created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`ALTER TABLE expenses ADD COLUMN IF NOT EXISTS branch_id VARCHAR(50) REFERENCES branches(id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_expenses_branch ON expenses(branch_id)`);

    // ── Admin Fee Payments ────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_fee_payments (
        id         VARCHAR(50)   PRIMARY KEY,
        loan_id    VARCHAR(50)   NOT NULL REFERENCES loans(id) ON DELETE CASCADE,
        amount     NUMERIC(18,2) NOT NULL,
        date       DATE          NOT NULL,
        notes      VARCHAR(500)  NULL,
        added_by   VARCHAR(50)   NULL,
        created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_admin_fee_loan_id ON admin_fee_payments(loan_id)`);

    // ── Audit Log ────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id         SERIAL        PRIMARY KEY,
        user_id    VARCHAR(50)   NULL,
        username   VARCHAR(100)  NULL,
        branch_id  VARCHAR(50)   NULL,
        action     VARCHAR(100)  NOT NULL,
        entity     VARCHAR(50)   NULL,
        entity_id  VARCHAR(50)   NULL,
        detail     VARCHAR(1000) NULL,
        created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS branch_id VARCHAR(50)`);

    // ── Mobile App Tables ─────────────────────────────────────────
    await client.query(`CREATE TABLE IF NOT EXISTS mobile_customers (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),name TEXT,phone TEXT UNIQUE,national_id TEXT UNIQUE,email TEXT,password TEXT,status TEXT DEFAULT 'active',expo_push_token TEXT,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await client.query(`ALTER TABLE mobile_customers ADD COLUMN IF NOT EXISTS expo_push_token TEXT`);
    await client.query(`CREATE TABLE IF NOT EXISTS mobile_loan_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),customer_id UUID REFERENCES mobile_customers(id),amount NUMERIC,interest_rate NUMERIC,term INTEGER,term_frequency TEXT,purpose TEXT,notes TEXT,status TEXT DEFAULT 'pending',reviewer_notes TEXT,reviewed_by TEXT,reviewed_at TIMESTAMPTZ,disbursed_at TIMESTAMPTZ,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await client.query(`ALTER TABLE mobile_loan_requests ADD COLUMN IF NOT EXISTS application_fee NUMERIC(18,2) NOT NULL DEFAULT 0`);
    await client.query(`ALTER TABLE mobile_loan_requests ADD COLUMN IF NOT EXISTS admin_fees NUMERIC(18,2) NOT NULL DEFAULT 0`);
    await client.query(`ALTER TABLE mobile_loan_requests ADD COLUMN IF NOT EXISTS source VARCHAR(10) NOT NULL DEFAULT 'mobile'`);
    await client.query(`ALTER TABLE mobile_loan_requests ADD COLUMN IF NOT EXISTS created_by VARCHAR(100)`);
    await client.query(`ALTER TABLE mobile_loan_requests ADD COLUMN IF NOT EXISTS branch_id VARCHAR(50) REFERENCES branches(id)`);
    await client.query(`ALTER TABLE mobile_loan_requests ADD COLUMN IF NOT EXISTS linked_client_id VARCHAR(50) REFERENCES clients(id)`);
    await client.query(`ALTER TABLE mobile_loan_requests ADD COLUMN IF NOT EXISTS linked_loan_id VARCHAR(50) REFERENCES loans(id)`);
    await client.query(`CREATE TABLE IF NOT EXISTS mobile_repayments (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),loan_id UUID REFERENCES mobile_loan_requests(id),customer_id UUID REFERENCES mobile_customers(id),amount NUMERIC,date DATE,method TEXT,reference TEXT,notes TEXT,created_at TIMESTAMPTZ DEFAULT NOW())`);
    await client.query(`CREATE TABLE IF NOT EXISTS mobile_notifications (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),customer_id UUID REFERENCES mobile_customers(id),title TEXT,body TEXT,type TEXT,read BOOLEAN DEFAULT FALSE,created_at TIMESTAMPTZ DEFAULT NOW())`);
    await client.query(`CREATE TABLE IF NOT EXISTS mobile_documents (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),customer_id UUID REFERENCES mobile_customers(id),loan_id UUID REFERENCES mobile_loan_requests(id),doc_type TEXT,filename TEXT,url TEXT,created_at TIMESTAMPTZ DEFAULT NOW())`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_mobile_loan_customer ON mobile_loan_requests(customer_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_mobile_loan_status ON mobile_loan_requests(status)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_mobile_repay_loan ON mobile_repayments(loan_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_mobile_notif_customer ON mobile_notifications(customer_id)`);

    await client.query('COMMIT');
    console.log('✅  All tables ready.');

    // ── Seed Branches ─────────────────────────────────────────────
    const branchCheck = await client.query('SELECT COUNT(*) AS cnt FROM branches');
    if (parseInt(branchCheck.rows[0].cnt) === 0) {
      const hId = uuidv4(), bId = uuidv4();
      await client.query(`INSERT INTO branches (id,name) VALUES ($1,$2),($3,$4)`,
        [hId, 'Harare', bId, 'Bulawayo']);
      console.log('✅  Branches seeded: Harare, Bulawayo');
    }

    // ── Seed Default Super Admin ──────────────────────────────────
    const userCheck = await client.query('SELECT COUNT(*) AS cnt FROM users');
    if (parseInt(userCheck.rows[0].cnt) === 0) {
      const hash = await bcrypt.hash('Admin@1234', 10);
      await client.query(
        `INSERT INTO users (id,username,full_name,role,password_hash) VALUES ($1,$2,$3,$4,$5)`,
        [uuidv4(), 'superadmin', 'Super Administrator', 'super_admin', hash]
      );
      console.log('✅  Default super admin created — username: superadmin  password: Admin@1234');
    }

    // ── Update existing data to assign Harare branch if null ─────
    const { rows: branches } = await client.query(`SELECT id FROM branches WHERE name='Harare' LIMIT 1`);
    if (branches.length > 0) {
      const hId = branches[0].id;
      await client.query(`UPDATE clients  SET branch_id=$1 WHERE branch_id IS NULL`, [hId]);
      await client.query(`UPDATE loans    SET branch_id=$1 WHERE branch_id IS NULL`, [hId]);
      await client.query(`UPDATE expenses SET branch_id=$1 WHERE branch_id IS NULL`, [hId]);
      console.log('✅  Existing data assigned to Harare branch.');
    }

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌  Database setup failed:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
  console.log('🚀  Database setup complete.\n');
}

setup();
