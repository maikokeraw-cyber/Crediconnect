// ================================================================
//  CrediConnect — Database Setup Script
//  Runs automatically on every Render deploy (safe — uses IF NOT EXISTS)
//  Can also be run manually: node scripts/setupDb.js
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

    // ── Users ────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            VARCHAR(50)  PRIMARY KEY,
        username      VARCHAR(100) NOT NULL UNIQUE,
        full_name     VARCHAR(200) NOT NULL,
        role          VARCHAR(20)  NOT NULL DEFAULT 'viewer'
                      CHECK (role IN ('admin','loan_officer','viewer')),
        password_hash VARCHAR(200) NOT NULL,
        active        BOOLEAN      NOT NULL DEFAULT TRUE,
        last_login    TIMESTAMPTZ  NULL,
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        created_by    VARCHAR(50)  NULL
      )
    `);

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
        added_by    VARCHAR(50)  NULL,
        created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      )
    `);

    // ── Loans ────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS loans (
        id             VARCHAR(50)    PRIMARY KEY,
        client_id      VARCHAR(50)    NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        amount         NUMERIC(18,2)  NOT NULL,
        interest_rate  NUMERIC(5,2)   NOT NULL,
        term           INTEGER        NOT NULL,
        term_frequency VARCHAR(10)    NOT NULL DEFAULT 'monthly',
        start_date     DATE           NOT NULL,
        purpose        VARCHAR(500)   NULL,
        notes          VARCHAR(1000)  NULL,
        admin_fees     NUMERIC(18,2)  NULL DEFAULT 0,
        status         VARCHAR(20)    NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','completed','defaulted')),
        added_by       VARCHAR(50)    NULL,
        created_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
        updated_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_loans_client_id ON loans(client_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_loans_status    ON loans(status)`);
    // Add new columns if upgrading from earlier version
    await client.query(`ALTER TABLE loans ADD COLUMN IF NOT EXISTS term_frequency VARCHAR(10) NOT NULL DEFAULT 'monthly'`);
    await client.query(`ALTER TABLE loans ADD COLUMN IF NOT EXISTS admin_fees NUMERIC(18,2) NOT NULL DEFAULT 0`);

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
    // Safety: ensure updated_at exists on clients
    await client.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);

    // ── Expenses ─────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS expenses (
        id          VARCHAR(50)   PRIMARY KEY,
        amount      NUMERIC(18,2) NOT NULL,
        category    VARCHAR(100)  NOT NULL,
        description VARCHAR(500)  NULL,
        date        DATE          NOT NULL,
        added_by    VARCHAR(50)   NULL,
        created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_expenses_date     ON expenses(date)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(category)`);

    // ── Audit Log ────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id         SERIAL       PRIMARY KEY,
        user_id    VARCHAR(50)  NULL,
        username   VARCHAR(100) NULL,
        action     VARCHAR(100) NOT NULL,
        entity     VARCHAR(50)  NULL,
        entity_id  VARCHAR(50)  NULL,
        detail     VARCHAR(1000) NULL,
        created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      )
    `);

    await client.query('COMMIT');
    console.log('✅  All tables ready.');

    // ── Seed default admin if no users exist ─────────────────────
    const { rows } = await client.query('SELECT COUNT(*) AS cnt FROM users');
    if (parseInt(rows[0].cnt) === 0) {
      const hash = await bcrypt.hash('Admin@1234', 10);
      await client.query(
        `INSERT INTO users (id, username, full_name, role, password_hash)
         VALUES ($1, $2, $3, $4, $5)`,
        [uuidv4(), 'admin', 'System Administrator', 'admin', hash]
      );
      console.log('✅  Default admin created — username: admin  password: Admin@1234');
    } else {
      console.log('ℹ️   Users already exist, skipping seed.');
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
