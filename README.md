# CrediConnect v3.0
### Microfinance Management System
**Stack:** Node.js · Express · PostgreSQL (Supabase) · Deployed on Render

---

## Overview
CrediConnect is a full-stack microfinance management system with:
- Role-based login (Admin, Loan Officer, Viewer)
- Client & loan management
- Repayment tracking
- Expense tracking
- Financial overview & reports
- Audit log
- Supabase PostgreSQL database
- Hosted free on Render

---

## Deployment: Step-by-Step

### STEP 1 — Create a Supabase database

1. Go to **https://supabase.com** and sign up (free)
2. Click **"New Project"**
3. Fill in:
   - **Name:** crediconnect
   - **Database Password:** choose a strong password and save it
   - **Region:** pick one closest to Zimbabwe (Europe West is fine)
4. Click **"Create new project"** and wait ~2 minutes
5. Once ready, go to: **Settings → Database**
6. Scroll to **"Connection string"** → select **URI** tab
7. Copy the connection string — it looks like:
   ```
   postgresql://postgres.[ref]:[YOUR-PASSWORD]@aws-0-eu-west-1.pooler.supabase.com:5432/postgres
   ```
   Replace `[YOUR-PASSWORD]` with the password you set in step 3
8. **Save this string** — you'll need it in Step 3

---

### STEP 2 — Push code to GitHub

1. Go to **https://github.com** and sign up / sign in
2. Click **"New repository"**
3. Name it: `crediconnect`
4. Set it to **Public** (required for Render free tier)
5. Click **"Create repository"**
6. On your computer, install **Git** from https://git-scm.com if you don't have it
7. Open **Command Prompt** in the project folder and run:

```bash
git init
git add .
git commit -m "Initial commit — CrediConnect v3.0"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/crediconnect.git
git push -u origin main
```
Replace `YOUR-USERNAME` with your GitHub username.

---

### STEP 3 — Deploy on Render

1. Go to **https://render.com** and sign up with your GitHub account
2. Click **"New +"** → **"Web Service"**
3. Select your `crediconnect` repository
4. Fill in:
   - **Name:** crediconnect
   - **Region:** Oregon (US West)
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `node scripts/setupDb.js && npm start`
   - **Plan:** Free
5. Scroll down to **"Environment Variables"** and add:

   | Key | Value |
   |-----|-------|
   | `DATABASE_URL` | *(paste your Supabase connection string from Step 1)* |
   | `JWT_SECRET` | *(any long random text, e.g. `myCompanyCrediConnect2024SecretKey!`)* |
   | `DB_SSL` | `true` |
   | `JWT_EXPIRES_IN` | `8h` |
   | `NODE_ENV` | `production` |

6. Click **"Create Web Service"**
7. Render will build and deploy — takes about 2 minutes
8. Your app will be live at:
   ```
   https://crediconnect.onrender.com
   ```
   (or similar URL shown in the Render dashboard)

---

### STEP 4 — First Login

Once deployed, open your Render URL and sign in with:

| Username | Password |
|----------|----------|
| `admin` | `Admin@1234` |

**Important:** Change the admin password immediately via **My Profile → Change Password**

---

## Updating the App

When you make changes to the code:
```bash
git add .
git commit -m "Description of changes"
git push
```
Render will automatically redeploy within 1–2 minutes.

---

## Project Structure

```
crediconnect/
├── server.js              ← Express API server
├── render.yaml            ← Render deployment config
├── package.json           ← Node dependencies
├── .env.example           ← Environment variable template
├── .gitignore             ← Files excluded from GitHub
├── scripts/
│   └── setupDb.js         ← Creates all database tables on deploy
└── public/
    └── index.html         ← Full frontend application
```

## Database Tables (created automatically)

| Table | Description |
|-------|-------------|
| `users` | Login accounts with roles |
| `clients` | Client profiles |
| `loans` | Loan records |
| `repayments` | Payment records |
| `expenses` | Operating expense records |
| `audit_log` | All actions with user + timestamp |

---

## User Roles

| Permission | Admin | Loan Officer | Viewer |
|---|:---:|:---:|:---:|
| View all data | ✅ | ✅ | ✅ |
| Add clients & loans | ✅ | ✅ | ❌ |
| Record repayments | ✅ | ✅ | ❌ |
| Record expenses | ✅ | ✅ | ❌ |
| Delete records | ✅ | ❌ | ❌ |
| Financial overview | ✅ | ❌ | ❌ |
| Reports & analytics | ✅ | ❌ | ❌ |
| User management | ✅ | ❌ | ❌ |
| Audit log | ✅ | ❌ | ❌ |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| "Database not connected" on login | Check DATABASE_URL in Render environment variables |
| App won't start on Render | Check Render logs → "Logs" tab in dashboard |
| Password forgotten | In Supabase dashboard → SQL editor → run: `UPDATE users SET password_hash='...' WHERE username='admin'` |
| Render app sleeps after 15min | Free tier limitation — upgrade to Starter ($7/mo) to keep it awake |
| SSL errors | Make sure DB_SSL=true is set in Render environment |
