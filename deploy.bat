@echo off
title CrediConnect — Deploy to Render
color 0A

echo.
echo  ================================
echo   CrediConnect Auto-Deploy
echo  ================================
echo.

REM ── Move to the project folder ──────────────────────────────────
REM Change this path if your folder is somewhere else
cd /d "C:\crediconnect-final"

REM ── Check git is installed ───────────────────────────────────────
git --version >nul 2>&1
if errorlevel 1 (
  echo  ERROR: Git is not installed.
  echo  Download it from https://git-scm.com
  pause
  exit
)

REM ── Pull latest (in case of conflicts) ──────────────────────────
echo  Pulling latest from GitHub...
git pull origin main --quiet

REM ── Stage all changes ────────────────────────────────────────────
echo  Staging changes...
git add .

REM ── Check if there is anything to commit ─────────────────────────
git diff --cached --quiet
if errorlevel 1 (
  REM There are changes — commit and push
  echo  Committing changes...
  git commit -m "Update — %DATE% %TIME%"

  echo  Pushing to GitHub...
  git push origin main

  if errorlevel 1 (
    echo.
    echo  ERROR: Push failed. Check your internet connection
    echo  or GitHub credentials and try again.
    pause
    exit
  )

  echo.
  echo  ================================
  echo   SUCCESS! Deployed to GitHub.
  echo   Render will update in ~2 mins.
  echo  ================================
  echo.
) else (
  echo.
  echo  No changes found — nothing to deploy.
  echo.
)

echo  Press any key to close...
pause >nul
