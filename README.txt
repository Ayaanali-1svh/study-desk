STUDY DESK — CLOUD HOMEWORK PLANNER
===================================

This version adds real accounts, password sign-in, five-digit email verification,
and cloud storage. It no longer stores account or homework data in localStorage.

WHAT IT DOES
------------
- Students create an account with their name, email address, and password.
- A five-digit code is emailed to the address entered during sign-up.
- The code expires after 10 minutes and can only be used once.
- Passwords are hashed before they are saved; they are never stored as plain text.
- Accounts, assignments, and study sessions are stored in PostgreSQL.
- The same account can sign in from a different browser or device and access the
  same planner data.
- While the planner is open, it checks for changes from other browsers every
  15 seconds.
- The dashboard starts empty. It does not add sample homework.

IMPORTANT: THIS IS A FULL-STACK WEBSITE
---------------------------------------
HTML and CSS alone cannot send emails, verify accounts, or share data between
browsers. This project includes a Node.js server and needs an online PostgreSQL
database plus an email-sending service before account creation will work.

SETUP
-----
1. Install Node.js 20 or newer.
2. Create a hosted PostgreSQL database with a provider such as Neon or Supabase.
3. Create an email-sending account with Resend and add/verify a sender domain.
4. Copy .env.example to a file named .env.
5. Fill in the values in .env:
   - DATABASE_URL: your PostgreSQL connection string.
   - SESSION_SECRET: a long random secret (at least 32 characters).
   - OTP_SECRET: a different long random secret (at least 32 characters).
   You can generate each secret in a terminal with:
      node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   - RESEND_API_KEY: the private API key from your email provider.
   - EMAIL_FROM: a sender address on the domain you verified with Resend.
6. In a terminal opened in this project folder, run:
      npm install
      npm start
7. Open http://localhost:3000 in your browser.

The server creates the required database tables automatically when it starts.
Do not upload your .env file or share its values. In particular, never put the
Resend API key, database password, or session secrets in public frontend files.

EMAIL SENDING NOTE
------------------
Resend requires a verified sender domain for normal delivery. Until that has
been configured, sign-up emails may not be delivered. The five-digit message is
sent by the server, not by the browser.

DEPLOYMENT FOR CROSS-BROWSER USE
-------------------------------
To use the same account on different browsers/devices, deploy this project to
an HTTPS Node.js host and keep the hosted PostgreSQL database and email service
connected. Set the same environment variables in the hosting dashboard. Then
open the deployed website URL in each browser and sign in with the same email
and password. Each browser gets its own secure sign-in cookie; the account and
planner data remain in the shared database.

LOCAL TESTING
-------------
You can test the layout locally after installing the dependencies, but account
creation and email codes will only work once DATABASE_URL, the two secrets, the
Resend API key, and a verified EMAIL_FROM address have been configured.

PROJECT FILES
-------------
public/index.html   Page structure and forms
public/style.css    Responsive website design
public/app.js       Browser-side interactions and API requests
server.js           Account, email-code, session, and planner API
schema.sql          PostgreSQL database tables
package.json        Node.js dependencies and run commands
.env.example        Environment variable template

SECURITY NOTES
--------------
- Use HTTPS when the site is deployed.
- Keep .env private and do not commit it to GitHub.
- Use different, randomly generated values for SESSION_SECRET and OTP_SECRET.
- Use a unique password for this account; do not reuse a school or email password.
- The five-digit code is limited to five verification attempts and is rate-limited.
