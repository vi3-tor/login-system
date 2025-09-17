const session = require('express-session');
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

dotenv.config();
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve public login files
app.use(express.static(path.join(__dirname, 'public')));

// Serve protected views' assets (CSS, JS, images)
app.use('/assets', express.static(path.join(__dirname, 'views/assets')));
app.use('/js', express.static(path.join(__dirname, 'views/js')));

// Session setup
app.use(session({
  secret: 'yourSecretKey',
  resave: false,
  saveUninitialized: false,
}));

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log('✅ MySQL Connected');
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // TLS
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASS,
 },
  tls: {
    rejectUnauthorized: false,
  },
});

transporter.sendMail({
  from: process.env.EMAIL,
  to: "victor4christ80@gmail.com",
  subject: "Test Email",
  text: "If you see this, SMTP works 🎉",
}, (err, info) => {
  if (err) {
    console.error("❌ Email test failed:", err);
  } else {
    console.log("✅ Test Email sent:", info.response);
  }
});


transporter.verify((error, success) => {
  if (error) {
    console.error('❌ SMTP Error:', error);
  } else {
    console.log('✅ SMTP Server ready');
  }
});


// Middleware to protect routes
const protect = (req, res, next) => {
  if (!req.session.userId) return res.redirect('/');
  next();
};




// Serve login page (public)
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Register
app.post('/auth/register', async (req, res) => {
	const { username, email, password } = req.body;
	const hashed = await bcrypt.hash(password, 10);
	const token = uuidv4();

	const sql = 'INSERT INTO users (username, email, password, token) VALUES (?, ?, ?, ?)';
	db.query(sql, [username, email, hashed, token], (err) => {
		if (err) {
			if (err.code === 'ER_DUP_ENTRY') {
				return res.status(409).json({ error: 'An account with this email already exists.' });
			}
			console.error(err);
			return res.status(500).json({ error: 'Something went wrong. Please try again.' });
		}

		const verifyLink = `${process.env.BASE_URL}/auth/verify/${token}`;
		transporter.sendMail({
			from: process.env.EMAIL,
			to: email,
			subject: 'Please verify your email',
			html: `<p>Click <a href="${verifyLink}">here</a> to verify your account.</p>`,
		});

		res.json({ message: 'Registration successful. Please check your email.' });
	});
});

// Verify email
app.get('/auth/verify/:token', (req, res) => {
  const token = req.params.token;
  const sql = 'UPDATE users SET verified = 1, token = NULL WHERE token = ?';

  db.query(sql, [token], (err, result) => {
    if (err || result.affectedRows === 0) {
      return res.send('Invalid or expired verification link.');
    }
    res.redirect('/');
  });
});

// Login
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';

  db.query(sql, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(401).json({ error: 'Incorrect password' });
    if (!user.verified) return res.status(401).json({ error: 'Please verify your email first.' });

    req.session.userId = user.id;
    res.json({ message: 'Login successful', redirect: '/index' });
  });
});


app.use('/product/assets', express.static(path.join(__dirname, 'views/product/assets')));
app.use('/product/assets/js', express.static(path.join(__dirname, 'views/product/assets/js')));


// 🔐 Protected Routes (views)
app.get('/index', protect, (_req, res) => {
  if (!_req.session.userId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/contact', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'contact.html'));
});

app.get('/blog-single', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'blog-single.html'));
});

app.get('/portfolio-details', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'portfolio-details.html'));
});

// Navigation routes


app.get('/agriculture', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'agriculture.html'));
});

app.get('/automobile', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'automobile.html'));
});

app.get('/medicine', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'medicine.html'));
});
app.get('/oil&gas', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'oil&gas.html'));
});
app.get('/home&office', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'home&office.html'));
});
app.get('/comingsoon', protect, (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'coming_soon.html'));
});
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});



app.get('/product', (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'views/product/product.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});


// 404 Fallback (after all other routes)
app.use((_req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'views', '404.html'));
});


// Server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
