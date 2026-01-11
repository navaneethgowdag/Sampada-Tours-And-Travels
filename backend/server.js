const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();

// ================= SECURITY MIDDLEWARE =================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));

// CORS configuration - Allow multiple origins
const allowedOrigins = [
  'http://localhost:5000',
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'http://127.0.0.1:5000',
  'http://localhost:8000',
  'http://127.0.0.1:8000',
  process.env.FRONTEND_URL
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(null, true); // Allow all origins in development
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Body parser
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Auth rate limit
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: "Too many login attempts, please try again later."
});

// ================= CONFIG =================
const SECRET_KEY = process.env.JWT_SECRET || "sampada_secret_key_change_in_production";
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

if (NODE_ENV === "production" && SECRET_KEY === "sampada_secret_key_change_in_production") {
  console.error("❌ CRITICAL: Using default JWT secret in production! Set JWT_SECRET in .env file!");
  process.exit(1);
}

// ================= DATABASE (PostgreSQL - Neon) =================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

// Test DB connection
pool.connect()
  .then(client => {
    console.log("✓ Connected to PostgreSQL (Neon)");
    client.release();
    initializeDatabase();
  })
  .catch(err => {
    console.error("❌ Database connection error:", err);
    process.exit(1);
  });

// ================= CREATE TABLES =================
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(15) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS feedback (
        id SERIAL PRIMARY KEY,
        user_name VARCHAR(100),
        phone VARCHAR(15),
        email VARCHAR(100),
        service_type VARCHAR(50) NOT NULL,
        message TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS package_bookings (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        package_name VARCHAR(100) NOT NULL,
        price_per_person INT NOT NULL,
        people_count INT NOT NULL CHECK (people_count > 0),
        from_place VARCHAR(100),
        to_place VARCHAR(100),
        days INT CHECK (days > 0),
        kms INT CHECK (kms >= 0),
        total_amount INT NOT NULL CHECK (total_amount >= 0),
        travel_date DATE NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS car_bookings (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        full_name VARCHAR(100) NOT NULL,
        phone VARCHAR(15) NOT NULL,
        email VARCHAR(100),
        vehicle_type VARCHAR(50) NOT NULL,
        trip_type VARCHAR(50) NOT NULL,
        kms INT NOT NULL CHECK (kms > 0),
        days INT NOT NULL DEFAULT 1 CHECK (days > 0),
        price_per_km FLOAT NOT NULL CHECK (price_per_km >= 0),
        driver_per_day FLOAT CHECK (driver_per_day >= 0),
        no_driver BOOLEAN DEFAULT FALSE,
        total_amount FLOAT NOT NULL CHECK (total_amount >= 0),
        travel_date DATE NOT NULL,
        billable_kms INT CHECK (billable_kms >= 0),
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("✓ All PostgreSQL tables initialized");
  } catch (err) {
    console.error("❌ Table creation error:", err);
    throw err;
  }
}

// ================= HELPERS =================
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePhone(phone) {
  const re = /^[0-9]{10}$/;
  return re.test(phone);
}

function sanitizeInput(input) {
  if (typeof input !== "string") return input;
  return input.trim().substring(0, 500);
}

function validatePassword(password) {
  if (password.length < 8) {
    return { valid: false, message: "Password must be at least 8 characters" };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: "Password must contain at least one uppercase letter" };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: "Password must contain at least one lowercase letter" };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: "Password must contain at least one number" };
  }
  return { valid: true };
}

// ================= AUTH MIDDLEWARE =================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token) {
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (!err) req.user = user;
    });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

// ================= HEALTH CHECK =================
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "OK",
      timestamp: new Date().toISOString(),
      environment: NODE_ENV,
      database: "connected"
    });
  } catch (err) {
    res.status(503).json({
      status: "ERROR",
      timestamp: new Date().toISOString(),
      environment: NODE_ENV,
      database: "disconnected"
    });
  }
});

// ================= REGISTER =================
app.post("/register", authLimiter, async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    if (!name || !phone || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!validatePhone(phone)) {
      return res.status(400).json({ message: "Phone must be 10 digits" });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ message: passwordValidation.message });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await pool.query(
      "INSERT INTO users (name, phone, email, password) VALUES ($1, $2, $3, $4)",
      [sanitizeInput(name), sanitizeInput(phone), email.toLowerCase().trim(), hashedPassword]
    );

    res.status(201).json({ message: "Registration successful! Please log in." });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ message: "Email already registered" });
    }
    console.error("Register error:", err);
    res.status(500).json({ message: "Registration failed" });
  }
});

// ================= LOGIN =================
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase().trim()]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin },
      SECRET_KEY,
      { expiresIn: "24h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        is_admin: user.is_admin
      },
      message: "Login successful"
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login" });
  }
});

// ================= USER PROFILE =================
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, phone, email, is_admin, created_at FROM users WHERE id = $1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= FEEDBACK =================
app.post("/feedback", optionalAuth, async (req, res) => {
  try {
    const { service_type, message, phone, email, name } = req.body;

    if (!service_type || !message) {
      return res.status(400).json({ message: "Service type and message are required" });
    }

    if (message.trim().length < 10) {
      return res.status(400).json({ message: "Message must be at least 10 characters" });
    }

    await pool.query(
      `INSERT INTO feedback (user_name, phone, email, service_type, message)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user ? req.user.name : sanitizeInput(name) || "Anonymous",
        phone ? sanitizeInput(phone) : null,
        email ? email.toLowerCase().trim() : null,
        sanitizeInput(service_type),
        sanitizeInput(message)
      ]
    );

    res.status(201).json({ message: "Thank you for your feedback!" });
  } catch (err) {
    console.error("Feedback error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/feedback", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM feedback WHERE email = $1 ORDER BY created_at DESC",
      [req.user.email]
    );
    res.json({ feedback: result.rows });
  } catch (err) {
    console.error("Get feedback error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= PACKAGE BOOKINGS =================
// Public package booking endpoint (works with or without auth)
app.post("/bookings/package", optionalAuth, async (req, res) => {
  try {
    const {
      package_name,
      price_per_person,
      people_count,
      from_place,
      to_place,
      days,
      kms,
      total_amount,
      travel_date,
      full_name,
      phone,
      email
    } = req.body;

    if (!package_name || !people_count || !total_amount || !travel_date || !full_name || !phone) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const result = await pool.query(
      `INSERT INTO package_bookings 
       (user_id, package_name, price_per_person, people_count, from_place, to_place, days, kms, total_amount, travel_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [
        req.user ? req.user.id : null,
        sanitizeInput(package_name),
        price_per_person || 0,
        people_count,
        sanitizeInput(from_place),
        sanitizeInput(to_place),
        days,
        kms,
        total_amount,
        travel_date
      ]
    );

    res.status(201).json({
      message: "Package booking confirmed! We will contact you shortly.",
      booking_id: result.rows[0].id
    });
  } catch (err) {
    console.error("Package booking error:", err);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/bookings/package", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM package_bookings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ bookings: result.rows });
  } catch (err) {
    console.error("Get package bookings error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= CAR BOOKINGS =================
app.post("/bookings/car", authenticateToken, async (req, res) => {
  try {
    const {
      full_name,
      phone,
      email,
      vehicle_type,
      trip_type,
      kms,
      days,
      price_per_km,
      driver_per_day,
      no_driver,
      total_amount,
      travel_date,
      billable_kms
    } = req.body;

    if (!full_name || !phone || !vehicle_type || !trip_type || !kms || !days || !price_per_km || !total_amount || !travel_date) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const result = await pool.query(
      `INSERT INTO car_bookings 
       (user_id, full_name, phone, email, vehicle_type, trip_type, kms, days, price_per_km, driver_per_day, no_driver, total_amount, travel_date, billable_kms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING id`,
      [
        req.user.id,
        sanitizeInput(full_name),
        sanitizeInput(phone),
        email ? email.toLowerCase().trim() : null,
        sanitizeInput(vehicle_type),
        sanitizeInput(trip_type),
        kms,
        days,
        price_per_km,
        driver_per_day,
        no_driver,
        total_amount,
        travel_date,
        billable_kms
      ]
    );

    res.status(201).json({
      message: "Car booking created successfully",
      booking_id: result.rows[0].id
    });
  } catch (err) {
    console.error("Car booking error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Public car booking endpoint (no auth required)
app.post("/book-car", optionalAuth, async (req, res) => {
  try {
    const {
      vehicle,
      tripType,
      kms,
      days,
      noDriver,
      fullName,
      phone,
      email,
      startDate,
      totalAmount
    } = req.body;

    if (!vehicle || !tripType || !kms || !days || !fullName || !phone || !startDate || !totalAmount) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Calculate price per km based on vehicle and trip type
    const vehicleRates = {
      'Sedan': { local: 12, outstation: 13, driver: 300 },
      'SUV': { local: 15, outstation: 16, driver: 350 },
      'Tempo': { local: 20, outstation: 22, driver: 400 }
    };

    const rates = vehicleRates[vehicle];
    if (!rates) {
      return res.status(400).json({ message: "Invalid vehicle type" });
    }

    const pricePerKm = tripType === 'Local' ? rates.local : rates.outstation;
    const driverPerDay = noDriver ? 0 : rates.driver;

    const result = await pool.query(
      `INSERT INTO car_bookings 
       (user_id, full_name, phone, email, vehicle_type, trip_type, kms, days, price_per_km, driver_per_day, no_driver, total_amount, travel_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING id`,
      [
        req.user ? req.user.id : null,
        sanitizeInput(fullName),
        sanitizeInput(phone),
        email ? email.toLowerCase().trim() : null,
        sanitizeInput(vehicle),
        sanitizeInput(tripType),
        parseInt(kms),
        parseInt(days),
        pricePerKm,
        driverPerDay,
        noDriver,
        parseFloat(totalAmount),
        startDate
      ]
    );

    res.status(201).json({
      message: "Car booking confirmed! We will contact you shortly.",
      booking_id: result.rows[0].id
    });
  } catch (err) {
    console.error("Car booking error:", err);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.get("/bookings/car", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM car_bookings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ bookings: result.rows });
  } catch (err) {
    console.error("Get car bookings error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= ADMIN ROUTES =================
app.get("/admin/feedback", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM feedback ORDER BY created_at DESC");
    res.json({ feedback: result.rows });
  } catch (err) {
    console.error("Admin feedback error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/admin/bookings/package", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT pb.*, u.name as user_name, u.email as user_email, u.phone as user_phone
      FROM package_bookings pb
      LEFT JOIN users u ON pb.user_id = u.id
      ORDER BY pb.created_at DESC
    `);
    res.json({ bookings: result.rows });
  } catch (err) {
    console.error("Admin package bookings error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/admin/bookings/car", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT cb.*, u.name as user_name, u.email as user_email
      FROM car_bookings cb
      LEFT JOIN users u ON cb.user_id = u.id
      ORDER BY cb.created_at DESC
    `);
    res.json({ bookings: result.rows });
  } catch (err) {
    console.error("Admin car bookings error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/admin/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, phone, email, is_admin, created_at FROM users ORDER BY created_at DESC"
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error("Admin users error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= ERROR HANDLING =================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Internal server error" });
});

app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// ================= GRACEFUL SHUTDOWN =================
async function gracefulShutdown(signal) {
  console.log(`\n${signal} received. Closing server gracefully...`);
  try {
    await pool.end();
    console.log("✓ Database connections closed");
    process.exit(0);
  } catch (err) {
    console.error("Error during shutdown:", err);
    process.exit(1);
  }
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// ================= START SERVER =================
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║  Sampada Tours & Travels API Server    ║
╠════════════════════════════════════════╣
║  Status: Running ✓                     ║
║  Port: ${PORT.toString().padEnd(33)}║
║  Environment: ${NODE_ENV.padEnd(24)}║
║  Database: PostgreSQL (Neon)           ║
╚════════════════════════════════════════╝
  `);
});