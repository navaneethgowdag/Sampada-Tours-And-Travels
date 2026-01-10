const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();

// ================= SECURITY MIDDLEWARE =================
// Use helmet for security headers
app.use(helmet());

// CORS configuration for production
const corsOptions = {
  origin: process.env.FRONTEND_URL || "http://localhost:5000",
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Body parser with size limits
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later."
});
app.use(limiter);

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 attempts per 15 minutes
  message: "Too many login attempts, please try again later."
});

// ================= CONFIG =================
const SECRET_KEY = process.env.JWT_SECRET || "sampada_secret_key_change_in_production";
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "./sampada_tours.db";
const NODE_ENV = process.env.NODE_ENV || "development";

// Warn if using default secret in production
if (NODE_ENV === "production" && SECRET_KEY === "sampada_secret_key_change_in_production") {
  console.warn("⚠️  WARNING: Using default JWT secret! Set JWT_SECRET in .env file!");
}

// ================= DATABASE =================
const db = new sqlite3.Database(DB_FILE, err => {
  if (err) {
    console.error("Database connection error:", err);
    process.exit(1);
  } else {
    console.log("✓ Connected to SQLite database");
    initializeDatabase();
  }
});

// Enable foreign keys
db.run("PRAGMA foreign_keys = ON");

// ================= CREATE TABLES =================
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) console.error("Users table error:", err);
    });

    // Feedback table
    db.run(`
      CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT,
        phone TEXT,
        email TEXT,
        service_type TEXT,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) console.error("Feedback table error:", err);
    });

    // Package bookings table
    db.run(`
      CREATE TABLE IF NOT EXISTS package_bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        package_name TEXT NOT NULL,
        price_per_person INTEGER,
        people_count INTEGER NOT NULL,
        from_place TEXT,
        to_place TEXT,
        days INTEGER,
        kms INTEGER,
        total_amount INTEGER NOT NULL,
        travel_date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `, (err) => {
      if (err) console.error("Package bookings table error:", err);
    });

    // Car bookings table
    db.run(`
      CREATE TABLE IF NOT EXISTS car_bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        full_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT,
        vehicle_type TEXT NOT NULL,
        trip_type TEXT NOT NULL,
        kms INTEGER NOT NULL,
        days INTEGER NOT NULL DEFAULT 1,
        price_per_km REAL NOT NULL,
        driver_per_day REAL,
        no_driver INTEGER DEFAULT 0,
        total_amount REAL NOT NULL,
        travel_date DATE NOT NULL,
        billable_kms INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `, (err) => {
      if (err) console.error("Car bookings table error:", err);
    });

    console.log("✓ All database tables initialized");
  });
}

// ================= INPUT VALIDATION HELPERS =================
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePhone(phone) {
  const re = /^[0-9]{10}$/;
  return re.test(phone);
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.trim().substring(0, 500); // Limit length
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

// Optional authentication (for endpoints that work with or without auth)
function optionalAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  
  if (token) {
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (!err) {
        req.user = user;
      }
    });
  }
  next();
}

// ================= HEALTH CHECK =================
app.get("/health", (req, res) => {
  res.json({ 
    status: "OK", 
    timestamp: new Date().toISOString(),
    environment: NODE_ENV
  });
});

// ================= REGISTER =================
app.post("/register", authLimiter, async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    // Validation
    if (!name || !phone || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (name.length < 3) {
      return res.status(400).json({ message: "Name must be at least 3 characters" });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!validatePhone(phone)) {
      return res.status(400).json({ message: "Phone must be 10 digits" });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }

    // Sanitize inputs
    const sanitizedName = sanitizeInput(name);
    const sanitizedPhone = sanitizeInput(phone);
    const sanitizedEmail = sanitizeInput(email).toLowerCase();

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Insert user
    db.run(
      "INSERT INTO users (name, phone, email, password) VALUES (?, ?, ?, ?)",
      [sanitizedName, sanitizedPhone, sanitizedEmail, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(400).json({ message: "Email already registered" });
          }
          console.error("Registration error:", err);
          return res.status(500).json({ message: "Registration failed" });
        }
        res.status(201).json({ 
          message: "Registration successful! Please log in.",
          userId: this.lastID
        });
      }
    );
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// ================= LOGIN =================
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const sanitizedEmail = sanitizeInput(email).toLowerCase();

    db.get(
      "SELECT * FROM users WHERE email = ?", 
      [sanitizedEmail], 
      async (err, user) => {
        if (err) {
          console.error("Login DB error:", err);
          return res.status(500).json({ message: "Login failed" });
        }

        if (!user) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        const token = jwt.sign(
          { 
            id: user.id, 
            name: user.name, 
            email: user.email,
            is_admin: user.is_admin 
          },
          SECRET_KEY,
          { expiresIn: "24h" }
        );

        res.json({ 
          token, 
          name: user.name,
          email: user.email,
          message: "Login successful"
        });
      }
    );
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login" });
  }
});

// ================= LOGOUT =================
app.post("/logout", (req, res) => {
  // For JWT, logout is handled client-side by removing the token
  // This endpoint exists for consistency and future session management
  res.json({ message: "Logged out successfully" });
});

// ================= FEEDBACK =================
app.post("/feedback", optionalAuth, (req, res) => {
  try {
    const { service_type, message, phone, email, name } = req.body;

    if (!message || !service_type) {
      return res.status(400).json({ message: "Service type and message are required" });
    }

    // Use authenticated user's name or provided name
    const userName = req.user ? req.user.name : (name || "Anonymous");
    const userPhone = sanitizeInput(phone) || null;
    const userEmail = email ? sanitizeInput(email).toLowerCase() : null;

    // Validate email if provided
    if (userEmail && !validateEmail(userEmail)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const sanitizedMessage = sanitizeInput(message);
    const sanitizedServiceType = sanitizeInput(service_type);

    db.run(
      `INSERT INTO feedback (user_name, phone, email, service_type, message)
       VALUES (?, ?, ?, ?, ?)`,
      [userName, userPhone, userEmail, sanitizedServiceType, sanitizedMessage],
      function(err) {
        if (err) {
          console.error("Feedback insert error:", err);
          return res.status(500).json({ message: "Failed to submit feedback" });
        }
        res.status(201).json({ 
          message: "Thank you for your feedback!",
          feedbackId: this.lastID
        });
      }
    );
  } catch (error) {
    console.error("Feedback error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= PACKAGE BOOKING =================
app.post("/package-booking", authenticateToken, (req, res) => {
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
      travel_date
    } = req.body;

    // Validation
    if (!package_name || !people_count || !total_amount || !travel_date) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    if (people_count < 1 || people_count > 100) {
      return res.status(400).json({ message: "Invalid number of people" });
    }

    if (total_amount < 0) {
      return res.status(400).json({ message: "Invalid amount" });
    }

    // Validate date
    const travelDate = new Date(travel_date);
    if (isNaN(travelDate.getTime())) {
      return res.status(400).json({ message: "Invalid travel date" });
    }

    db.run(
      `INSERT INTO package_bookings
       (user_id, package_name, price_per_person, people_count, from_place, to_place, days, kms, total_amount, travel_date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        sanitizeInput(package_name),
        price_per_person || null,
        people_count,
        from_place ? sanitizeInput(from_place) : null,
        to_place ? sanitizeInput(to_place) : null,
        days || null,
        kms || null,
        total_amount,
        travel_date
      ],
      function(err) {
        if (err) {
          console.error("Package booking error:", err);
          return res.status(500).json({ message: "Booking failed" });
        }
        res.status(201).json({ 
          message: "Package booking confirmed successfully!",
          bookingId: this.lastID
        });
      }
    );
  } catch (error) {
    console.error("Package booking error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= CAR BOOKING =================
app.post("/book-car", optionalAuth, (req, res) => {
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
      totalAmount,
      billableKms
    } = req.body;

    // Validation
    if (!vehicle || !tripType || !fullName || !phone || !startDate || !totalAmount) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    if (!validatePhone(phone)) {
      return res.status(400).json({ message: "Invalid phone number" });
    }

    if (email && !validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (kms < 1 || days < 1) {
      return res.status(400).json({ message: "Invalid distance or days" });
    }

    // Validate date
    const travelDate = new Date(startDate);
    if (isNaN(travelDate.getTime())) {
      return res.status(400).json({ message: "Invalid travel date" });
    }

    // Calculate pricing based on vehicle and trip type
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

    db.run(
      `INSERT INTO car_bookings
       (user_id, full_name, phone, email, vehicle_type, trip_type, kms, days, price_per_km, driver_per_day, no_driver, total_amount, travel_date, billable_kms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user ? req.user.id : null,
        sanitizeInput(fullName),
        sanitizeInput(phone),
        email ? sanitizeInput(email).toLowerCase() : null,
        vehicle,
        tripType,
        kms,
        days,
        pricePerKm,
        driverPerDay,
        noDriver ? 1 : 0,
        totalAmount,
        startDate,
        billableKms || kms
      ],
      function(err) {
        if (err) {
          console.error("Car booking error:", err);
          return res.status(500).json({ message: "Booking failed" });
        }
        res.status(201).json({ 
          message: "Car booking confirmed successfully! We will contact you shortly.",
          bookingId: this.lastID
        });
      }
    );
  } catch (error) {
    console.error("Car booking error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ================= ADMIN: GET FEEDBACK =================
app.get("/admin/feedback", authenticateToken, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: "Admin access required" });
  }

  db.all(
    "SELECT * FROM feedback ORDER BY created_at DESC", 
    (err, rows) => {
      if (err) {
        console.error("Admin feedback error:", err);
        return res.status(500).json({ message: "Failed to fetch feedback" });
      }
      res.json({ feedback: rows });
    }
  );
});

// ================= ADMIN: GET ALL BOOKINGS =================
app.get("/admin/bookings", authenticateToken, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: "Admin access required" });
  }

  const packageQuery = "SELECT 'package' as type, * FROM package_bookings ORDER BY created_at DESC";
  const carQuery = "SELECT 'car' as type, * FROM car_bookings ORDER BY created_at DESC";

  db.all(packageQuery, (err1, packages) => {
    if (err1) {
      console.error("Admin bookings error:", err1);
      return res.status(500).json({ message: "Failed to fetch bookings" });
    }

    db.all(carQuery, (err2, cars) => {
      if (err2) {
        console.error("Admin bookings error:", err2);
        return res.status(500).json({ message: "Failed to fetch bookings" });
      }

      res.json({ 
        packageBookings: packages,
        carBookings: cars
      });
    });
  });
});

// ================= ERROR HANDLING =================
// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ 
    message: NODE_ENV === "production" 
      ? "Internal server error" 
      : err.message 
  });
});

// ================= GRACEFUL SHUTDOWN =================
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing database...');
  db.close((err) => {
    if (err) console.error(err);
    process.exit(err ? 1 : 0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, closing database...');
  db.close((err) => {
    if (err) console.error(err);
    process.exit(err ? 1 : 0);
  });
});

// ================= START SERVER =================
const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║  Sampada Tours & Travels API Server   ║
╠════════════════════════════════════════╣
║  Status: Running                       ║
║  Port: ${PORT}                            ║
║  Environment: ${NODE_ENV}              ║
║  URL: http://localhost:${PORT}           ║
╚════════════════════════════════════════╝
  `);
});

// Handle server errors
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use`);
  } else {
    console.error('Server error:', error);
  }
  process.exit(1);
});

module.exports = app;