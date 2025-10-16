const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = require('./config/dbconfig');

// Route imports - FIXED: Check if these files exist and export correctly
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const ctfRoutes = require('./routes/ctfRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

// Add error handlers at the TOP
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

// Connect to Database
connectDB();

// Configure CORS for multiple origins - FIXED: Add Railway URL
const allowedOrigins = [
  'https://ctfchallange.vercel.app',
  'https://ctftechdbackend-production.up.railway.app', // ADD THIS
  'http://localhost:5173',
  'http://localhost:3000',
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With']
};

// Security Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// FIXED: Use simpler CORS setup for Railway
app.use(cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Body Parsing Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - Origin: ${req.headers.origin || 'No Origin'}`);
  next();
});

// FIXED: Add a simple test route FIRST
app.get('/test', (req, res) => {
  res.json({ 
    message: 'Test endpoint working!',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// API Routes - FIXED: Add error handling for routes
try {
  app.use('/api/auth', authRoutes.router || authRoutes);
  app.use('/api/admin', adminRoutes.router || adminRoutes);
  app.use('/api/ctf', ctfRoutes.router || ctfRoutes);
  app.use('/api/user', userRoutes.router || userRoutes);
} catch (error) {
  console.error('Route loading error:', error);
}

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    cors: {
      allowedOrigins: allowedOrigins,
      currentOrigin: req.headers.origin || 'No Origin Header'
    }
  });
});

// Enhanced root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'CTF Platform API - Pure CTF Management System',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    status: 'operational',
    timestamp: new Date().toISOString()
  });
});

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'CTF Platform API',
    version: '1.0.0',
    status: 'operational',
    timestamp: new Date().toISOString()
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error Stack:', err.stack);
  
  // CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ 
      error: 'CORS Error: Origin not allowed',
      allowedOrigins: allowedOrigins,
      yourOrigin: req.headers.origin
    });
  }
  
  res.status(err.status || 500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message
  });
});

const PORT = process.env.PORT || 8080;

// FIXED: Remove '0.0.0.0' and use simpler listen
app.listen(PORT, () => {
  console.log(`
🚀 CTF Platform Server running on port ${PORT}
📊 Environment: ${process.env.NODE_ENV || 'development'}
🌐 Railway URL: https://ctftechdbackend-production.up.railway.app
✅ Test URL: https://ctftechdbackend-production.up.railway.app/test
🔍 Health Check: https://ctftechdbackend-production.up.railway.app/api/health
  `);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n👋 Shutting down server gracefully...');
  mongoose.connection.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n👋 Server terminated');
  mongoose.connection.close();
  process.exit(0);
});