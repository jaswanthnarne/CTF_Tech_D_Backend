const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = require('./config/dbconfig');

const app = express();

// Add error handlers at the TOP
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥');
  console.log('Error:', err.name, err.message);
});

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥');
  console.log('Error:', err.name, err.message);
  process.exit(1);
});

console.log('🚀 Starting server initialization...');

// Connect to Database
connectDB();

// Configure CORS
const allowedOrigins = [
  'https://ctfchallange.vercel.app',
  'https://ctftechdbackend-production.up.railway.app',
  'http://localhost:5173',
  'http://localhost:3000',
];

// SIMPLIFIED CORS - Remove the complex function
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
}));

// Security Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: {
    error: 'Too many requests from this IP, please try again later.',
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
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
  next();
});

// SIMPLE TEST ROUTES - Add these BEFORE your route imports
app.get('/', (req, res) => {
  res.json({
    message: 'CTF Platform API - Server is RUNNING!',
    version: '1.0.0',
    status: 'operational',
    timestamp: new Date().toISOString()
  });
});

app.get('/test', (req, res) => {
  res.json({ 
    message: '✅ Test endpoint working!',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

console.log('✅ Basic routes loaded');

// NOW load your routes with error handling
let routesLoaded = false;
try {
  console.log('🔄 Loading route modules...');
  
  // Load routes with individual error handling
  try {
    const authRoutes = require('./routes/authRoutes');
    app.use('/api/auth', authRoutes.router || authRoutes);
    console.log('✅ Auth routes loaded');
  } catch (error) {
    console.log('❌ Auth routes failed:', error.message);
  }
  
  try {
    const adminRoutes = require('./routes/adminRoutes');
    app.use('/api/admin', adminRoutes.router || adminRoutes);
    console.log('✅ Admin routes loaded');
  } catch (error) {
    console.log('❌ Admin routes failed:', error.message);
  }
  
  try {
    const ctfRoutes = require('./routes/ctfRoutes');
    app.use('/api/ctf', ctfRoutes.router || ctfRoutes);
    console.log('✅ CTF routes loaded');
  } catch (error) {
    console.log('❌ CTF routes failed:', error.message);
  }
  
  try {
    const userRoutes = require('./routes/userRoutes');
    app.use('/api/user', userRoutes.router || userRoutes);
    console.log('✅ User routes loaded');
  } catch (error) {
    console.log('❌ User routes failed:', error.message);
  }
  
  routesLoaded = true;
  console.log('🎉 All routes loaded successfully');
  
} catch (error) {
  console.log('💥 Route loading failed:', error);
}

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'CTF Platform API',
    version: '1.0.0',
    status: 'operational',
    routesLoaded: routesLoaded,
    timestamp: new Date().toISOString()
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    availableRoutes: ['/', '/test', '/api/health', '/api']
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('💥 Application Error:', err.message);
  console.error('Stack:', err.stack);
  
  res.status(500).json({ 
    error: 'Internal server error',
    message: 'Something went wrong'
  });
});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`
🎉 CTF Platform Server SUCCESSFULLY started on port ${PORT}
📊 Environment: ${process.env.NODE_ENV || 'development'}
🌐 Railway URL: https://ctftechdbackend-production.up.railway.app
✅ Test these URLs:
   - https://ctftechdbackend-production.up.railway.app/
   - https://ctftechdbackend-production.up.railway.app/test
   - https://ctftechdbackend-production.up.railway.app/api/health
  `);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n👋 Shutting down server gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n👋 Server terminated');
  process.exit(0);
});