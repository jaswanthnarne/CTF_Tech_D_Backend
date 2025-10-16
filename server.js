const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose'); // Added mongoose import
require('dotenv').config();

const connectDB = require('./config/dbconfig');

// Route imports
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const ctfRoutes = require('./routes/ctfRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

// Connect to Database
connectDB();

// Configure CORS for multiple origins
const allowedOrigins = [
  'https://ctfchallange.vercel.app', // Your Vercel frontend
  'http://localhost:5173', // Local development
  'http://localhost:3000', // Alternative local port
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
  crossOriginResourcePolicy: { policy: "cross-origin" } // Allow images and resources from different origins
}));
app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // requests per window
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

// API Routes
app.use('/api/auth', authRoutes.router);
app.use('/api/admin', adminRoutes.router);
app.use('/api/ctf', ctfRoutes);
app.use('/api/user', userRoutes);

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
    cors: {
      enabled: true,
      allowedOrigins: allowedOrigins
    },
    endpoints: {
      auth: '/api/auth',
      admin: '/api/admin', 
      ctf: '/api/ctf',
      user: '/api/user',
      health: '/api/health'
    },
    documentation: 'Check /api/health for detailed status'
  });
});

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'CTF Platform API',
    version: '1.0.0',
    status: 'operational',
    cors: {
      enabled: true,
      allowedOrigins: allowedOrigins
    },
    endpoints: {
      authentication: {
        login: 'POST /api/auth/login',
        register: 'POST /api/auth/register',
        logout: 'POST /api/auth/logout',
        refresh: 'POST /api/auth/refresh'
      },
      admin: {
        users: 'GET /api/admin/users',
        ctfs: 'GET /api/admin/ctfs'
      },
      ctf: {
        list: 'GET /api/ctf',
        details: 'GET /api/ctf/:id',
        submit: 'POST /api/ctf/:id/submit'
      },
      user: {
        profile: 'GET /api/user/profile',
        dashboard: 'GET /api/user/dashboard'
      }
    }
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    availableRoutes: [
      '/api/auth/*',
      '/api/admin/*',
      '/api/ctf/*', 
      '/api/user/*',
      '/api/health',
      '/api'
    ],
    documentation: 'Visit /api for API documentation'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error Stack:', err.stack);
  console.error('Error Details:', {
    message: err.message,
    url: req.originalUrl,
    method: req.method,
    origin: req.headers.origin,
    body: req.body
  });
  
  // CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ 
      error: 'CORS Error: Origin not allowed',
      allowedOrigins: allowedOrigins,
      yourOrigin: req.headers.origin
    });
  }
  
  // JSON parsing errors
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ 
      error: 'Invalid JSON in request body',
      message: 'Please check your request body format'
    });
  }
  
  // Mongoose errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      details: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      error: 'Invalid ID format',
      message: 'The provided ID is not valid'
    });
  }
  
  // Default error
  res.status(err.status || 500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message,
    ...(process.env.NODE_ENV !== 'production' && { 
      stack: err.stack,
      details: err 
    })
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
🚀 CTF Platform Server running on port ${PORT}
📊 Environment: ${process.env.NODE_ENV || 'development'}
🔗 Allowed Frontend URLs:
   - https://ctfchallange.vercel.app
   - http://localhost:5173
   - http://localhost:3000
📧 Email Service: ${process.env.EMAIL_USER ? 'Enabled' : 'Disabled'}
🌐 API Base URL: http://localhost:${PORT}/api
🔍 Health Check: http://localhost:${PORT}/api/health
📚 API Docs: http://localhost:${PORT}/api
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