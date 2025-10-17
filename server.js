const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

// Add error handlers
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION:', err.message);
});

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION:', err.message);
});

console.log('🔧 Starting ultra-minimal server...');

// Basic middleware only
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// SIMPLE CORS - allow everything for now
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Test route - NO DATABASE, NO EXTERNAL IMPORTS
app.get('/', (req, res) => {
  res.json({
    message: '🎉 ULTRA-MINIMAL SERVER IS WORKING!',
    status: 'SUCCESS',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.get('/test', (req, res) => {
  res.json({
    message: '✅ Test endpoint working perfectly!',
    server: 'Express.js',
    status: 'Healthy'
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// Handle preflight
app.options('*', (req, res) => {
  res.status(200).send();
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    availableRoutes: ['/', '/test', '/health']
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({
    error: 'Something went wrong',
    message: err.message
  });
});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`
🎉 ULTRA-MINIMAL SERVER RUNNING ON PORT ${PORT}
✅ NO DATABASE CONNECTION
✅ NO EXTERNAL ROUTES  
✅ NO COMPLEX MIDDLEWARE
🌐 TEST URL: https://ctftechdbackend-production.up.railway.app/
🔗 HEALTH: https://ctftechdbackend-production.up.railway.app/health
⚡ TEST: https://ctftechdbackend-production.up.railway.app/test
  `);
});