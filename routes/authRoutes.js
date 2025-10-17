const express = require('express');
const User = require('../models/User');
const { body, validationResult } = require('express-validator');
const jwt = require("jsonwebtoken");
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const sendMail = require('../utils/sendMail');

const router = express.Router();

// ----------------- MIDDLEWARE ----------------- //

// Require authentication
// In authRoutes.js - update the requireAuth middleware
const requireAuth = async (req, res, next) => {
  try {
    console.log('🔐 requireAuth middleware checking authentication...');
    
    // Use same token extraction as admin routes
    let token = req.cookies?.jwt || 
                req.headers.authorization?.replace('Bearer ', '') ||
                req.headers.Authorization?.replace('Bearer ', '') ||
                req.query?.token;

    console.log('📡 Token present:', !!token);
    
    if (!token) {
      console.log('❌ No token found - authentication required');
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Clean the token (same as admin routes)
    token = token.trim().replace(/^"(.*)"$/, '$1');

    // DEVELOPMENT MODE: Handle mock tokens if needed
    if (process.env.NODE_ENV === 'development') {
      // Add any development handling if required
    }

    if (token === 'null' || token === 'undefined' || token === 'loggedout') {
      console.log('❌ Invalid token value:', token);
      return res.status(401).json({ error: 'Invalid token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('🔍 Decoded token:', { id: decoded.id, role: decoded.role });

    const user = await User.findById(decoded.id);
    if (!user) {
      console.log('❌ User not found for ID:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (!user.isActive) {
      console.log('❌ User account is deactivated');
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    console.log('✅ User authenticated:', user.email);
    req.user = user;
    next();
  } catch (err) {
    console.error('🔒 Auth middleware error:', err.message);
    
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    console.error('Auth middleware unexpected error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// ----------------- PUBLIC ROUTES ----------------- //

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({ 
    message: 'Auth service is running', 
    timestamp: new Date().toISOString() 
  });
});

// User registration - Fixed version
router.post('/register', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character'),
  body('fullName').notEmpty().withMessage('Full name is required'),
  body('sem').notEmpty().withMessage('Semester is required'),
  body('erpNumber').notEmpty().withMessage('ERP Number is required'),
  body('collegeName').notEmpty().withMessage('College name is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { 
      email, 
      password, 
      fullName, 
      contactNumber, 
      specialization, 
      sem, 
      erpNumber, 
      collegeName 
    } = req.body;

    console.log('Registration request data:', req.body); // Debug log

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Check if ERP number already exists
    const existingERP = await User.findOne({ erpNumber });
    if (existingERP) {
      return res.status(400).json({ error: 'User with this ERP number already exists' });
    }

    // Generate username from email
    const username = email.split('@')[0] + Math.random().toString(36).substring(2, 8);

    // Create new user with correct field names
    const newUser = new User({
      username,
      email,
      password,
      fullName,
      contactNumber: contactNumber || '',
      specialization: specialization || 'Cybersecurity',
      sem: sem || '7',
      erpNumber,
      collegeName: collegeName || 'PIET',
      role: 'student',
      isVerified: true,
    });

    await newUser.save();

await sendMail({
  email: newUser.email,
  subject: 'Welcome to TechD Labs CTF Challenge Platform',
  message: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0;">
  <div style="background: #dc2626; color: white; padding: 25px; text-align: center;">
    <h1 style="margin: 0; font-size: 24px;">TECHD LABS</h1>
    <p style="margin: 5px 0 0 0; opacity: 0.9;">CTF Challenge Platform</p>
  </div>
  
  <div style="padding: 30px;">
    <p style="color: #1f2937; margin-bottom: 15px;">
      Hello <strong>${newUser.fullName}</strong>,
    </p>
    
    <p style="color: #4b5563; margin-bottom: 20px;">
      Your account has been successfully created on the TechD Labs CTF Challenge Platform.
    </p>
    
    <div style="background: #f8fafc; padding: 20px; border-radius: 6px; margin: 20px 0; border: 1px solid #e5e7eb;">
      <h3 style="color: #dc2626; margin: 0 0 15px 0; text-align: center;">Account Credentials</h3>
      <table style="width: 100%;">
        <tr><td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb; font-weight: bold; width: 120px;">Email:</td><td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">${newUser.email}</td></tr>
        <tr><td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb; font-weight: bold;">Password:</td><td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">${password}</td></tr>
        <tr><td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb; font-weight: bold;">Semester:</td><td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">${newUser.sem}</td></tr>
        <tr><td style="padding: 8px 0; font-weight: bold;">ERP Number:</td><td style="padding: 8px 0;">${newUser.erpNumber}</td></tr>
      </table>
    </div>

    <div style="background: #fef2f2; padding: 15px; border-radius: 6px; margin: 20px 0; border: 1px solid #fecaca;">
      <p style="color: #dc2626; margin: 0; font-weight: bold;">🔒 Change your password after first login</p>
    </div>

    <div style="text-align: center; margin: 25px 0;">
      <a href="${process.env.FRONTEND_URL}/login" style="background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
        Login to Platform
      </a>
      <p style="color: #6b7280; margin: 10px 0 0 0; font-size: 14px;">Access your account to start challenges</p>
    </div>

    <div style="background: #f8fafc; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #dc2626;">
      <p style="color: #4b5563; margin: 0; font-size: 14px;">
        <strong>Note:</strong> Keep your credentials secure and do not share them with anyone.
      </p>
    </div>
  </div>
  
  <div style="background: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e5e7eb;">
    <p style="color: #6b7280; margin: 0 0 5px 0; font-size: 12px;">© ${new Date().getFullYear()} TechD Labs CTF Platform</p>
    <p style="color: #9ca3af; margin: 0; font-size: 11px;">Building cybersecurity professionals</p>
  </div>
</div>
  `
});
    // Generate JWT token
    const token = jwt.sign({ 
      id: newUser._id, 
      role: newUser.role,
      email: newUser.email
    }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // Set cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    const userResponse = newUser.toJSON();
    delete userResponse.password;

    res.status(201).json({
      message: 'User registered successfully',
      user: userResponse,
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ error: 'Validation failed', details: errors });
    }
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Get current user
router.get('/me', requireAuth, async (req, res) => {
  try {
    console.log('📡 /me endpoint - user:', req.user.email);
    res.json({ 
      user: req.user.toJSON(),
      message: 'User retrieved successfully'
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User login
router.post('/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    console.log('🔐 Login attempt for:', req.body.email);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      console.log('❌ User not found:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const correct = await bcrypt.compare(password, user.password);
    if (!correct) {
      console.log('❌ Incorrect password for:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    if (!user.isActive) {
      console.log('❌ Account deactivated:', email);
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Track login
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    user.lastLogin = new Date();
    user.lastSeen = new Date();
    user.loginHistory.push({
      timestamp: new Date(),
      ipAddress: clientIP,
      userAgent: userAgent,
      location: await getLocationFromIP(clientIP)
    });

    if (user.loginHistory.length > 10) {
      user.loginHistory = user.loginHistory.slice(-10);
    }

    await user.save();

    // Generate JWT token
    const token = jwt.sign({ 
      id: user._id, 
      role: user.role,
      email: user.email
    }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // Set cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    console.log('✅ Login successful for:', email);
    
    const userResponse = user.toJSON();
    delete userResponse.password;
    
    res.json({ 
      message: 'Login successful', 
      user: userResponse, 
      token: token 
    });
  } catch (err) {
    console.error('💥 Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Forgot password
// Forgot password - with domain validation
router.post('/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email')
    .custom((email) => {
      if (!email.endsWith('@paruluniversity.ac.in')) {
        throw new Error('Only @paruluniversity.ac.in emails are accepted');
      }
      return true;
    })
], async (req, res) => {
  try {
    console.log('🔐 Forgot password request for:', req.body.email);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal whether email exists for security
      return res.json({ 
        message: 'If an account with that email exists, a password reset link has been sent.' 
      });
    }

    // Generate raw + hashed token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    await user.save();

    const resetURL = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password/${resetToken}`;

    await sendMail({
  email: user.email,
  subject: 'Password Reset Request - TechD Labs',
  message: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0;">
  <div style="background: #dc2626; color: white; padding: 25px; text-align: center;">
    <h2 style="margin: 0;">TechD Labs</h2>
  </div>
  
  <div style="padding: 30px;">
    <p style="color: #1f2937; margin-bottom: 15px;">
      Hi <strong>${user.fullName || 'User'}</strong>,
    </p>
    
    <p style="color: #4b5563; margin-bottom: 15px;">
      We received a request to reset your password for your TechD Labs account.
    </p>
    
    <div style="text-align: center; margin: 25px 0;">
      <a href="${resetURL}" 
         style="background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
        Reset Password
      </a>
    </div>
    
    <p style="color: #dc2626; font-weight: bold; text-align: center; margin: 20px 0;">
      This link will expire in 1 hour.
    </p>
    
    <p style="color: #4b5563; margin: 20px 0;">
      If you didn't request this reset, please ignore this email. Your account remains secure.
    </p>
  </div>
  
  <div style="background: #f8fafc; padding: 15px; text-align: center; font-size: 12px; color: #555;">
    © ${new Date().getFullYear()} TechD Labs. All rights reserved.
  </div>
</div>
  `
});

    res.json({ 
      message: 'If an account with that email exists, a password reset link has been sent.' 
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error while processing your request' });
  }
});

// Reset password
router.post('/reset-password/:token', [
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { token } = req.params;
    const { newPassword } = req.body;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    }).select('+password');

    if (!user) {
      return res.status(400).json({ error: 'Token is invalid or has expired' });
    }

    // Check if new password is same as old
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ 
        error: 'New password cannot be the same as the old password' 
      });
    }

    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Send confirmation email
await sendMail({
  email: user.email,
  subject: 'Password Changed Successfully - TechD Labs',
  message: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0;">
  <div style="background: #dc2626; color: white; padding: 25px; text-align: center;">
    <h2 style="margin: 0;">Password Updated Successfully</h2>
  </div>
  
  <div style="padding: 30px;">
    <p style="color: #1f2937; margin-bottom: 15px;">
      Hi <strong>${user.fullName || 'User'}</strong>,
    </p>
    
    <p style="color: #4b5563; margin-bottom: 15px;">
      Your password was successfully updated on <strong>${new Date().toLocaleString()}</strong>.
    </p>
    
    <p style="color: #dc2626; font-weight: bold; margin: 20px 0;">
      If you didn't make this change, please contact our security team immediately.
    </p>
  </div>
  
  <div style="background: #f8fafc; padding: 15px; text-align: center; font-size: 12px; color: #555;">
    © ${new Date().getFullYear()} TechD Labs. All rights reserved.
  </div>
</div>
  `
});

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ----------------- PROTECTED ROUTES ----------------- //

// All routes below this line require authentication
router.use(requireAuth);

// Apply lastSeen update to all protected routes
router.use(async (req, res, next) => {
  try {
    if (req.user) {
      req.user.lastSeen = new Date();
      await req.user.save();
    }
    next();
  } catch (error) {
    console.error('Error updating last seen:', error);
    next();
  }
});

// Logout
router.post('/logout', async (req, res) => {
  try {
    console.log('🚪 Logging out user:', req.user.email);
    
    // Update logout time in login history
    const latestLogin = req.user.loginHistory
      .filter(login => !login.logoutTime)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

    if (latestLogin) {
      latestLogin.logoutTime = new Date();
      latestLogin.sessionDuration = latestLogin.logoutTime - new Date(latestLogin.timestamp);
      await req.user.save();
    }

    res.cookie('jwt', 'loggedout', { 
      expires: new Date(Date.now() + 10 * 1000), 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    });
    
    console.log('✅ Logout successful');
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile
router.patch('/update-profile', [
  body('email').optional().isEmail().withMessage('Please provide a valid email'),
  body('contactNumber').optional().isMobilePhone().withMessage('Please provide a valid phone number'),
  body('expertiseLevel').optional().isIn(['Beginner', 'Junior', 'Intermediate', 'Senior', 'Expert']).withMessage('Invalid expertise level')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const updates = ['fullName', 'contactNumber', 'specialization', 'expertiseLevel'];
    
    // Check if email is being updated and if it's unique
    if (req.body.email && req.body.email !== req.user.email) {
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already taken' });
      }
      req.user.email = req.body.email;
    }

    updates.forEach(field => {
      if (req.body[field] !== undefined) req.user[field] = req.body[field];
    });

    await req.user.save();

    const userResponse = req.user.toJSON();
    delete userResponse.password;

    res.json({ 
      message: 'Profile updated successfully', 
      user: userResponse 
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password (when logged in)
router.patch('/change-password', [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
    .withMessage('New password must contain uppercase, lowercase, number, and special character')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id).select('+password');

    const correct = await bcrypt.compare(currentPassword, user.password);
    if (!correct) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Check if new password is same as old
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ 
        error: 'New password cannot be the same as the current password' 
      });
    }

    user.password = newPassword;
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user session info
router.get('/session', (req, res) => {
  try {
    const userResponse = req.user.toJSON();
    delete userResponse.password;

    res.json({
      user: userResponse,
      session: {
        authenticated: true,
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000) // 1 day from now
      }
    });
  } catch (error) {
    console.error('Session error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ----------------- HELPER FUNCTIONS ----------------- //

async function getLocationFromIP(ip) {
  try {
    if (ip === '127.0.0.1' || ip === '::1') return 'Localhost';
    if (ip.startsWith('192.168.')) return 'Local Network';
    if (ip.startsWith('10.')) return 'Private Network';
    if (ip.startsWith('172.')) return 'Private Network';
    return 'Unknown';
  } catch {
    return 'Unknown';
  }
}

module.exports = { router, requireAuth };