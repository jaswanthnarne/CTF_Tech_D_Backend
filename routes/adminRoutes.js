const express = require('express');
const mongoose = require('mongoose');
const User = require('../models/User');
const Admin = require('../models/Admin');
const CTF = require('../models/CTF');
const Submission = require('../models/Submission');
const { body, validationResult } = require('express-validator');
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const { Parser } = require('@json2csv/plainjs');
const sendMail = require('../utils/sendMail');

const router = express.Router();

// Middleware to protect admin routes
const requireAdmin = async (req, res, next) => {
  try {
    console.log('🔐 Admin auth middleware checking authentication...');
    
    // Extract token from multiple sources
    let token = req.cookies?.jwt || 
                req.headers.authorization?.replace('Bearer ', '') ||
                req.headers.Authorization?.replace('Bearer ', '') ||
                req.query?.token;

    // console.log('📡 Token present:', !!token);
    
    if (!token) {
      console.log('❌ No token found - authentication required');
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Clean the token
    token = token.trim().replace(/^"(.*)"$/, '$1');

    // DEVELOPMENT MODE: Handle mock tokens
    if (process.env.NODE_ENV === 'development') {
      console.log('🔧 Development mode - checking for mock token');
      
      if (token === 'mock-token' || token === 'dev-token' || token.startsWith('mock-')) {
        console.log('🔧 Using development mock authentication');
        
        // Find any admin user for development
        let adminUser = await Admin.findOne({}).sort({ createdAt: -1 }) || 
                       await User.findOne({ role: 'admin' }).sort({ createdAt: -1 });
        
        if (!adminUser) {
          console.log('❌ No admin user found for mock authentication');
          return res.status(403).json({ error: 'No admin user found in database' });
        }

        console.log('✅ Development mock authentication successful:', adminUser.email);
        req.admin = adminUser;
        return next();
      }
    }

    // PRODUCTION MODE: Real JWT verification
    if (token === 'null' || token === 'undefined' || token === 'loggedout') {
      console.log('❌ Invalid token value:', token);
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('✅ Token decoded successfully:', { 
      id: decoded.id, 
      role: decoded.role,
      isAdminCollection: decoded.isAdminCollection 
    });

    let adminUser = null;

    // Check if user is from Admin collection
    if (decoded.isAdminCollection) {
      adminUser = await Admin.findById(decoded.id);
      console.log('🔍 Admin collection lookup:', adminUser ? 'Found' : 'Not found');
    } 
    // Check if user is from User collection with admin role
    else {
      adminUser = await User.findOne({ 
        _id: decoded.id, 
        role: 'admin',
        isActive: true 
      });
      console.log('🔍 User collection admin lookup:', adminUser ? 'Found' : 'Not found');
    }

    if (!adminUser) {
      console.log('❌ Admin user not found or not authorized');
      return res.status(403).json({ error: 'Admin access required' });
    }

    if (!adminUser.isActive) {
      console.log('❌ Admin account is deactivated');
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    console.log('✅ Admin authenticated:', adminUser.email, 'Role:', adminUser.role);
    req.admin = adminUser;
    next();
  } catch (error) {
    console.error('🔒 Admin auth error:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      console.error('🔒 JWT Error Details:', {
        token: req.headers.authorization?.substring(0, 50) + '...',
        message: error.message
      });
      return res.status(401).json({ error: 'Invalid token format' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    console.error('Admin auth unexpected error:', error);
    res.status(500).json({ error: 'Authentication server error' });
  }
};

// ==========================
// Admin Management
// ==========================

// Register first admin
router.post('/register-first-admin', async (req, res) => {
    try {
        const existingAdmins = await Admin.countDocuments();
        if (existingAdmins > 0) {
            return res.status(400).json({ error: 'First admin already registered' });
        }
        const { fullName, email, password } = req.body;
        if (!fullName || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        const newAdmin = new Admin({ fullName, email, password, role: 'superadmin' });
        await newAdmin.save();
        const adminResponse = newAdmin.toObject();
        delete adminResponse.password;
        res.status(201).json({ message: 'First superadmin created successfully', admin: adminResponse });
    } catch (error) {
        console.error('Register first admin error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create admin (superadmin only)
router.post('/create-admin', requireAdmin, [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('fullName').notEmpty().withMessage('Full name is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });

    // Check if current admin is superadmin
    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ error: 'Superadmin access required' });
    }

    const { fullName, email, password, role } = req.body;

    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin with this email already exists' });
    }

    const newAdmin = new Admin({ 
      fullName, 
      email, 
      password, 
      role: role || 'admin' 
    });
    await newAdmin.save();

    const adminResponse = newAdmin.toObject();
    delete adminResponse.password;

    res.status(201).json({ 
      message: 'Admin created successfully', 
      admin: adminResponse 
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin login
router.post('/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    console.log("login admin", req.body);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });

    const { email, password } = req.body;
    
    // Try to find in Admin collection first
    let admin = await Admin.findOne({ email }).select('+password');
    let isAdminCollection = true;

    // If not found in Admin collection, check User collection for admin role
    if (!admin) {
      admin = await User.findOne({ email, role: 'admin' }).select('+password');
      isAdminCollection = false;
    }

    if (!admin) return res.status(401).json({ error: 'Invalid email or password' });

    const isMatch = await admin.correctPassword(password, admin.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });

    if (!admin.isActive) return res.status(403).json({ error: 'Account is deactivated' });

    // Update last login
    admin.lastLogin = new Date();
    await admin.save();

    const token = jwt.sign({ 
      id: admin._id, 
      role: admin.role,
      isAdminCollection 
    }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    const adminResponse = admin.toObject();
    delete adminResponse.password;

    res.json({ 
      message: 'Login successful', 
      admin: adminResponse, 
      token 
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get admin profile
router.get('/profile', requireAdmin, async (req, res) => {
  try {
    const admin = await (req.admin.constructor.modelName === 'Admin' ? 
      Admin : User).findById(req.admin._id).select('-password');
    
    res.json({
      message: 'Admin profile retrieved successfully',
      admin
    });
  } catch (error) {
    console.error('Get admin profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// CTF Management
// ==========================

// Create CTF
router.post('/ctfs/create', requireAdmin, [
  body('title').notEmpty().withMessage('Title is required'),
  body('description').notEmpty().withMessage('Description is required'),
  body('category').isIn(['Web Security', 'Cryptography', 'Forensics', 'Reverse Engineering', 'Pwn', 'Misc']).withMessage('Invalid category'),
  body('points').isInt({ min: 0 }).withMessage('Points must be a positive integer'),
  body('activeHours.startTime').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Start time must be in HH:MM format'),
  body('activeHours.endTime').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('End time must be in HH:MM format'),
  body('schedule.startDate').isISO8601().withMessage('Valid start date is required'),
  body('schedule.endDate').isISO8601().withMessage('Valid end date is required')
], async (req, res) => {
  try {
    console.log('Create CTF request body:', req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { 
      title, description, category, points, flag, difficulty,
      activeHours, schedule, maxAttempts, hints, files, rules, ctfLink
    } = req.body;

    // ✅ Validate active hours: must be different
    if (activeHours.startTime === activeHours.endTime) {
      return res.status(400).json({ error: 'Start time and end time cannot be the same' });
    }

    // ✅ Validate schedule: allow same date, only block if end < start
    if (new Date(schedule.startDate) > new Date(schedule.endDate)) {
      return res.status(400).json({ error: 'End date cannot be before start date' });
    }

    const ctf = new CTF({
      title,
      description,
      category,
      points,
      flag: flag || `CTF{${crypto.randomBytes(8).toString('hex')}}`,
      difficulty: difficulty || 'Easy',
      activeHours,
      schedule: {
        startDate: new Date(schedule.startDate),
        endDate: new Date(schedule.endDate),
        recurrence: schedule.recurrence || 'once'
      },
      maxAttempts: maxAttempts || 3,
      hints: hints || [],
      files: files || [],
      rules: rules || {},
      ctfLink: ctfLink || '',
      createdBy: req.admin._id
    });

    ctf.status = ctf.calculateStatus();
    console.log('Initial CTF status:', ctf.status);
    
    await ctf.save();

    res.status(201).json({
      message: 'CTF created successfully',
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        category: ctf.category,
        points: ctf.points,
        difficulty: ctf.difficulty,
        status: ctf.status,
        activeHours: ctf.activeHours,
        schedule: ctf.schedule,
        isVisible: ctf.isVisible,
        isPublished: ctf.isPublished,
        ctfLink: ctf.ctfLink
      }
    });
  } catch (error) {
    console.error('Create CTF error:', error);
    
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validationErrors 
      });
    }
    
    res.status(500).json({ error: 'Server error' });
  }
});

// ✅ Get All CTFs (Admin View with Filters + Pagination)
// In adminRoutes.js - Update the get all CTFs endpoint
router.get('/ctfs', requireAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      status = 'all',
      category = 'all',
      search = ''
    } = req.query;

    const filter = {};

    if (status !== 'all') {
      filter.status = status;
    }

    if (category !== 'all') {
      filter.category = category;
    }

    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const ctfs = await CTF.find(filter)
      .populate('createdBy', 'fullName email')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await CTF.countDocuments(filter);

    // ✅ Update status for each CTF based on current time
    const updatedCTFs = await Promise.all(ctfs.map(async (ctf) => {
      const newStatus = ctf.calculateStatus();
      if (ctf.status !== newStatus) {
        ctf.status = newStatus;
        await ctf.save();
      }
      return ctf;
    }));

    // ✅ Transform for cleaner response
    const formattedCTFs = updatedCTFs.map(ctf => ({
      _id: ctf._id,
      title: ctf.title,
      description: ctf.description,
      category: ctf.category,
      points: ctf.points,
      difficulty: ctf.difficulty,
      status: ctf.status,
      isCurrentlyActive: ctf.isCurrentlyActive(),
      createdBy: ctf.createdBy,
      createdAt: ctf.createdAt,
      schedule: ctf.schedule,
      activeHours: ctf.activeHours,
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      ctfLink: ctf.ctfLink,
      participants: ctf.participants
    }));

    res.json({
      ctfs: formattedCTFs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get all CTFs error:', error);
    res.status(500).json({ error: 'Server error while fetching CTFs' });
  }
});


// ✅ Get Single CTF (Admin View with Participants)
router.get('/ctfs/:id', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id)
      .populate('createdBy', 'fullName email')
      .populate('participants.user', 'fullName email expertiseLevel');

    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    const detailedCTF = {
      _id: ctf._id,
      title: ctf.title,
      description: ctf.description,
      category: ctf.category,
      points: ctf.points,
      difficulty: ctf.difficulty,
      flag: ctf.flag,
      status: ctf.status,
      createdBy: ctf.createdBy,
      schedule: ctf.schedule,
      activeHours: ctf.activeHours,
      hints: ctf.hints,
      files: ctf.files,
      rules: ctf.rules,
      maxAttempts: ctf.maxAttempts,
      participants: ctf.participants,
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      ctfLink: ctf.ctfLink,
      createdAt: ctf.createdAt,
      updatedAt: ctf.updatedAt
    };

    res.json({ ctf: detailedCTF });
  } catch (error) {
    console.error('Get CTF by ID error:', error);
    res.status(500).json({ error: 'Server error while fetching CTF details' });
  }
});


// Update CTF
// Update CTF
router.put('/ctfs/:id', requireAdmin, [
  body('title').optional().notEmpty().withMessage('Title cannot be empty'),
  body('description').optional().notEmpty().withMessage('Description cannot be empty'),
  body('category').optional().isIn(['Web Security', 'Cryptography', 'Forensics', 'Reverse Engineering', 'Pwn', 'Misc']).withMessage('Invalid category'),
  body('points').optional().isInt({ min: 0 }).withMessage('Points must be a positive integer'),
  body('activeHours.startTime').optional().matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Start time must be in HH:MM format'),
  body('activeHours.endTime').optional().matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('End time must be in HH:MM format')
], async (req, res) => {
  try {
    console.log('Update CTF request body:', req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const ctf = await CTF.findById(req.params.id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    const basicFields = [
      'title', 'description', 'category', 'points', 'difficulty',
      'maxAttempts', 'hints', 'files', 'rules', 'ctfLink'
    ];

    basicFields.forEach(field => {
      if (req.body[field] !== undefined) {
        ctf[field] = req.body[field];
      }
    });

    if (req.body.schedule) {
      const updatedSchedule = {
        startDate: req.body.schedule.startDate ? new Date(req.body.schedule.startDate) : ctf.schedule.startDate,
        endDate: req.body.schedule.endDate ? new Date(req.body.schedule.endDate) : ctf.schedule.endDate,
        recurrence: req.body.schedule.recurrence || ctf.schedule.recurrence || 'once'
      };

      // ✅ Allow same date
      if (updatedSchedule.startDate > updatedSchedule.endDate) {
        return res.status(400).json({ error: 'End date cannot be before start date' });
      }

      ctf.schedule = updatedSchedule;
    }

    if (req.body.activeHours) {
      const updatedActiveHours = {
        startTime: req.body.activeHours.startTime || ctf.activeHours.startTime,
        endTime: req.body.activeHours.endTime || ctf.activeHours.endTime,
        timezone: req.body.activeHours.timezone || ctf.activeHours.timezone || 'UTC'
      };

      // ✅ Require different times
      if (updatedActiveHours.startTime === updatedActiveHours.endTime) {
        return res.status(400).json({ error: 'Start time and end time cannot be the same' });
      }

      ctf.activeHours = updatedActiveHours;
    }

    if (typeof req.body.isVisible !== 'undefined') ctf.isVisible = req.body.isVisible;
    if (typeof req.body.isPublished !== 'undefined') ctf.isPublished = req.body.isPublished;

    ctf.status = ctf.calculateStatus();

    await ctf.validate();
    await ctf.save();

    res.json({
      message: 'CTF updated successfully',
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        category: ctf.category,
        points: ctf.points,
        status: ctf.status,
        isVisible: ctf.isVisible,
        isPublished: ctf.isPublished,
        schedule: ctf.schedule,
        activeHours: ctf.activeHours,
        ctfLink: ctf.ctfLink
      }
    });
  } catch (error) {
    console.error('Update CTF error:', error);
    
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => ({
        field: err.path,
        message: err.message
      }));
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validationErrors 
      });
    }
    
    res.status(500).json({ error: 'Server error' });
  }
});

// Publish CTF
router.post('/ctfs/:id/publish', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id);
    
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    ctf.isVisible = true;
    ctf.isPublished = true;
    await ctf.save();

    res.json({ 
      message: 'CTF published successfully',
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        isVisible: ctf.isVisible,
        isPublished: ctf.isPublished
      }
    });
  } catch (error) {
    console.error('Publish CTF error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Unpublish CTF
router.post('/ctfs/:id/unpublish', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id);
    
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    ctf.isVisible = false;
    ctf.isPublished = false;
    await ctf.save();

    res.json({ 
      message: 'CTF unpublished successfully',
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        isVisible: ctf.isVisible,
        isPublished: ctf.isPublished
      }
    });
  } catch (error) {
    console.error('Unpublish CTF error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete CTF
router.delete('/ctfs/:id', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Delete related submissions
    await Submission.deleteMany({ ctf: req.params.id });

    await CTF.findByIdAndDelete(req.params.id);

    res.json({ message: 'CTF deleted successfully' });
  } catch (error) {
    console.error('Delete CTF error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get CTF participants
router.get('/ctfs/:id/participants', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;

    const ctf = await CTF.findById(req.params.id)
      .populate({
        path: 'participants.user',
        select: 'fullName email expertiseLevel lastSeen'
      })
      .select('participants title');

    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Sort participants by points earned (descending) and submission time
    const sortedParticipants = ctf.participants.sort((a, b) => {
      if (b.pointsEarned !== a.pointsEarned) {
        return b.pointsEarned - a.pointsEarned;
      }
      return new Date(a.submittedAt) - new Date(b.submittedAt);
    });

    // Paginate participants
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const paginatedParticipants = sortedParticipants.slice(startIndex, endIndex);

    res.json({
      ctf: { _id: ctf._id, title: ctf.title },
      participants: paginatedParticipants,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: ctf.participants.length,
        pages: Math.ceil(ctf.participants.length / limit)
      }
    });
  } catch (error) {
    console.error('Get CTF participants error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// routes/adminRoutes.js - Add these endpoints

// Toggle CTF activation
router.put('/ctfs/:id/toggle-activation', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    await ctf.toggleActivation();
    await ctf.save();

    res.json({
      message: `CTF ${ctf.isVisible ? 'activated' : 'deactivated'} successfully`,
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        isVisible: ctf.isVisible,
        status: ctf.status
      }
    });
  } catch (error) {
    console.error('Toggle activation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// In your admin routes - Add these endpoints:

// Force status update for CTF
router.put('/ctfs/:id/force-status', requireAdmin, [
  body('status').isIn(['active', 'upcoming', 'ended', 'inactive']).withMessage('Invalid status')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { status } = req.body;
    const ctf = await CTF.findById(req.params.id);
    
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Use the force status method
    ctf.forceStatusUpdate(status);
    await ctf.save();

    res.json({
      message: `CTF status force-updated to ${status}`,
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: ctf.status,
        isVisible: ctf.isVisible,
        isPublished: ctf.isPublished
      }
    });
  } catch (error) {
    console.error('Force status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});



// Enhanced CTF analytics endpoint
router.get('/ctf-analytics/:id', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id)
      .populate('participants.user', 'fullName email expertiseLevel');
    
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Use the enhanced analytics method
    const analytics = ctf.getAnalytics();

    res.json({
      message: 'CTF analytics retrieved successfully',
      analytics
    });
  } catch (error) {
    console.error('Get CTF analytics error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Bulk status update endpoint
router.post('/ctfs/bulk-status-update', requireAdmin, [
  body('ctfIds').isArray().withMessage('CTF IDs array is required'),
  body('status').isIn(['active', 'upcoming', 'ended', 'inactive']).withMessage('Invalid status')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { ctfIds, status } = req.body;
    
    const results = await Promise.all(
      ctfIds.map(async (ctfId) => {
        try {
          const ctf = await CTF.findById(ctfId);
          if (ctf) {
            ctf.forceStatusUpdate(status);
            await ctf.save();
            return { ctfId, success: true, title: ctf.title };
          }
          return { ctfId, success: false, error: 'CTF not found' };
        } catch (error) {
          return { ctfId, success: false, error: error.message };
        }
      })
    );

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success);

    res.json({
      message: `Bulk status update completed: ${successful} successful, ${failed.length} failed`,
      results: {
        successful,
        failed,
        details: results
      }
    });
  } catch (error) {
    console.error('Bulk status update error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Export CTF submissions
router.get('/export/ctfs/:id/submissions', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    const submissions = await Submission.find({ ctf: req.params.id })
      .populate('user', 'fullName email')
      .populate('reviewedBy', 'fullName email')
      .sort({ submittedAt: -1 });

    if (!submissions.length) {
      return res.status(404).json({ error: 'No submissions found for this CTF' });
    }

    // Helper to convert UTC date to IST string
    const toIST = (date) => {
      if (!date) return '';
      return new Date(date).toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        hour12: false,
      });
    };

    // Map only required fields
    const formattedSubmissions = submissions.map((sub) => ({
      userFullName: sub.user?.fullName || 'N/A',
      userEmail: sub.user?.email || 'N/A',
      screenshotUrl: sub.screenshot?.url || '',
      submissionStatus: sub.submissionStatus || '',
      points: sub.points ?? 0,
      submittedAt: toIST(sub.submittedAt),
      reviewedAt: toIST(sub.reviewedAt),
      reviewedBy: sub.reviewedBy?.fullName || sub.reviewedBy?.email || 'N/A',
    }));

    const fields = [
      'userFullName',
      'userEmail',
      'screenshotUrl',
      'submissionStatus',
      'points',
      'submittedAt',
      'reviewedAt',
      'reviewedBy',
    ];

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedSubmissions);

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=submissions-${ctf.title}-${new Date()
        .toISOString()
        .split('T')[0]}.csv`
    );

    res.send(csv);
  } catch (error) {
    console.error('Export submissions error:', error);
    res.status(500).json({ error: 'Failed to export submissions' });
  }
});

// Export CTF participants
router.get('/export/ctfs/:id/participants', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id).populate('participants.user', 'fullName email expertiseLevel');
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    const participantsData = ctf.participants.map(p => ({
      fullName: p.user.fullName,
      email: p.user.email,
      expertiseLevel: p.user.expertiseLevel,
      joinedAt: p.joinedAt,
      submittedAt: p.submittedAt,
      isCorrect: p.isCorrect,
      pointsEarned: p.pointsEarned,
      attempts: p.attempts
    }));

    const fields = [
      'fullName',
      'email',
      'expertiseLevel',
      'joinedAt',
      'submittedAt',
      'isCorrect',
      'pointsEarned',
      'attempts'
    ];

    const parser = new Parser({ fields });
    const csv = parser.parse(participantsData);

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=participants-${ctf.title}-${new Date().toISOString().split('T')[0]}.csv`);
    res.send(csv);
  } catch (error) {
    console.error('Export participants error:', error);
    res.status(500).json({ error: 'Failed to export participants' });
  }
});

// ==========================
// User Management
// ==========================

// Create user
router.post('/users/create', requireAdmin, [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character'),
  body('fullName').notEmpty().trim().withMessage('Full name is required')
], async (req, res) => {
  try {
    console.log("create user", req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });

    const { email, password, fullName, contactNumber, Sem, expertiseLevel } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Generate username from email
    const username = email.split('@')[0] + Math.random().toString(36).substring(2, 8);

    const newUser = new User({
      username,
      email,
      password,
      fullName,
      contactNumber: contactNumber || '',
      Sem: Sem || '7',
      expertiseLevel: expertiseLevel || 'Beginner',
      isVerified: true
    });

    await newUser.save();

    // Send welcome email
  await sendMail({
  email: newUser.email,
  subject: 'Welcome to TechD CTF Platform - Your Account Details',
  message: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0;">
  <div style="background: #dc2626; color: white; padding: 25px; text-align: center;">
    <h1 style="margin: 0; font-size: 24px;">TECHD CTF PLATFORM</h1>
    <p style="margin: 5px 0 0 0; opacity: 0.9;">Cybersecurity Challenge Platform</p>
  </div>
  
  <div style="padding: 30px;">
    <p style="color: #1f2937; font-size: 16px; margin-bottom: 20px;">
      Hello <strong>${newUser.fullName}</strong>,
    </p>
    
    <p style="color: #4b5563; margin-bottom: 25px;">
      Your account has been successfully created. Here are your login credentials:
    </p>
    
    <div style="background: #f8fafc; padding: 20px; border-radius: 6px; margin: 20px 0; border: 1px solid #e5e7eb;">
      <h3 style="color: #dc2626; text-align: center; margin: 0 0 15px 0;">Account Credentials</h3>
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
        <strong>Note:</strong> Keep your credentials secure and do not share them.
      </p>
    </div>
  </div>
  
  <div style="background: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e5e7eb;">
    <p style="color: #6b7280; margin: 0 0 5px 0; font-size: 12px;">© ${new Date().getFullYear()} TechD CTF Platform</p>
    <p style="color: #9ca3af; margin: 0; font-size: 11px;">Building cybersecurity professionals</p>
  </div>
</div>
  `
});

    const userResponse = newUser.toJSON();
    delete userResponse.password;

    res.status(201).json({ 
      message: 'User created successfully', 
      user: userResponse 
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users
router.get('/users', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    
    const filter = {};
    if (search) {
      filter.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(filter)
      .select('-password -passwordResetToken -passwordResetExpires -loginHistory')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(filter);

    res.json({
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user
router.put('/users/:id', requireAdmin, [
  body('email').optional().isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { id } = req.params;
    const { email, fullName, contactNumber, Sem, expertiseLevel, isActive } = req.body;
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if email is being changed and if it's already taken
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already taken' });
      }
      user.email = email;
    }

    // Update fields
    if (fullName) user.fullName = fullName;
    if (contactNumber !== undefined) user.contactNumber = contactNumber;
    if (Sem) user.Sem  = Sem;
    if (expertiseLevel) user.expertiseLevel = expertiseLevel;
    if (typeof isActive !== 'undefined') user.isActive = isActive;
    
    await user.save();

    const userResponse = user.toJSON();
    delete userResponse.password;
    
    res.json({ 
      message: 'User updated successfully',
      user: userResponse
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user
router.delete('/users/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Prevent admin from deleting themselves
    if (req.admin._id.toString() === id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    await User.findByIdAndDelete(id);
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


// ==========================
// Analytics & Dashboard
// ==========================
router.get('/analytics/recent-activity', requireAdmin, async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    // Get recent submissions
    const recentSubmissions = await Submission.find()
      .populate('user', 'fullName email')
      .populate('ctf', 'title')
      .sort({ submittedAt: -1 })
      .limit(parseInt(limit))
      .then(submissions => 
        submissions.map(sub => ({
          type: 'submission',
          _id: sub._id,
          user: sub.user,
          ctf: sub.ctf,
          isCorrect: sub.submissionStatus === 'approved',
          points: sub.points,
          submittedAt: sub.submittedAt,
          timestamp: sub.submittedAt
        }))
      );
    
    res.json({
      message: 'Recent activity retrieved successfully',
      activities: recentSubmissions
    });
    
  } catch (error) {
    console.error('Get recent activity error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Get dashboard statistics
// Dashboard stats endpoint
router.get('/dashboard-stats', requireAdmin, async (req, res) => {
  try {
    // Get total users count
    const totalUsers = await User.countDocuments();
    
    // Get active users (users with recent activity)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const activeUsers = await User.countDocuments({
      lastLogin: { $gte: sevenDaysAgo }
    });
    
    // Get new users today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const newUsersToday = await User.countDocuments({
      createdAt: { $gte: today }
    });
    
    // Get CTF stats
    const totalCTFs = await CTF.countDocuments();
    const publishedCTFs = await CTF.countDocuments({ isPublished: true });
    const visibleCTFs = await CTF.countDocuments({ 
      isPublished: true, 
      status: 'active' 
    });
    
    // Get submission stats
    const totalSubmissions = await Submission.countDocuments();
    const correctSubmissions = await Submission.countDocuments({ 
      submissionStatus: 'approved' 
    });
    const pendingSubmissions = await Submission.countDocuments({ 
      submissionStatus: 'pending' 
    });
    
    // Calculate CTF status breakdown
    const currentTime = new Date();
    const ctfs = await CTF.find({});
    
    const ctfStatusBreakdown = {
      active: { count: 0 },
      upcoming: { count: 0 },
      ended: { count: 0 },
      inactive: { count: 0 }
    };
    
    ctfs.forEach(ctf => {
      const startDate = new Date(ctf.schedule.startDate);
      const endDate = new Date(ctf.schedule.endDate);
      
      if (ctf.status === 'active') {
        if (currentTime >= startDate && currentTime <= endDate) {
          ctfStatusBreakdown.active.count++;
        } else if (currentTime < startDate) {
          ctfStatusBreakdown.upcoming.count++;
        } else {
          ctfStatusBreakdown.ended.count++;
        }
      } else {
        ctfStatusBreakdown.inactive.count++;
      }
    });
    
    // Get recent activity (last 20 activities)
    const recentActivity = await Submission.find()
      .populate('user', 'fullName email')
      .populate('ctf', 'title')
      .sort({ submittedAt: -1 })
      .limit(20)
      .then(submissions => 
        submissions.map(sub => ({
          type: 'submission',
          _id: sub._id,
          user: sub.user,
          ctf: sub.ctf,
          isCorrect: sub.submissionStatus === 'approved',
          points: sub.points,
          submittedAt: sub.submittedAt,
          timestamp: sub.submittedAt
        }))
      );
    
    const stats = {
      totalUsers,
      activeUsers,
      newUsersToday,
      totalCTFs,
      publishedCTFs,
      visibleCTFs,
      totalSubmissions,
      correctSubmissions,
      pendingSubmissions,
      ctfStatusBreakdown
    };
    
    res.json({
      message: 'Dashboard stats retrieved successfully',
      stats,
      recentActivity
    });
    
  } catch (error) {
    console.error('Get dashboard stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get CTF analytics
router.get('/ctf-analytics/:id', requireAdmin, async (req, res) => {
  try {
    const ctf = await CTF.findById(req.params.id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    const analytics = {
      basic: {
        title: ctf.title,
        category: ctf.category,
        difficulty: ctf.difficulty,
        points: ctf.points,
        status: ctf.status,
        totalParticipants: ctf.participants.length,
        correctSubmissions: ctf.correctSubmissions,
        totalSubmissions: ctf.totalSubmissions,
        successRate: ctf.totalSubmissions > 0 ? 
          Math.round((ctf.correctSubmissions / ctf.totalSubmissions) * 100) : 0
      },
      participants: ctf.participants.map(p => ({
        user: p.user,
        joinedAt: p.joinedAt,
        submittedAt: p.submittedAt,
        isCorrect: p.isCorrect,
        pointsEarned: p.pointsEarned,
        attempts: p.attempts
      })),
      schedule: {
        activeHours: ctf.activeHours,
        currentStatus: ctf.isCurrentlyActive() ? 'Active' : 'Inactive',
        nextActive: ctf.calculateNextActivePeriod()
      }
    };

    res.json({ analytics });
  } catch (error) {
    console.error('Get CTF analytics error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// In adminRoutes.js - Add force status recalculation
router.post('/ctfs/recalculate-statuses', requireAdmin, async (req, res) => {
  try {
    const ctfs = await CTF.find({});
    let updated = 0;
    
    for (const ctf of ctfs) {
      const oldStatus = ctf.status;
      const newStatus = ctf.calculateStatus();
      
      if (oldStatus !== newStatus) {
        ctf.status = newStatus;
        await ctf.save();
        updated++;
        
        console.log('🔄 Status Updated:', {
          title: ctf.title,
          from: oldStatus,
          to: newStatus,
          isCurrentlyActive: ctf.isCurrentlyActive()
        });
      }
    }
    
    res.json({
      message: `CTF statuses recalculated: ${updated} updated`,
      updated
    });
  } catch (error) {
    console.error('Recalculate statuses error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// ==========================
// System Management
// ==========================

// Update all CTF statuses
router.post('/update-ctf-statuses', requireAdmin, async (req, res) => {
  try {
    const result = await CTF.updateAllStatuses();
    res.json({ 
      message: 'CTF statuses updated successfully',
      updated: result.updated
    });
  } catch (error) {
    console.error('Update CTF statuses error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin logout
router.post('/logout', requireAdmin, (req, res) => {
  res.clearCookie('jwt');
  res.json({ message: 'Logged out successfully' });
});


// ==========================
// Comprehensive Analytics
// ==========================

// Get comprehensive analytics
router.get('/analytics/comprehensive', requireAdmin, async (req, res) => {
  try {
    const { timeRange = '7d' } = req.query;
    
    // Calculate date range based on timeRange parameter
    let startDate;
    const endDate = new Date();
    
    switch (timeRange) {
      case '24h':
        startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90d':
        startDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    }

    // Get comprehensive analytics data
    const [
      userStats,
      ctfStats,
      submissionStats,
      categoryPerformance,
      userActivityStats
    ] = await Promise.all([
      // User statistics
      User.aggregate([
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            active: { $sum: { $cond: ['$isActive', 1, 0] } },
            verified: { $sum: { $cond: ['$isVerified', 1, 0] } }
          }
        },
        {
          $project: {
            _id: 0,
            total: 1,
            active: 1,
            verified: 1
          }
        }
      ]),
      
      // CTF statistics by status
      CTF.aggregate([
        {
          $group: {
            _id: '$status',
            count: { $sum: 1 }
          }
        }
      ]),
      
      // Submission statistics
      Submission.aggregate([
        {
          $match: {
            submittedAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            correctSubmissions: { $sum: { $cond: ['$isCorrect', 1, 0] } }
          }
        }
      ]),
      
      // Category performance
      Submission.aggregate([
        {
          $match: {
            submittedAt: { $gte: startDate, $lte: endDate },
            isCorrect: true
          }
        },
        {
          $lookup: {
            from: 'ctfs',
            localField: 'ctf',
            foreignField: '_id',
            as: 'ctfInfo'
          }
        },
        {
          $unwind: '$ctfInfo'
        },
        {
          $group: {
            _id: '$ctfInfo.category',
            totalSolves: { $sum: 1 },
            averagePoints: { $avg: '$points' }
          }
        },
        {
          $sort: { totalSolves: -1 }
        }
      ]),
      
      // User activity stats
      User.aggregate([
        {
          $project: {
            activeToday: {
              $cond: [
                { $gte: ['$lastLogin', new Date(Date.now() - 24 * 60 * 60 * 1000)] },
                1,
                0
              ]
            },
            activeThisWeek: {
              $cond: [
                { $gte: ['$lastLogin', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)] },
                1,
                0
              ]
            }
          }
        },
        {
          $group: {
            _id: null,
            activeToday: { $sum: '$activeToday' },
            activeThisWeek: { $sum: '$activeThisWeek' }
          }
        }
      ])
    ]);

    // Get user role distribution
    const roleStats = await User.aggregate([
      {
        $group: {
          _id: '$role',
          count: { $sum: 1 }
        }
      }
    ]);

    // Get recent activity for the selected time range
    const recentActivity = await Submission.find({
      submittedAt: { $gte: startDate, $lte: endDate }
    })
    .populate('user', 'fullName email')
    .populate('ctf', 'title category')
    .sort({ submittedAt: -1 })
    .limit(20)
    .select('user ctf isCorrect points submittedAt');

    // Format the response
    const analytics = {
      users: {
        total: userStats[0]?.total || 0,
        active: userStats[0]?.active || 0,
        verified: userStats[0]?.verified || 0,
        roleStats: roleStats,
        activityStats: userActivityStats
      },
      ctfs: {
        total: ctfStats.reduce((acc, curr) => acc + curr.count, 0),
        statusStats: ctfStats
      },
      submissions: {
        total: submissionStats[0]?.total || 0,
        correctSubmissions: submissionStats[0]?.correctSubmissions || 0,
        categoryPerformance: categoryPerformance
      },
      resources: {
        totalStorage: 0, // You can calculate this if you have file storage
        activeConnections: 0 // You can track this if needed
      },
      recentActivity: recentActivity,
      timeRange: {
        start: startDate,
        end: endDate,
        label: timeRange
      }
    };

    res.json({
      message: 'Comprehensive analytics retrieved successfully',
      analytics
    });
  } catch (error) {
    console.error('Get comprehensive analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics data' });
  }
});

// Get user login history
// Recent logins endpoint
router.get('/recent-logins', requireAdmin, async (req, res) => {
  try {
    const { limit = 8 } = req.query;
    
    const recentLogins = await User.find()
      .sort({ lastLogin: -1 })
      .limit(parseInt(limit))
      .select('fullName email role isActive lastLogin');
    
    res.json({
      message: 'Recent logins retrieved successfully',
      recentLogins
    });
    
  } catch (error) {
    console.error('Get recent logins error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Add this endpoint in the Analytics & Dashboard section
router.get('/recent-logins', requireAdmin, async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const recentLogins = await User.find({ 
      lastLogin: { $exists: true, $ne: null }
    })
    .select('fullName email role lastLogin lastSeen isActive')
    .sort({ lastLogin: -1 })
    .limit(parseInt(limit));

    res.json({
      message: 'Recent logins retrieved successfully',
      recentLogins
    });
  } catch (error) {
    console.error('Get recent logins error:', error);
    res.status(500).json({ error: 'Failed to fetch recent logins' });
  }
});
// Export users data
router.get('/export/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find({})
      .select('fullName email contactNumber Sem expertiseLevel role isActive createdAt lastLogin')
      .sort({ createdAt: -1 });

    const fields = [
      'fullName',
      'email', 
      'contactNumber',
      'Sem',
      'expertiseLevel',
      'role',
      'isActive',
      'createdAt',
      'lastLogin'
    ];

    const parser = new Parser({ fields });
    const csv = parser.parse(users);

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=users-export.csv');
    res.send(csv);
  } catch (error) {
    console.error('Export users error:', error);
    res.status(500).json({ error: 'Failed to export users data' });
  }
});

// Export CTF data
router.get('/export/ctfs', requireAdmin, async (req, res) => {
  try {
    const ctfs = await CTF.find({})
      .populate('createdBy', 'fullName email')
      .select('title category points difficulty status isPublished participants createdAt')
      .sort({ createdAt: -1 });

    const formattedCTFs = ctfs.map(ctf => ({
      title: ctf.title,
      category: ctf.category,
      points: ctf.points,
      difficulty: ctf.difficulty,
      status: ctf.status,
      isPublished: ctf.isPublished,
      participants: ctf.participants.length,
      createdBy: ctf.createdBy?.fullName || 'Unknown',
      createdAt: ctf.createdAt
    }));

    const fields = [
      'title',
      'category',
      'points',
      'difficulty', 
      'status',
      'isPublished',
      'participants',
      'createdBy',
      'createdAt'
    ];

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedCTFs);

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=ctfs-export.csv');
    res.send(csv);
  } catch (error) {
    console.error('Export CTFs error:', error);
    res.status(500).json({ error: 'Failed to export CTFs data' });
  }
});


// System health check
router.get('/system-health', requireAdmin, async (req, res) => {
  try {
    const [userCount, ctfCount, submissionCount, dbStatus] = await Promise.all([
      User.countDocuments(),
      CTF.countDocuments(),
      Submission.countDocuments(),
      // Simple database connection check
      User.findOne().select('_id').lean()
    ]);

    const health = {
      status: 'healthy',
      timestamp: new Date(),
      components: {
        database: {
          status: dbStatus ? 'connected' : 'disconnected',
          users: userCount,
          ctfs: ctfCount,
          submissions: submissionCount
        },
        api: {
          status: 'running',
          uptime: process.uptime()
        },
        memory: {
          used: process.memoryUsage().heapUsed / 1024 / 1024,
          total: process.memoryUsage().heapTotal / 1024 / 1024
        }
      }
    };

    res.json(health);
  } catch (error) {
    console.error('System health check error:', error);
    res.status(500).json({ 
      status: 'unhealthy',
      error: 'System health check failed' 
    });
  }
});

// Get system configuration
router.get('/system/config', requireAdmin, async (req, res) => {
  try {
    const config = {
      environment: process.env.NODE_ENV || 'development',
      frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
      emailEnabled: !!process.env.EMAIL_SERVICE,
      features: {
        userRegistration: true,
        ctfCreation: true,
        emailNotifications: !!process.env.EMAIL_SERVICE,
        fileUploads: true,
        realTimeLeaderboard: true
      },
      limits: {
        maxFileSize: '4MB',
        maxUsers: 300,
        maxCTFs: 50,
        maxSubmissionsPerCTF: 1
      },
      version: '0.0.1'
    };

    res.json({ config });
  } catch (error) {
    console.error('Get system config error:', error);
    res.status(500).json({ error: 'Failed to get system configuration' });
  }
});

// Bulk user operations
router.post('/bulk/users/activate', requireAdmin, async (req, res) => {
  try {
    const { userIds } = req.body;
    
    if (!userIds || !Array.isArray(userIds)) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    const result = await User.updateMany(
      { _id: { $in: userIds } },
      { $set: { isActive: true } }
    );

    res.json({
      message: `${result.modifiedCount} users activated successfully`,
      activated: result.modifiedCount
    });
  } catch (error) {
    console.error('Bulk activate users error:', error);
    res.status(500).json({ error: 'Failed to activate users' });
  }
});

router.post('/bulk/users/deactivate', requireAdmin, async (req, res) => {
  try {
    const { userIds } = req.body;
    
    if (!userIds || !Array.isArray(userIds)) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    const result = await User.updateMany(
      { _id: { $in: userIds } },
      { $set: { isActive: false } }
    );

    res.json({
      message: `${result.modifiedCount} users deactivated successfully`,
      deactivated: result.modifiedCount
    });
  } catch (error) {
    console.error('Bulk deactivate users error:', error);
    res.status(500).json({ error: 'Failed to deactivate users' });
  }
});

// Add these routes to the adminRoutes.js file

// ==========================
// SCREENSHOT REVIEW ROUTES
// ==========================

// Get all pending submissions
router.get('/submissions/pending', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    const submissions = await Submission.find({ 
      submissionStatus: 'pending'
    })
    .populate('user', 'fullName email')
    .populate('ctf', 'title category points')
    .sort({ submittedAt: 1 }) // Oldest first
    .limit(limit * 1)
    .skip((page - 1) * limit);

    const total = await Submission.countDocuments({ 
      submissionStatus: 'pending'
    });

    res.json({
      submissions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get pending submissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all submissions with filtering
router.get('/submissions', requireAdmin, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      status = 'all',
      ctfId = 'all',
      userId = 'all',
      search = ''
    } = req.query;

    let filter = {};

    if (status !== 'all') {
      filter.submissionStatus = status;
    }

    if (ctfId !== 'all') {
      filter.ctf = ctfId;
    }

    if (userId !== 'all') {
      filter.user = userId;
    }

    // Search functionality
    if (search) {
      const submissions = await Submission.find(filter)
        .populate('user', 'fullName email')
        .populate('ctf', 'title category')
        .populate('reviewedBy', 'fullName email')
        .sort({ submittedAt: -1 });

      const filteredSubmissions = submissions.filter(submission => 
        submission.user?.fullName?.toLowerCase().includes(search.toLowerCase()) ||
        submission.user?.email?.toLowerCase().includes(search.toLowerCase()) ||
        submission.ctf?.title?.toLowerCase().includes(search.toLowerCase()) ||
        submission.flag?.toLowerCase().includes(search.toLowerCase())
      );

      const total = filteredSubmissions.length;
      const paginatedSubmissions = filteredSubmissions.slice(
        (page - 1) * limit,
        page * limit
      );

      return res.json({
        submissions: paginatedSubmissions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      });
    }

    const submissions = await Submission.find(filter)
      .populate('user', 'fullName email expertiseLevel')
      .populate('ctf', 'title category points')
      .populate('reviewedBy', 'fullName email')
      .sort({ submittedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Submission.countDocuments(filter);

    res.json({
      submissions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get all submissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get submission by ID
router.get('/submissions/:submissionId', requireAdmin, async (req, res) => {
  try {
    const { submissionId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(submissionId)) {
      return res.status(400).json({ error: 'Invalid submission ID format' });
    }

    const submission = await Submission.findById(submissionId)
      .populate('user', 'fullName email expertiseLevel')
      .populate('ctf', 'title category points difficulty')
      .populate('reviewedBy', 'fullName email');

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    res.json({
      message: 'Submission retrieved successfully',
      submission
    });
  } catch (error) {
    console.error('Get submission error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's all submissions
router.get('/users/:userId/submissions', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    const submissions = await Submission.find({ 
      user: userId
    })
    .populate('ctf', 'title category points')
    .populate('reviewedBy', 'fullName email')
    .sort({ submittedAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);


    const total = await Submission.countDocuments({ 
      user: userId
    });

    // Get user info
    const user = await User.findById(userId)
    res.json({
      user,
      submissions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get user submissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced approve submission with custom points
router.post('/submissions/:submissionId/approve', requireAdmin, [
  body('feedback').optional().trim(),
  body('points').optional().isInt({ min: 0 }).withMessage('Points must be a positive integer')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { submissionId } = req.params;
    const { feedback, points } = req.body;
    const adminId = req.admin._id;

    if (!mongoose.Types.ObjectId.isValid(submissionId)) {
      return res.status(400).json({ error: 'Invalid submission ID format' });
    }

    const submission = await Submission.findById(submissionId)
      .populate('user', 'fullName email')
      .populate('ctf', 'title points maxAttempts');

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    if (submission.submissionStatus !== 'pending') {
      return res.status(400).json({ 
        error: 'Submission has already been reviewed' 
      });
    }

    // Calculate points - use provided points or CTF default points
    const awardedPoints = points !== undefined ? parseInt(points) : submission.ctf.points;

    // Update submission
    submission.submissionStatus = 'approved';
    submission.isCorrect = true;
    submission.points = awardedPoints;
    submission.adminFeedback = feedback || 'Great job! Your submission has been approved.';
    submission.reviewedAt = new Date();
    submission.reviewedBy = adminId;

    await submission.save();

    // Update CTF participant
    const ctf = await CTF.findById(submission.ctf._id);
    if (ctf) {
      const participant = ctf.participants.find(p => 
        p.user.toString() === submission.user._id.toString()
      );
      
      if (participant) {
        participant.isCorrect = true;
        participant.pointsEarned = awardedPoints;
        participant.submittedAt = new Date();
        participant.hasPendingSubmission = false;
        
        // Update attempts if needed
        if (participant.attempts < submission.attemptNumber) {
          participant.attempts = submission.attemptNumber;
        }
      } else {
        // Add participant if not exists
        ctf.participants.push({
          user: submission.user._id,
          joinedAt: new Date(),
          submittedAt: new Date(),
          isCorrect: true,
          pointsEarned: awardedPoints,
          attempts: submission.attemptNumber || 1,
          hasPendingSubmission: false
        });
      }
      
      ctf.correctSubmissions += 1;
      await ctf.save();
    }

    // Send approval email
    try {
   await sendMail({
  email: submission.user.email,
  subject: `🎉 CTF Submission Approved - ${submission.ctf.title}`,
  message: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0;">
  <div style="background: #28a745; color: white; padding: 25px; text-align: center;">
    <h2 style="margin: 0;">🎉 Submission Approved!</h2>
  </div>
  
  <div style="padding: 30px;">
    <p style="color: #1f2937; margin-bottom: 15px;">
      Hello <strong>${submission.user.fullName}</strong>,
    </p>
    
    <p style="color: #4b5563; margin-bottom: 20px;">
      Great news! Your submission for <strong>${submission.ctf.title}</strong> has been approved.
    </p>
    
    <div style="background: #f8f9fa; padding: 20px; border-radius: 6px; margin: 20px 0; border: 1px solid #e5e7eb;">
      <h3 style="color: #28a745; margin: 0 0 15px 0; text-align: center;">Submission Details</h3>
      <table style="width: 100%;">
        <tr><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold; width: 120px;">Challenge:</td><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">${submission.ctf.title}</td></tr>
        <tr><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Points Awarded:</td><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; color: #28a745; font-weight: bold;">${awardedPoints}</td></tr>
        <tr><td style="padding: 8px 0; font-weight: bold;">Status:</td><td style="padding: 8px 0; color: #28a745; font-weight: bold;">Approved ✅</td></tr>
      </table>
    </div>

    ${feedback ? `
    <div style="background: #e7f3ff; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #007bff;">
      <p style="color: #007bff; font-weight: bold; margin: 0 0 8px 0;">Admin Feedback:</p>
      <p style="color: #1f2937; margin: 0;">${feedback}</p>
    </div>
    ` : ''}

    <p style="color: #4b5563; margin-bottom: 25px;">
      Congratulations on successfully completing this challenge! Your points have been added to your total score.
    </p>
    
    <div style="text-align: center; margin: 25px 0;">
      <a href="${process.env.FRONTEND_URL}/dashboard" 
         style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
        View Dashboard
      </a>
    </div>
  </div>
  
  <div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 12px; color: #555;">
    © ${new Date().getFullYear()} CTF Platform. All rights reserved.
  </div>
</div>
  `
});
    } catch (emailError) {
      console.error('Failed to send approval email:', emailError);
    }

    res.json({ 
      message: 'Submission approved successfully',
      submission: {
        _id: submission._id,
        submissionStatus: submission.submissionStatus,
        points: submission.points,
        reviewedAt: submission.reviewedAt
      }
    });
  } catch (error) {
    console.error('Approve submission error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reject submission
router.post('/submissions/:submissionId/reject', requireAdmin, [
  body('feedback').notEmpty().withMessage('Feedback is required for rejection')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { submissionId } = req.params;
    const { feedback } = req.body;
    const adminId = req.admin._id;

    if (!mongoose.Types.ObjectId.isValid(submissionId)) {
      return res.status(400).json({ error: 'Invalid submission ID format' });
    }

    const submission = await Submission.findById(submissionId)
      .populate('user', 'fullName email')
      .populate('ctf', 'title points activeHours schedule');

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    if (submission.submissionStatus !== 'pending') {
      return res.status(400).json({ 
        error: 'Submission has already been reviewed' 
      });
    }

    // Update submission
    submission.submissionStatus = 'rejected';
    submission.isCorrect = false;
    submission.points = 0;
    submission.adminFeedback = feedback;
    submission.reviewedAt = new Date();
    submission.reviewedBy = adminId;

    await submission.save();

    // Update CTF participant
    const ctf = await CTF.findById(submission.ctf._id);
    if (ctf) {
      ctf.updateParticipantSubmissionStatus(submission.user._id, false);
      await ctf.save();
    }

    // Check if CTF is still active for resubmission
    const canResubmit = ctf && ctf.canSubmit();

    // Send rejection email
    try {
  await sendMail({
  email: submission.user.email,
  subject: `CTF Submission Requires Attention - ${submission.ctf.title}`,
  message: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0;">
  <div style="background: #dc3545; color: white; padding: 25px; text-align: center;">
    <h2 style="margin: 0;">⚠️ Submission Requires Review</h2>
  </div>
  
  <div style="padding: 30px;">
    <p style="color: #1f2937; margin-bottom: 15px;">
      Hello <strong>${submission.user.fullName}</strong>,
    </p>
    
    <p style="color: #4b5563; margin-bottom: 20px;">
      Your submission for <strong>${submission.ctf.title}</strong> requires some attention.
    </p>
    
    <div style="background: #f8f9fa; padding: 20px; border-radius: 6px; margin: 20px 0; border: 1px solid #e5e7eb;">
      <h3 style="color: #dc3545; margin: 0 0 15px 0; text-align: center;">Submission Details</h3>
      <table style="width: 100%;">
        <tr><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold; width: 120px;">Challenge:</td><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">${submission.ctf.title}</td></tr>
        <tr><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Status:</td><td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; color: #dc3545; font-weight: bold;">Rejected</td></tr>
        <tr><td style="padding: 8px 0; font-weight: bold;">Can Resubmit:</td><td style="padding: 8px 0;">${canResubmit ? 'Yes ✅' : 'No ❌'}</td></tr>
      </table>
    </div>

    <div style="background: #fff3cd; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #ffc107;">
      <p style="color: #856404; font-weight: bold; margin: 0 0 8px 0;">Admin Feedback:</p>
      <p style="color: #1f2937; margin: 0;">${feedback}</p>
    </div>

    ${canResubmit ? `
    <div style="background: #d4edda; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #28a745;">
      <p style="color: #155724; margin: 0;">
        <strong>Good news!</strong> You can resubmit with a corrected screenshot. 
        The CTF is still active until ${new Date(submission.ctf.schedule.endDate).toLocaleString()}.
      </p>
    </div>
    
    <div style="text-align: center; margin: 25px 0;">
      <a href="${process.env.FRONTEND_URL}/ctf/${submission.ctf._id}" 
         style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
        Resubmit Solution
      </a>
    </div>
    ` : `
    <div style="background: #f8d7da; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #dc3545;">
      <p style="color: #721c24; margin: 0;">
        <strong>Note:</strong> The CTF active period has ended, so you cannot resubmit for this challenge.
      </p>
    </div>
    `}
  </div>
  
  <div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 12px; color: #555;">
    © ${new Date().getFullYear()} CTF Platform. All rights reserved.
  </div>
</div>
  `
});
    } catch (emailError) {
      console.error('Failed to send rejection email:', emailError);
      // Don't fail the request if email fails
    }

    res.json({ 
      message: 'Submission rejected successfully',
      submission: {
        _id: submission._id,
        submissionStatus: submission.submissionStatus,
        adminFeedback: submission.adminFeedback,
        reviewedAt: submission.reviewedAt,
        canResubmit: canResubmit
      }
    });
  } catch (error) {
    console.error('Reject submission error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced submission statistics with more analytics
router.get('/submissions/stats', requireAdmin, async (req, res) => {
  try {
    const { timeRange = 'all' } = req.query;
    
    let dateFilter = {};
    const now = new Date();
    
    switch (timeRange) {
      case '24h':
        dateFilter.submittedAt = { $gte: new Date(now - 24 * 60 * 60 * 1000) };
        break;
      case '7d':
        dateFilter.submittedAt = { $gte: new Date(now - 7 * 24 * 60 * 60 * 1000) };
        break;
      case '30d':
        dateFilter.submittedAt = { $gte: new Date(now - 30 * 24 * 60 * 60 * 1000) };
        break;
      // 'all' includes all submissions
    }

    const [statusStats, totalStats, dailyStats, ctfStats] = await Promise.all([
      // Status distribution
      Submission.aggregate([
        { $match: dateFilter },
        {
          $group: {
            _id: '$submissionStatus',
            count: { $sum: 1 }
          }
        }
      ]),
      
      // Total statistics
      Submission.aggregate([
        { $match: dateFilter },
        {
          $group: {
            _id: null,
            totalSubmissions: { $sum: 1 },
            pendingSubmissions: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'pending'] }, 1, 0] }
            },
            approvedSubmissions: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
            },
            rejectedSubmissions: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'rejected'] }, 1, 0] }
            },
            totalPoints: { $sum: '$points' },
            averagePoints: { $avg: '$points' }
          }
        }
      ]),
      
      // Daily submissions for last 7 days
      Submission.aggregate([
        {
          $match: {
            submittedAt: { $gte: new Date(now - 7 * 24 * 60 * 60 * 1000) }
          }
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format: '%Y-%m-%d',
                date: '$submittedAt'
              }
            },
            count: { $sum: 1 },
            approved: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
            },
            pending: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'pending'] }, 1, 0] }
            }
          }
        },
        { $sort: { _id: 1 } }
      ]),
      
      // CTF-wise statistics
      Submission.aggregate([
        { $match: dateFilter },
        {
          $lookup: {
            from: 'ctfs',
            localField: 'ctf',
            foreignField: '_id',
            as: 'ctfInfo'
          }
        },
        { $unwind: '$ctfInfo' },
        {
          $group: {
            _id: '$ctfInfo.title',
            totalSubmissions: { $sum: 1 },
            approvedSubmissions: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
            },
            averagePoints: { $avg: '$points' }
          }
        },
        { $sort: { totalSubmissions: -1 } },
        { $limit: 10 }
      ])
    ]);

    const stats = {
      statusDistribution: statusStats,
      totals: totalStats[0] || {
        totalSubmissions: 0,
        pendingSubmissions: 0,
        approvedSubmissions: 0,
        rejectedSubmissions: 0,
        totalPoints: 0,
        averagePoints: 0
      },
      dailyTrends: dailyStats,
      topCTFs: ctfStats,
      timeRange: timeRange
    };

    res.json(stats);
  } catch (error) {
    console.error('Get submission stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// In adminRoutes.js - Add this route for screenshot review
router.get('/submissions/:submissionId/screenshot', requireAdmin, async (req, res) => {
  try {
    const { submissionId } = req.params;

    const submission = await Submission.findById(submissionId)
      .populate('user', 'fullName email')
      .populate('ctf', 'title category points')
      .populate('reviewedBy', 'fullName email');

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    res.json({
      message: 'Submission retrieved successfully',
      submission: {
        _id: submission._id,
        user: submission.user,
        ctf: submission.ctf,
        flag: submission.flag,
        screenshot: submission.screenshot,
        submissionStatus: submission.submissionStatus,
        adminFeedback: submission.adminFeedback,
        submittedAt: submission.submittedAt,
        reviewedAt: submission.reviewedAt,
        reviewedBy: submission.reviewedBy,
        attemptNumber: submission.attemptNumber,
        isCorrect: submission.isCorrect,
        points: submission.points
      }
    });
  } catch (error) {
    console.error('Get submission screenshot error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


// ==========================
// SUBMISSION ANALYTICS ROUTES
// ==========================

// Get comprehensive submission analytics
router.get('/analytics/submissions', requireAdmin, async (req, res) => {
  try {
    const { timeRange = '7d' } = req.query;
    
    // Calculate date range
    let startDate;
    const endDate = new Date();
    
    switch (timeRange) {
      case '24h':
        startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    }

    // Get submission statistics
    const [statusStats, dailyTrend, categoryStats, userStats] = await Promise.all([
      // Status distribution
      Submission.aggregate([
        {
          $match: {
            submittedAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $group: {
            _id: '$submissionStatus',
            count: { $sum: 1 }
          }
        }
      ]),
      
      // Daily trend for the last 7 days
      Submission.aggregate([
        {
          $match: {
            submittedAt: { 
              $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
              $lte: endDate
            }
          }
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format: '%Y-%m-%d',
                date: '$submittedAt'
              }
            },
            total: { $sum: 1 },
            approved: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
            },
            pending: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'pending'] }, 1, 0] }
            },
            rejected: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'rejected'] }, 1, 0] }
            }
          }
        },
        { $sort: { _id: 1 } }
      ]),
      
      // Category performance
      Submission.aggregate([
        {
          $match: {
            submittedAt: { $gte: startDate, $lte: endDate },
            submissionStatus: 'approved'
          }
        },
        {
          $lookup: {
            from: 'ctfs',
            localField: 'ctf',
            foreignField: '_id',
            as: 'ctfInfo'
          }
        },
        { $unwind: '$ctfInfo' },
        {
          $group: {
            _id: '$ctfInfo.category',
            totalSolved: { $sum: 1 },
            totalPoints: { $sum: '$points' },
            averagePoints: { $avg: '$points' }
          }
        },
        { $sort: { totalSolved: -1 } }
      ]),
      
      // User submission statistics
      Submission.aggregate([
        {
          $match: {
            submittedAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $group: {
            _id: '$user',
            totalSubmissions: { $sum: 1 },
            approvedSubmissions: {
              $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
            },
            totalPoints: { $sum: '$points' }
          }
        },
        {
          $lookup: {
            from: 'users',
            localField: '_id',
            foreignField: '_id',
            as: 'userInfo'
          }
        },
        { $unwind: '$userInfo' },
        {
          $project: {
            'userInfo.password': 0,
            'userInfo.loginHistory': 0
          }
        },
        { $sort: { totalPoints: -1 } },
        { $limit: 10 }
      ])
    ]);

    // Get total counts
    const totalStats = await Submission.aggregate([
      {
        $match: {
          submittedAt: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: null,
          totalSubmissions: { $sum: 1 },
          approvedSubmissions: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
          },
          pendingSubmissions: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'pending'] }, 1, 0] }
          },
          rejectedSubmissions: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'rejected'] }, 1, 0] }
          },
          totalPoints: { $sum: '$points' },
          averagePoints: { $avg: '$points' }
        }
      }
    ]);

    // Get recent submissions for activity feed
    const recentSubmissions = await Submission.find({
      submittedAt: { $gte: startDate, $lte: endDate }
    })
    .populate('user', 'fullName email')
    .populate('ctf', 'title category points')
    .populate('reviewedBy', 'fullName email')
    .sort({ submittedAt: -1 })
    .limit(20)
    .select('user ctf submissionStatus points submittedAt reviewedAt reviewedBy');

    const analytics = {
      totals: totalStats[0] || {
        totalSubmissions: 0,
        approvedSubmissions: 0,
        pendingSubmissions: 0,
        rejectedSubmissions: 0,
        totalPoints: 0,
        averagePoints: 0
      },
      statusDistribution: statusStats,
      dailyTrend: dailyTrend,
      categoryPerformance: categoryStats,
      topUsers: userStats,
      recentSubmissions: recentSubmissions,
      timeRange: {
        start: startDate,
        end: endDate,
        label: timeRange
      }
    };

    res.json({
      message: 'Submission analytics retrieved successfully',
      analytics
    });
  } catch (error) {
    console.error('Get submission analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch submission analytics' });
  }
});

router.get('/submissions/stats', requireAdmin, async (req, res) => {
  try {
    const { timeRange = '7d' } = req.query;
    
    console.log('📊 Fetching submission stats for timeRange:', timeRange);
    
    // Validate timeRange parameter
    const validTimeRanges = ['24h', '7d', '30d', 'all'];
    if (!validTimeRanges.includes(timeRange)) {
      return res.status(400).json({ 
        error: 'Invalid timeRange parameter', 
        validValues: validTimeRanges 
      });
    }
    
    let dateFilter = {};
    const now = new Date();
    
    // Set date filter based on timeRange
    if (timeRange !== 'all') {
      let milliseconds;
      switch (timeRange) {
        case '24h':
          milliseconds = 24 * 60 * 60 * 1000;
          break;
        case '7d':
          milliseconds = 7 * 24 * 60 * 60 * 1000;
          break;
        case '30d':
          milliseconds = 30 * 24 * 60 * 60 * 1000;
          break;
        default:
          milliseconds = 7 * 24 * 60 * 60 * 1000;
      }
      dateFilter.submittedAt = { $gte: new Date(now - milliseconds) };
    }

    console.log('📅 Date filter:', dateFilter);

    // Get status distribution
    const statusDistribution = await Submission.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: '$submissionStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    console.log('📈 Status distribution:', statusDistribution);

    // Get total statistics
    const totals = await Submission.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: null,
          totalSubmissions: { $sum: 1 },
          pendingSubmissions: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'pending'] }, 1, 0] }
          },
          approvedSubmissions: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
          },
          rejectedSubmissions: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'rejected'] }, 1, 0] }
          },
          totalPoints: { $sum: '$points' },
          averagePoints: { $avg: '$points' }
        }
      }
    ]);

    console.log('📊 Totals:', totals);

    // Get daily trends for the last 7 days
    const dailyTrends = await Submission.aggregate([
      {
        $match: {
          submittedAt: { $gte: new Date(now - 7 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$submittedAt',
              timezone: 'Asia/Kolkata'
            }
          },
          count: { $sum: 1 },
          approved: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'approved'] }, 1, 0] }
          },
          pending: {
            $sum: { $cond: [{ $eq: ['$submissionStatus', 'pending'] }, 1, 0] }
          }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    console.log('📅 Daily trends:', dailyTrends);

    const result = {
      statusDistribution: statusDistribution,
      totals: totals[0] || {
        totalSubmissions: 0,
        pendingSubmissions: 0,
        approvedSubmissions: 0,
        rejectedSubmissions: 0,
        totalPoints: 0,
        averagePoints: 0
      },
      dailyTrends: dailyTrends,
      timeRange: timeRange
    };

    console.log('✅ Final result:', result);

    res.json(result);
    
  } catch (error) {
    console.error('❌ Get submission stats error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch submission statistics',
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});
module.exports = { router, requireAdmin };