const express = require('express');
const mongoose = require('mongoose');
const User = require('../models/User');
const CTF = require('../models/CTF');
const Submission = require('../models/Submission');
const { requireAuth } = require('./authRoutes');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// ==========================
// IST TIME HELPER FUNCTIONS
// ==========================

const getCurrentIST = () => {
  const now = new Date();
  const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC+5:30
  return new Date(now.getTime() + istOffset);
};

const getCurrentISTString = () => {
  const istTime = getCurrentIST();
  return `${istTime.getUTCHours().toString().padStart(2, '0')}:${istTime.getUTCMinutes().toString().padStart(2, '0')}`;
};

// Helper to convert date to IST string
const toIST = (date) => {
  if (!date) return '';
  return new Date(date).toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    hour12: false,
  });
};

// ==========================
// USER PROFILE ROUTES
// ==========================

// Get user profile
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -passwordResetToken -passwordResetExpires -loginHistory');
    
    res.json({
      message: 'Profile retrieved successfully',
      user,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user profile
router.patch('/profile', requireAuth, [
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

    const allowedUpdates = [
      'fullName', 'contactNumber', 'specialization', 
      'expertiseLevel'
    ];
    
    const updates = {};
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    // Handle email separately (needs uniqueness check)
    if (req.body.email && req.body.email !== req.user.email) {
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already taken' });
      }
      updates.email = req.body.email;
    }

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password -passwordResetToken -passwordResetExpires -loginHistory');

    res.json({
      message: 'Profile updated successfully',
      user,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('Update profile error:', error);
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ error: 'Validation failed', details: errors });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user dashboard data with IST
router.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get basic user info
    const user = await User.findById(userId)
      .select('fullName email role specialization expertiseLevel lastLogin');

    // Get CTF participation stats
    const ctfStats = await CTF.aggregate([
      { $match: { 'participants.user': userId } },
      {
        $group: {
          _id: null,
          totalJoined: { $sum: 1 },
          solvedCTFs: {
            $sum: {
              $cond: [
                { 
                  $gt: [
                    {
                      $size: {
                        $filter: {
                          input: '$participants',
                          as: 'p',
                          cond: {
                            $and: [
                              { $eq: ['$$p.user', userId] },
                              { $eq: ['$$p.isCorrect', true] }
                            ]
                          }
                        }
                      }
                    },
                    0
                  ]
                }, 1, 0
              ]
            }
          }
        }
      }
    ]);

    // Get submission stats
    const submissionStats = await Submission.aggregate([
      { $match: { user: userId } },
      {
        $group: {
          _id: null,
          totalSubmissions: { $sum: 1 },
          correctSubmissions: { $sum: { $cond: ['$isCorrect', 1, 0] } },
          totalPoints: { $sum: '$points' }
        }
      }
    ]);

    // Get recent submissions with IST timestamps
    const recentSubmissions = await Submission.find({ user: userId })
      .populate('ctf', 'title category points')
      .sort({ submittedAt: -1 })
      .limit(5)
      .select('isCorrect points submittedAt ctf submissionStatus')
      .then(submissions => 
        submissions.map(sub => ({
          ...sub.toObject(),
          submittedAtIST: toIST(sub.submittedAt)
        }))
      );

    // Get active CTFs with IST status
    const activeCTFs = await CTF.find({
      'participants.user': userId,
      status: 'active',
      isVisible: true
    })
    .select('title description category points difficulty activeHours schedule status')
    .limit(3)
    .then(ctfs => 
      ctfs.map(ctf => ({
        ...ctf.toObject(),
        isCurrentlyActive: ctf.isCurrentlyActive(),
        canSubmit: ctf.canSubmit(),
        currentIST: getCurrentISTString()
      }))
    );

    const dashboardData = {
      user,
      stats: {
        ctfs: ctfStats[0] || { totalJoined: 0, solvedCTFs: 0 },
        submissions: submissionStats[0] || { totalSubmissions: 0, correctSubmissions: 0, totalPoints: 0 },
        accuracy: submissionStats[0] ? 
          Math.round((submissionStats[0].correctSubmissions / submissionStats[0].totalSubmissions) * 100) : 0
      },
      recentActivity: recentSubmissions,
      activeCTFs
    };

    res.json({
      message: 'Dashboard data retrieved successfully',
      ...dashboardData,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('Get dashboard error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// USER CTF ROUTES WITH IST
// ==========================

// Get user's joined CTFs with IST status
router.get('/ctfs/joined', requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status = 'all' } = req.query;
    
    let filter = {
      'participants.user': req.user._id,
      isVisible: true
    };

    // Use CTF status instead of date filtering for IST compatibility
    if (status !== 'all') {
      filter.status = status;
    }

    const ctfs = await CTF.find(filter)
      .populate('createdBy', 'fullName email')
      .select('-flag')
      .sort({ 'schedule.startDate': 1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .then(ctfs => 
        ctfs.map(ctf => ({
          ...ctf.toObject(),
          isCurrentlyActive: ctf.isCurrentlyActive(),
          canSubmit: ctf.canSubmit(),
          currentIST: getCurrentISTString()
        }))
      );

    const total = await CTF.countDocuments(filter);

    res.json({
      ctfs,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata',
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get joined CTFs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's submission for a specific CTF with IST info
router.get('/ctfs/:id/my-submission', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    console.log('🔍 Fetching submission for CTF:', id, 'User:', userId);

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const submission = await Submission.findOne({
      user: userId,
      ctf: id
    })
    .populate('ctf', 'title category points activeHours schedule')
    .populate('reviewedBy', 'fullName email')
    .sort({ submittedAt: -1 });

    if (!submission) {
      return res.status(404).json({ 
        error: 'No submission found for this CTF',
        submission: null,
        currentIST: getCurrentISTString()
      });
    }

    // Enhance submission with IST info
    const enhancedSubmission = {
      ...submission.toObject(),
      submittedAtIST: toIST(submission.submittedAt),
      reviewedAtIST: submission.reviewedAt ? toIST(submission.reviewedAt) : null
    };

    console.log('✅ Submission found:', submission._id);
    res.json({ 
      message: 'Submission found',
      submission: enhancedSubmission,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('❌ Get user submission error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's CTF progress with IST validation
router.get('/ctfs/:id/progress', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id)
      .select('title description category points difficulty status activeHours schedule participants rules');

    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Find user's participation
    const participation = ctf.participants.find(
      p => p.user.toString() === userId.toString()
    );

    // Get user's submissions for this CTF with IST timestamps
    const submissions = await Submission.find({
      user: userId,
      ctf: id
    })
    .sort({ submittedAt: -1 })
    .then(subs => 
      subs.map(sub => ({
        ...sub.toObject(),
        submittedAtIST: toIST(sub.submittedAt),
        reviewedAtIST: sub.reviewedAt ? toIST(sub.reviewedAt) : null
      }))
    );

    const progress = {
      hasJoined: !!participation,
      isSolved: participation ? participation.isCorrect : false,
      pointsEarned: participation ? participation.pointsEarned : 0,
      attempts: participation ? participation.attempts : 0,
      maxAttempts: ctf.maxAttempts,
      submittedAt: participation ? participation.submittedAt : null,
      submittedAtIST: participation ? toIST(participation.submittedAt) : null,
      submissions: submissions,
      canSubmit: ctf.canSubmit() && (!participation?.isCorrect || ctf.rules.allowMultipleSubmissions)
    };

    res.json({
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        description: ctf.description,
        category: ctf.category,
        points: ctf.points,
        difficulty: ctf.difficulty,
        status: ctf.status,
        activeHours: ctf.activeHours,
        schedule: {
          ...ctf.schedule.toObject(),
          startDateIST: toIST(ctf.schedule.startDate),
          endDateIST: toIST(ctf.schedule.endDate)
        },
        isCurrentlyActive: ctf.isCurrentlyActive(),
        canSubmit: ctf.canSubmit(),
        rules: ctf.rules
      },
      progress,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('Get CTF progress error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's submission history with IST timestamps
router.get('/my-submissions', requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20, ctfId } = req.query;

    let filter = { user: req.user._id };
    if (ctfId) {
      filter.ctf = ctfId;
    }

    const submissions = await Submission.find(filter)
      .populate('ctf', 'title category points')
      .sort({ submittedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select('-ipAddress -userAgent')
      .then(subs => 
        subs.map(sub => ({
          ...sub.toObject(),
          submittedAtIST: toIST(sub.submittedAt),
          reviewedAtIST: sub.reviewedAt ? toIST(sub.reviewedAt) : null
        }))
      );

    const total = await Submission.countDocuments(filter);

    res.json({
      submissions,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata',
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get submissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// USER STATISTICS ROUTES WITH IST
// ==========================

// Get user's statistics
router.get('/stats', requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;

    // Total submissions and correct submissions
    const submissionStats = await Submission.aggregate([
      { $match: { user: userId } },
      {
        $group: {
          _id: null,
          totalSubmissions: { $sum: 1 },
          correctSubmissions: { 
            $sum: { $cond: ['$isCorrect', 1, 0] }
          },
          totalPoints: { $sum: '$points' }
        }
      }
    ]);

    // CTFs participated in
    const ctfStats = await CTF.aggregate([
      { $match: { 'participants.user': userId } },
      {
        $group: {
          _id: null,
          totalCTFs: { $sum: 1 },
          solvedCTFs: {
            $sum: {
              $cond: [
                { 
                  $gt: [
                    {
                      $size: {
                        $filter: {
                          input: '$participants',
                          as: 'p',
                          cond: {
                            $and: [
                              { $eq: ['$$p.user', userId] },
                              { $eq: ['$$p.isCorrect', true] }
                            ]
                          }
                        }
                      }
                    },
                    0
                  ]
                }, 1, 0
              ]
            }
          }
        }
      }
    ]);

    // Category-wise performance
    const categoryStats = await Submission.aggregate([
      { 
        $match: { 
          user: userId,
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
      { $unwind: '$ctfInfo' },
      {
        $group: {
          _id: '$ctfInfo.category',
          totalSolved: { $sum: 1 },
          totalPoints: { $sum: '$points' }
        }
      },
      { $sort: { totalPoints: -1 } }
    ]);

    // Recent activity with IST timestamps
    const recentActivity = await Submission.find({ user: userId })
      .populate('ctf', 'title category')
      .sort({ submittedAt: -1 })
      .limit(10)
      .select('isCorrect points submittedAt ctf submissionStatus')
      .then(subs => 
        subs.map(sub => ({
          ...sub.toObject(),
          submittedAtIST: toIST(sub.submittedAt)
        }))
      );

    const stats = {
      submissions: submissionStats[0] || { 
        totalSubmissions: 0, 
        correctSubmissions: 0, 
        totalPoints: 0 
      },
      ctfs: ctfStats[0] || { totalCTFs: 0, solvedCTFs: 0 },
      categories: categoryStats,
      recentActivity,
      accuracy: submissionStats[0] ? 
        Math.round((submissionStats[0].correctSubmissions / submissionStats[0].totalSubmissions) * 100) : 0
    };

    res.json({ 
      stats,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('Get user stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user ranking
router.get('/ranking', requireAuth, async (req, res) => {
  try {
    const userId = req.user._id;

    // Get global ranking
    const globalRanking = await Submission.aggregate([
      {
        $match: { isCorrect: true }
      },
      {
        $group: {
          _id: '$user',
          totalPoints: { $sum: '$points' },
          solveCount: { $sum: 1 },
          lastSolve: { $max: '$submittedAt' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          'user.password': 0,
          'user.loginHistory': 0,
          'user.passwordResetToken': 0,
          'user.passwordResetExpires': 0
        }
      },
      {
        $sort: {
          totalPoints: -1,
          lastSolve: 1
        }
      }
    ]);

    // Find user's position
    const userRank = globalRanking.findIndex(rank => 
      rank._id.toString() === userId.toString()
    );

    const userRanking = userRank !== -1 ? {
      position: userRank + 1,
      totalPoints: globalRanking[userRank].totalPoints,
      solveCount: globalRanking[userRank].solveCount,
      totalParticipants: globalRanking.length,
      lastSolveIST: toIST(globalRanking[userRank].lastSolve)
    } : {
      position: globalRanking.length + 1,
      totalPoints: 0,
      solveCount: 0,
      totalParticipants: globalRanking.length,
      lastSolveIST: null
    };

    // Get top 10 users with IST timestamps
    const topUsers = globalRanking.slice(0, 10).map(user => ({
      ...user,
      lastSolveIST: toIST(user.lastSolve)
    }));

    res.json({
      userRanking,
      topUsers,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('Get user ranking error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// CTF JOIN AND SUBMISSION ROUTES WITH IST VALIDATION
// ==========================

// Join CTF with IST validation
router.post('/ctfs/:id/join', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    // Enhanced validation with IST logging
    console.log('🔍 Join CTF Validation (IST):', {
      title: ctf.title,
      isVisible: ctf.isVisible,
      isPublished: ctf.isPublished,
      status: ctf.status,
      isCurrentlyActive: ctf.isCurrentlyActive(),
      currentIST: getCurrentISTString(),
      activeHours: ctf.activeHours,
      timezone: 'Asia/Kolkata'
    });

    // Enhanced validation for joining
    if (!ctf.isVisible || !ctf.isPublished) {
      return res.status(403).json({ 
        error: 'CTF is not available for joining',
        details: {
          isVisible: ctf.isVisible,
          isPublished: ctf.isPublished,
          currentIST: getCurrentISTString()
        }
      });
    }

    // Check if CTF is currently active using IST
    const isActive = ctf.isCurrentlyActive();
    if (!isActive) {
      return res.status(403).json({ 
        error: `CTF is only active between ${ctf.activeHours.startTime} - ${ctf.activeHours.endTime} IST. Current time: ${getCurrentISTString()} IST`,
        details: {
          activeHours: ctf.activeHours,
          currentIST: getCurrentISTString(),
          backendStatus: ctf.status,
          isCurrentlyActive: ctf.isCurrentlyActive(),
          timezone: 'Asia/Kolkata'
        }
      });
    }

    // Check if already joined
    const alreadyJoined = ctf.participants.some(
      participant => participant.user.toString() === userId.toString()
    );

    if (alreadyJoined) {
      return res.status(400).json({ 
        error: 'Already joined this CTF',
        details: {
          ctfId: ctf._id,
          ctfTitle: ctf.title
        }
      });
    }

    // Add participant to CTF
    ctf.addParticipant(userId);
    await ctf.save();

    console.log('✅ CTF Joined Successfully (IST):', {
      ctfId: ctf._id,
      ctfTitle: ctf.title,
      userId: userId,
      joinedAt: new Date().toISOString(),
      currentIST: getCurrentISTString(),
      activeHours: ctf.activeHours
    });

    res.json({ 
      message: 'Successfully joined CTF', 
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: ctf.status,
        isCurrentlyActive: isActive,
        activeHours: ctf.activeHours,
        timezone: 'Asia/Kolkata',
        joinedAt: new Date()
      },
      timeInfo: {
        currentIST: getCurrentISTString(),
        serverTime: new Date().toISOString(),
        timezone: 'Asia/Kolkata'
      }
    });
  } catch (error) {
    console.error('❌ Join CTF error:', error);
    
    // Get current IST time for error logging
    const currentIST = getCurrentISTString();
    
    console.error('❌ Join CTF Error Details (IST):', {
      error: error.message,
      currentIST: currentIST,
      timestamp: new Date().toISOString()
    });

    if (error.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }
    
    res.status(500).json({ 
      error: 'Server error while joining CTF',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Check if user has joined CTF
router.get('/ctfs/:id/joined', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid CTF ID format' });
    }

    const ctf = await CTF.findById(id);
    if (!ctf) {
      return res.status(404).json({ error: 'CTF not found' });
    }

    const hasJoined = ctf.participants.some(
      participant => participant.user.toString() === userId.toString()
    );

    res.json({ 
      joined: hasJoined,
      ctf: {
        _id: ctf._id,
        title: ctf.title,
        status: ctf.status,
        isCurrentlyActive: ctf.isCurrentlyActive(),
        canSubmit: ctf.canSubmit()
      },
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata'
    });
  } catch (error) {
    console.error('Check CTF join status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// ENHANCED CTF LISTING WITH IST
// ==========================

// Get available CTFs for user with IST status
router.get('/ctfs/available', requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, category = 'all', search = '' } = req.query;
    
    let filter = { 
      isVisible: true, 
      isPublished: true 
    };
    
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
      .select('-flag -participants')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .then(ctfs => 
        ctfs.map(ctf => ({
          ...ctf.toObject(),
          isCurrentlyActive: ctf.isCurrentlyActive(),
          canSubmit: ctf.canSubmit(),
          currentIST: getCurrentISTString()
        }))
      );

    const total = await CTF.countDocuments(filter);

    // Get unique categories for filter
    const categories = await CTF.distinct('category', { isVisible: true });

    res.json({
      ctfs,
      categories,
      currentIST: getCurrentISTString(),
      timezone: 'Asia/Kolkata',
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get available CTFs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;