import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
const envPath = path.join(__dirname, '.env');
dotenv.config({ path: envPath });

// MongoDB Connection
const mongoUrl = process.env.MONGO_URL;
const dbName = process.env.DB_NAME;
const client = new MongoClient(mongoUrl);
let db;

// Security Configuration
const SECRET_KEY = process.env.JWT_SECRET_KEY || 'your-secret-key-change-in-production';
const ALGORITHM = 'HS256';
const ACCESS_TOKEN_EXPIRE_MINUTES = 1440; // 24 hours
const VALID_FACULTY_IDS = ['66', '107', '102', '132', '222', '319'];

// Express Setup
const app = express();
const router = express.Router();

// Middleware
app.use(express.json());
app.use(cors({
  origin: (process.env.CORS_ORIGINS || '*').split(','),
  credentials: true,
}));

// Connect to MongoDB
async function connectDB() {
  try {
    await client.connect();
    db = client.db(dbName);
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
}

// Helper Functions
function hashPassword(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
}

function verifyPassword(plainPassword, hashedPassword) {
  return bcrypt.compareSync(plainPassword, hashedPassword);
}

function createAccessToken(data) {
  const payload = { ...data };
  const token = jwt.sign(payload, SECRET_KEY, {
    algorithm: ALGORITHM,
    expiresIn: `${ACCESS_TOKEN_EXPIRE_MINUTES}m`,
  });
  return token;
}

// Authentication Middleware
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ detail: 'No token provided' });
    }

    const payload = jwt.verify(token, SECRET_KEY);
    const userId = payload.sub;

    if (!userId) {
      return res.status(401).json({ detail: 'Invalid token' });
    }

    const userDoc = await db.collection('users').findOne({ id: userId });
    if (!userDoc) {
      return res.status(401).json({ detail: 'User not found' });
    }

    req.currentUser = {
      id: userDoc.id,
      email: userDoc.email,
      name: userDoc.name,
      role: userDoc.role,
      background_image_url: userDoc.background_image_url,
      profile_image_url: userDoc.profile_image_url,
      department: userDoc.department,
      year: userDoc.year,
      section: userDoc.section,
      roll_number: userDoc.roll_number,
      employee_id: userDoc.employee_id,
      mobile_number: userDoc.mobile_number,
      created_at: userDoc.created_at,
    };
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ detail: 'Token expired' });
    }
    return res.status(401).json({ detail: 'Invalid token' });
  }
}

// Email Helper
function sendEmailTask(toEmail, subject, body) {
  const smtpEmail = process.env.SMTP_EMAIL;
  const smtpPassword = process.env.SMTP_PASSWORD;
  const smtpServer = process.env.SMTP_SERVER || 'smtp.gmail.com';
  const smtpPort = parseInt(process.env.SMTP_PORT || '587');

  if (!smtpEmail || !smtpPassword) {
    console.log(`⚠️ SMTP credentials missing. Email to ${toEmail} skipped.`);
    return;
  }

  const transporter = nodemailer.createTransport({
    host: smtpServer,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: {
      user: smtpEmail,
      pass: smtpPassword,
    },
  });

  const mailOptions = {
    from: `Smart Digital Campus <${smtpEmail}>`,
    to: toEmail,
    subject: subject,
    text: body,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(`❌ Failed to send email: ${error}`);
    } else {
      console.log(`📧 Email sent to ${toEmail}`);
    }
  });
}

// ============ OTP Endpoints ============

// Send OTP
router.post('/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ detail: 'Email is required' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await db.collection('otps').updateOne(
      { email: email },
      {
        $set: {
          otp: otp,
          created_at: new Date(),
        },
      },
      { upsert: true }
    );

    console.log(`🔐 OTP for ${email}: ${otp}`);

    const emailSubject = 'Smart Digital Campus - Verification OTP';
    const emailBody = `Your verification code is: ${otp}\n\nThis code expires in 10 minutes.`;
    sendEmailTask(email, emailSubject, emailBody);

    return res.status(200).json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Auth Endpoints ============

// Register
router.post('/auth/register', async (req, res) => {
  try {
    const {
      email,
      name,
      password,
      role,
      otp,
      background_image_url,
      profile_image_url,
      department,
      year,
      section,
      roll_number,
      employee_id,
      mobile_number,
    } = req.body;

    // Validate password length
    if (password.length < 8) {
      return res.status(400).json({ detail: 'Password must be at least 8 characters long' });
    }

    // Check if user exists
    const existingUser = await db.collection('users').findOne({ email: email });
    if (existingUser) {
      return res.status(400).json({ detail: 'Email already registered' });
    }

    // Validate employee IDs
    if (role === 'admin' && employee_id !== '9') {
      return res.status(400).json({ detail: 'Invalid employee ID' });
    }

    if (role === 'faculty' && !VALID_FACULTY_IDS.includes(employee_id)) {
      return res.status(400).json({ detail: 'Invalid employee ID' });
    }

    // Student OTP validation
    if (role === 'student') {
      if (!otp) {
        return res.status(400).json({ detail: 'OTP is required for student registration' });
      }

      const otpRecord = await db.collection('otps').findOne({ email: email });
      if (!otpRecord || otpRecord.otp !== otp) {
        return res.status(400).json({ detail: 'Invalid or expired OTP' });
      }

      await db.collection('otps').deleteOne({ email: email });
    }

    const userId = uuidv4();
    const passwordHash = hashPassword(password);
    const now = new Date();

    const userDoc = {
      id: userId,
      email,
      name,
      role,
      background_image_url: background_image_url || null,
      profile_image_url: profile_image_url || null,
      department: department || null,
      year: year || null,
      section: section || null,
      roll_number: roll_number || null,
      employee_id: employee_id || null,
      mobile_number: mobile_number || null,
      password_hash: passwordHash,
      created_at: now,
    };

    await db.collection('users').insertOne(userDoc);

    const user = { ...userDoc };
    delete user.password_hash;

    return res.status(201).json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Login
router.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ detail: 'Email and password are required' });
    }

    // Try to find user by email first
    let userDoc = await db.collection('users').findOne({ email: email });

    // If not found by email, try by roll number
    if (!userDoc) {
      userDoc = await db.collection('users').findOne({ roll_number: email });
    }

    if (!userDoc || !verifyPassword(password, userDoc.password_hash)) {
      return res.status(401).json({ detail: 'Invalid credentials' });
    }

    const user = { ...userDoc };
    delete user.password_hash;

    const token = createAccessToken({ sub: user.id, role: user.role });

    return res.status(200).json({ token, user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Current User
router.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    return res.status(200).json(req.currentUser);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Update Profile Image
router.put('/users/me/profile-image', authenticateToken, async (req, res) => {
  try {
    const { profile_image_url } = req.body;

    if (!profile_image_url) {
      return res.status(400).json({ detail: 'Profile image URL is required' });
    }

    await db.collection('users').updateOne(
      { id: req.currentUser.id },
      { $set: { profile_image_url: profile_image_url } }
    );

    const updatedUser = await db.collection('users').findOne({ id: req.currentUser.id });
    delete updatedUser.password_hash;

    return res.status(200).json(updatedUser);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Student Endpoints ============

// Get Students
router.get('/students', authenticateToken, async (req, res) => {
  try {
    if (!['faculty', 'admin'].includes(req.currentUser.role)) {
      return res.status(403).json({ detail: 'Not authorized' });
    }

    const { year, section } = req.query;
    const query = { role: 'student' };

    if (year) {
      query.year = parseInt(year);
    }
    if (section) {
      query.section = section;
    }

    const students = await db
      .collection('users')
      .find(query, { projection: { password_hash: 0, _id: 0 } })
      .sort({ roll_number: 1 })
      .toArray();

    return res.status(200).json(students);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Student Attendance
router.get('/students/:student_id/attendance', authenticateToken, async (req, res) => {
  try {
    const { student_id } = req.params;

    if (req.currentUser.role === 'student' && req.currentUser.id !== student_id) {
      return res.status(403).json({ detail: 'Not authorized' });
    }

    const records = await db
      .collection('attendance')
      .find({ student_id: student_id }, { projection: { _id: 0 } })
      .toArray();

    return res.status(200).json(records);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Student Marks
router.get('/students/:student_id/marks', authenticateToken, async (req, res) => {
  try {
    const { student_id } = req.params;

    if (req.currentUser.role === 'student' && req.currentUser.id !== student_id) {
      return res.status(403).json({ detail: 'Not authorized' });
    }

    const records = await db
      .collection('marks')
      .find({ student_id: student_id }, { projection: { _id: 0 } })
      .toArray();

    return res.status(200).json(records);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Attendance Endpoints ============

// Mark Batch Attendance
router.post('/attendance/batch', authenticateToken, async (req, res) => {
  try {
    if (req.currentUser.role !== 'faculty') {
      return res.status(403).json({ detail: 'Only faculty can mark attendance' });
    }

    const { students_status, subject, date } = req.body;

    if (!students_status || students_status.length === 0) {
      return res.status(400).json({ detail: 'No attendance records provided' });
    }

    const now = new Date();
    const recordsToInsert = students_status.map((studentStatus) => ({
      id: uuidv4(),
      student_id: studentStatus.student_id,
      student_name: studentStatus.student_name,
      subject: subject,
      date: date,
      status: studentStatus.status,
      marked_by: req.currentUser.id,
      marked_by_name: req.currentUser.name,
      created_at: now,
    }));

    await db.collection('attendance').insertMany(recordsToInsert);

    return res.status(201).json({
      message: `Attendance marked for ${recordsToInsert.length} students.`,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Mark Single Attendance
router.post('/attendance', authenticateToken, async (req, res) => {
  try {
    if (req.currentUser.role !== 'faculty') {
      return res.status(403).json({ detail: 'Only faculty can mark attendance' });
    }

    const { student_id, student_name, subject, date, status } = req.body;
    const now = new Date();

    const record = {
      id: uuidv4(),
      student_id,
      student_name,
      subject,
      date,
      status,
      marked_by: req.currentUser.id,
      marked_by_name: req.currentUser.name,
      created_at: now,
    };

    await db.collection('attendance').insertOne(record);

    return res.status(201).json(record);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get All Attendance
router.get('/attendance', authenticateToken, async (req, res) => {
  try {
    if (!['faculty', 'admin'].includes(req.currentUser.role)) {
      return res.status(403).json({ detail: 'Not authorized' });
    }

    const { date, subject, year, section } = req.query;
    const matchQuery = {};

    if (date) matchQuery.date = date;
    if (subject) matchQuery.subject = subject;

    // Simple query if no year/section filter
    if (!year && !section) {
      const records = await db
        .collection('attendance')
        .find(matchQuery, { projection: { _id: 0 } })
        .sort({ created_at: -1 })
        .limit(1000)
        .toArray();

      return res.status(200).json(records);
    }

    // Aggregation pipeline for year/section filtering
    const pipeline = [];

    if (Object.keys(matchQuery).length > 0) {
      pipeline.push({ $match: matchQuery });
    }

    pipeline.push(
      {
        $lookup: {
          from: 'users',
          localField: 'student_id',
          foreignField: 'id',
          as: 'student_info',
        },
      },
      { $unwind: '$student_info' }
    );

    const userMatchQuery = {};
    if (year) userMatchQuery['student_info.year'] = parseInt(year);
    if (section) userMatchQuery['student_info.section'] = section;

    if (Object.keys(userMatchQuery).length > 0) {
      pipeline.push({ $match: userMatchQuery });
    }

    pipeline.push(
      {
        $project: {
          _id: 0,
          id: 1,
          student_id: 1,
          student_name: 1,
          subject: 1,
          date: 1,
          status: 1,
          marked_by: 1,
          marked_by_name: 1,
          created_at: 1,
        },
      }
    );

    const records = await db.collection('attendance').aggregate(pipeline).toArray();

    return res.status(200).json(records);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Marks Endpoints ============

// Add Batch Marks
router.post('/marks/batch', authenticateToken, async (req, res) => {
  try {
    if (req.currentUser.role !== 'faculty') {
      return res.status(403).json({ detail: 'Only faculty can add marks' });
    }

    const { students_marks, subject, max_marks, exam_type } = req.body;

    if (!students_marks || students_marks.length === 0) {
      return res.status(400).json({ detail: 'No marks records provided' });
    }

    const now = new Date();
    const recordsToInsert = students_marks.map((studentMark) => ({
      id: uuidv4(),
      student_id: studentMark.student_id,
      student_name: studentMark.student_name,
      subject: subject,
      marks: studentMark.marks,
      max_marks: max_marks,
      exam_type: exam_type,
      marked_by: req.currentUser.id,
      marked_by_name: req.currentUser.name,
      created_at: now,
    }));

    await db.collection('marks').insertMany(recordsToInsert);

    return res.status(201).json({
      message: `Marks added for ${recordsToInsert.length} students.`,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Add Single Marks
router.post('/marks', authenticateToken, async (req, res) => {
  try {
    if (req.currentUser.role !== 'faculty') {
      return res.status(403).json({ detail: 'Only faculty can add marks' });
    }

    const { student_id, student_name, subject, marks, max_marks, exam_type } = req.body;
    const now = new Date();

    const record = {
      id: uuidv4(),
      student_id,
      student_name,
      subject,
      marks,
      max_marks,
      exam_type,
      marked_by: req.currentUser.id,
      marked_by_name: req.currentUser.name,
      created_at: now,
    };

    await db.collection('marks').insertOne(record);

    return res.status(201).json(record);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get All Marks
router.get('/marks', authenticateToken, async (req, res) => {
  try {
    if (!['faculty', 'admin'].includes(req.currentUser.role)) {
      return res.status(403).json({ detail: 'Not authorized' });
    }

    const { subject, exam_type, year, section } = req.query;
    const matchQuery = {};

    if (subject) matchQuery.subject = subject;
    if (exam_type) matchQuery.exam_type = exam_type;

    // Simple query if no year/section filter
    if (!year && !section) {
      const records = await db
        .collection('marks')
        .find(matchQuery, { projection: { _id: 0 } })
        .sort({ created_at: -1 })
        .limit(1000)
        .toArray();

      return res.status(200).json(records);
    }

    // Aggregation pipeline for year/section filtering
    const pipeline = [];

    if (Object.keys(matchQuery).length > 0) {
      pipeline.push({ $match: matchQuery });
    }

    pipeline.push(
      {
        $lookup: {
          from: 'users',
          localField: 'student_id',
          foreignField: 'id',
          as: 'student_info',
        },
      },
      { $unwind: '$student_info' }
    );

    const userMatchQuery = {};
    if (year) userMatchQuery['student_info.year'] = parseInt(year);
    if (section) userMatchQuery['student_info.section'] = section;

    if (Object.keys(userMatchQuery).length > 0) {
      pipeline.push({ $match: userMatchQuery });
    }

    pipeline.push(
      {
        $project: {
          _id: 0,
          id: 1,
          student_id: 1,
          student_name: 1,
          subject: 1,
          marks: 1,
          max_marks: 1,
          exam_type: 1,
          marked_by: 1,
          marked_by_name: 1,
          created_at: 1,
        },
      }
    );

    const records = await db.collection('marks').aggregate(pipeline).toArray();

    return res.status(200).json(records);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Notices Endpoints ============

// Create Notice
router.post('/notices', authenticateToken, async (req, res) => {
  try {
    if (!['faculty', 'admin'].includes(req.currentUser.role)) {
      return res.status(403).json({ detail: 'Only faculty and admin can post notices' });
    }

    const { title, content, role_target } = req.body;
    const now = new Date();

    const notice = {
      id: uuidv4(),
      title,
      content,
      posted_by: req.currentUser.id,
      posted_by_name: req.currentUser.name,
      role_target,
      created_at: now,
    };

    await db.collection('notices').insertOne(notice);

    return res.status(201).json(notice);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Notices
router.get('/notices', authenticateToken, async (req, res) => {
  try {
    const notices = await db
      .collection('notices')
      .find(
        { role_target: { $in: [req.currentUser.role] } },
        { projection: { _id: 0 } }
      )
      .sort({ created_at: -1 })
      .limit(1000)
      .toArray();

    return res.status(200).json(notices);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Requests Endpoints ============

// Create Request
router.post('/requests', authenticateToken, async (req, res) => {
  try {
    if (req.currentUser.role !== 'student') {
      return res.status(403).json({ detail: 'Only students can create requests' });
    }

    const { request_type, reason, roll_number, start_date, end_date } = req.body;
    const now = new Date();

    const request = {
      id: uuidv4(),
      student_id: req.currentUser.id,
      student_name: req.currentUser.name,
      roll_number: roll_number || req.currentUser.roll_number || null,
      request_type,
      reason,
      start_date: start_date || null,
      end_date: end_date || null,
      status: 'pending',
      approved_by: null,
      approved_by_name: null,
      admin_comment: null,
      created_at: now,
    };

    await db.collection('requests').insertOne(request);

    return res.status(201).json(request);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Requests
router.get('/requests', authenticateToken, async (req, res) => {
  try {
    const query =
      req.currentUser.role === 'student' ? { student_id: req.currentUser.id } : {};

    const requests = await db
      .collection('requests')
      .find(query, { projection: { _id: 0 } })
      .sort({ created_at: -1 })
      .limit(1000)
      .toArray();

    return res.status(200).json(requests);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Update Request
router.put('/requests/:request_id', authenticateToken, async (req, res) => {
  try {
    if (!['faculty', 'admin'].includes(req.currentUser.role)) {
      return res.status(403).json({ detail: 'Only faculty and admin can update requests' });
    }

    const { request_id } = req.params;
    const { status, admin_comment } = req.body;

    const updateDict = {
      status,
      admin_comment: admin_comment || null,
      approved_by: req.currentUser.id,
      approved_by_name: req.currentUser.name,
    };

    const result = await db.collection('requests').updateOne(
      { id: request_id },
      { $set: updateDict }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ detail: 'Request not found' });
    }

    const updatedRequest = await db.collection('requests').findOne({ id: request_id });
    delete updatedRequest._id;

    return res.status(200).json(updatedRequest);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Complaints Endpoints ============

// Submit Complaint
router.post('/complaints', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    const now = new Date();

    const complaint = {
      id: uuidv4(),
      content,
      submitted_by_role: req.currentUser.role,
      year: req.currentUser.year || null,
      section: req.currentUser.section || null,
      department: req.currentUser.department || null,
      created_at: now,
    };

    await db.collection('complaints').insertOne(complaint);

    return res.status(201).json(complaint);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Complaints
router.get('/complaints', authenticateToken, async (req, res) => {
  try {
    if (!['faculty', 'admin'].includes(req.currentUser.role)) {
      return res.status(403).json({ detail: 'Not authorized to view complaints' });
    }

    const complaints = await db
      .collection('complaints')
      .find({}, { projection: { _id: 0 } })
      .sort({ created_at: -1 })
      .limit(1000)
      .toArray();

    return res.status(200).json(complaints);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Admin Analytics ============

// Get Analytics
router.get('/admin/analytics', authenticateToken, async (req, res) => {
  try {
    if (req.currentUser.role !== 'admin') {
      return res.status(403).json({ detail: 'Only admin can access analytics' });
    }

    const totalStudents = await db.collection('users').countDocuments({ role: 'student' });
    const totalFaculty = await db.collection('users').countDocuments({ role: 'faculty' });
    const pendingRequests = await db
      .collection('requests')
      .countDocuments({ status: 'pending' });
    const totalNotices = await db.collection('notices').countDocuments({});

    // Calculate average marks per section
    const marksPipeline = [
      {
        $lookup: {
          from: 'users',
          localField: 'student_id',
          foreignField: 'id',
          as: 'student_info',
        },
      },
      { $unwind: '$student_info' },
      {
        $match: {
          'student_info.role': 'student',
          'student_info.section': { $ne: null },
          'student_info.year': { $ne: null },
        },
      },
      {
        $project: {
          section: '$student_info.section',
          year: '$student_info.year',
          percentage: {
            $cond: [
              { $eq: ['$max_marks', 0] },
              0,
              { $multiply: [{ $divide: ['$marks', '$max_marks'] }, 100] },
            ],
          },
        },
      },
      {
        $group: {
          _id: { year: '$year', section: '$section' },
          average_percentage: { $avg: '$percentage' },
        },
      },
      { $sort: { '_id.year': 1, '_id.section': 1 } },
      {
        $project: {
          _id: 0,
          year: '$_id.year',
          section: '$_id.section',
          average_percentage: { $round: ['$average_percentage', 2] },
        },
      },
    ];

    const sectionMarks = await db.collection('marks').aggregate(marksPipeline).toArray();

    return res.status(200).json({
      total_students: totalStudents,
      total_faculty: totalFaculty,
      pending_requests: pendingRequests,
      total_notices: totalNotices,
      section_marks: sectionMarks,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// ============ Users Endpoints ============

// Get All Users
router.get('/users', authenticateToken, async (req, res) => {
  try {
    if (req.currentUser.role !== 'admin') {
      return res.status(403).json({ detail: 'Only admin can access all users' });
    }

    const users = await db
      .collection('users')
      .find({}, { projection: { password_hash: 0, _id: 0 } })
      .limit(1000)
      .toArray();

    return res.status(200).json(users);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ detail: 'Internal server error' });
  }
});

// Use router with /api prefix
app.use('/api', router);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ detail: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ detail: 'Endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    await connectDB();
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await client.close();
  process.exit(0);
});

startServer();
