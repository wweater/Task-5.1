import { Instructor } from '../models/Instructor.js';
import Joi from 'joi';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================

function publicProfile(doc) {
  // A successful login is a "trophy": we deliberately return the sensitive
  // fields so a bypass clearly reveals what it compromised.
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role,
    apiKey: doc.apiKey,
    privateEmail: doc.privateEmail,
    privatePhone: doc.privatePhone
  };
}

// POST /api/instructors/login
const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
});

export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.message });
    }

    const instructor = await Instructor.findOne({ username: value.username });

    if (!instructor || !(await instructor.comparePassword(value.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
        return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}
// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // 1. Whitelist: Only accept expected string query fields
    const filter = {};
    if (typeof req.query.name === 'string') {
      filter.name = req.query.name;
    }
    if (typeof req.query.department === 'string') {
      filter.department = req.query.department;
    }

    // 2. Field Projection: Never leak secrets in search results
    const instructors = await Instructor.find(filter)
      .select('-password -apiKey -privateEmail -privatePhone')
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
// GET /api/instructors/search
