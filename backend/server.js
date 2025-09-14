// =================================================================
// --- 1. IMPORTS & INITIAL SETUP ---
// =================================================================
// We begin by importing all the necessary libraries (packages) that our server needs to function.

const express = require('express');        // The core framework for building our web server and APIs.
const cors = require('cors');              // Middleware to enable Cross-Origin Resource Sharing, allowing our frontend to communicate with this backend.
const bcrypt = require('bcryptjs');        // A library for securely "hashing" passwords. We never store plain text passwords, only their irreversible hashes.
const mongoose = require('mongoose');      // An Object Data Modeling (ODM) library that makes interacting with our MongoDB database simple and structured.
const nodemailer = require('nodemailer');  // A module for sending emails from Node.js, which we use for sending OTPs.
const jwt = require('jsonwebtoken');       // A library to implement JSON Web Tokens (JWT) for secure user authentication after they log in.
const Razorpay = require('razorpay');      // NEW: The official Razorpay library for payment processing.
const crypto = require('crypto');          // NEW: A built-in Node.js module used to securely verify payment signatures.

// --- Key Configuration Variables ---
// These are central settings for our application.

// This is a secret key used to sign our JWTs. It MUST be stored securely as an environment variable in production.
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-is-long-and-random';

// The port on which our server will listen. Render provides this as an environment variable, or we default to 3000 for local development.
const PORT = process.env.PORT || 3000;

// --- Initialize the Express App & Razorpay ---
const app = express();
// We create a new Razorpay instance using the secret keys that we will store on Render.
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});


// =================================================================
// --- 2. MIDDLEWARE & DATABASE CONNECTION ---
// =================================================================
// Middleware are functions that run for every incoming request. They are essential for preparing the request before it reaches our specific endpoints.

app.use(cors()); // Enables CORS for all routes, allowing any frontend to make requests to this server.
app.use(express.json({ limit: '10mb' })); // This parses incoming request bodies into JSON format and sets a 10mb limit for large data like base64 images.

// --- Connect to MongoDB ---
// This is one of the most critical parts of the server setup.

// We get the database connection string from an environment variable named MONGO_URI. This is what Render and MongoDB Atlas will provide.
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sipeDB';

// We log the URI we are attempting to connect to. This is very helpful for debugging deployment issues.
console.log(`Attempting to connect to MongoDB...`);

// Mongoose attempts to establish a persistent connection to the database.
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Successfully connected to MongoDB!')) // This message confirms our database is connected and ready.
    .catch(err => console.error('❌ Database connection error:', err)); // If this message appears, there's a problem with the database connection.


// =================================================================
// --- 3. DATABASE SCHEMAS & MODELS (MongoDB Version) ---
// =================================================================
// Schemas define the structure, data types, and rules for the documents we will store in our database collections.
// Models are the tools we use in our code to create, read, update, and delete these documents.

// --- UPDATED studentSchema with membership fields ---
const studentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    contactNumber: { type: String },
    institution: { type: String, required: true },
    exam: { type: String, required: true },
    password: { type: String, required: true },
    isPremiumMember: { type: Boolean, default: false }, // NEW: Tracks if the student has paid for the Master Chapter.
    razorpayPaymentId: { type: String },                 // NEW: Stores the successful payment ID for records.
});
const Student = mongoose.model('Student', studentSchema);

const institutionSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, required: true },
    state: { type: String, required: true },
    city: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    contactPerson: { type: String, required: true },
    website: { type: String },
    password: { type: String, required: true },
    status: { type: String, default: 'Pending Review' }
});
const Institution = mongoose.model('Institution', institutionSchema);

const sessionSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    examType: { type: String },
    mentorName: { type: String, required: true },
    mentorPicture: { type: String },
    institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true }
});
const Session = mongoose.model('Session', sessionSchema);

const inquirySchema = new mongoose.Schema({
    userType: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    institutionName: { type: String },
    expertise: { type: String },
    message: { type: String, required: true }
});
const Inquiry = mongoose.model('Inquiry', inquirySchema);

const alumniSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    company: { type: String, required: true },
    linkedin: { type: String },
    picture: { type: String },
    institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true }
});
const Alumni = mongoose.model('Alumni', alumniSchema);

const eventSchema = new mongoose.Schema({
    title: { type: String, required: true },
    date: { type: Date, required: true },
    time: { type: String, required: true },
    description: { type: String, required: true },
    institutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Institution', required: true }
});
const Event = mongoose.model('Event', eventSchema);

const hubSubmissionSchema = new mongoose.Schema({
    helpType: { type: String, required: true },
    prototypeFile: { type: String },
    financialSupport: { type: Number },
    description: { type: String, required: true },
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true }
});
const HubSubmission = mongoose.model('HubSubmission', hubSubmissionSchema);


// =================================================================
// --- 4. HELPER FUNCTIONS (OTP & AUTH MIDDLEWARE) ---
// =================================================================
const otpStore = {};

// --- Production Email Setup ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendOtpEmail = async (email) => {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiry: Date.now() + 10 * 60 * 1000 };
    console.log(`Generated OTP for ${email}: ${otp}`);

    const mailOptions = {
        from: `"SIPE Support" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Your SIPE Verification Code',
        html: `<p>Your verification code is <b>${otp}</b>. It is valid for 10 minutes.</p>`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ OTP email sent successfully to ${email}`);
};


const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized: No token provided.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.institution = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Unauthorized: Invalid token.' });
    }
};

const studentAuthMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized: No token provided.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.student = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Unauthorized: Invalid token.' });
    }
};


// =================================================================
// --- 5. API ENDPOINTS (ROUTES) ---
// =================================================================

// --- Public Endpoints ---
app.post('/api/contact', async (req, res) => {
    try {
        await Inquiry.create(req.body);
        res.status(201).json({ message: 'Your inquiry has been submitted successfully!' });
    } catch (error) { res.status(500).json({ message: 'Server error. Please try again later.' }); }
});

app.get('/api/institutions', async (req, res) => {
    try {
        const institutions = await Institution.find({}, 'name'); 
        res.status(200).json(institutions);
    } catch (error) { res.status(500).json({ message: 'Failed to fetch institutions.' }); }
});

app.get('/api/alumni/:institutionName', async (req, res) => {
    try {
        const institution = await Institution.findOne({ name: req.params.institutionName });
        if (!institution) return res.status(404).json([]);
        const alumni = await Alumni.find({ institutionId: institution._id });
        res.json(alumni);
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/events/:institutionName', async (req, res) => {
    try {
        const institution = await Institution.findOne({ name: req.params.institutionName });
        if (!institution) return res.status(404).json([]);
        const events = await Event.find({ institutionId: institution._id });
        res.json(events);
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// --- Student Auth ---
app.post('/api/students/send-otp', async (req, res) => {
    try {
        await sendOtpEmail(req.body.email);
        res.status(200).json({ message: 'OTP sent successfully. Please check your email.' });
    } catch (error) { res.status(500).json({ message: error.message || 'Failed to send OTP.' }); }
});

app.post('/api/students/signup', async (req, res) => {
    try {
        const { name, email, contactNumber, institution, exam, password, otp } = req.body;
        const storedOtpData = otpStore[email];
        if (!storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        if (await Student.findOne({ email })) return res.status(400).json({ message: 'User with this email already exists.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        await Student.create({ name, email, contactNumber, institution, exam, password: hashedPassword });
        delete otpStore[email];
        res.status(201).json({ message: 'User created successfully! Please log in.' });
    } catch (error) { res.status(500).json({ message: 'Server error during signup.' }); }
});

app.post('/api/students/login', async (req, res) => {
    const { email, password } = req.body;
    const student = await Student.findOne({ email });
    if (!student || !(await bcrypt.compare(password, student.password))) {
        return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const token = jwt.sign({ id: student._id, name: student.name, institution: student.institution }, JWT_SECRET, { expiresIn: '24h' });
    res.status(200).json({ message: 'Login successful!', token });
});

// --- Institution Auth ---
app.post('/api/institutions/send-otp', async (req, res) => {
    try {
        await sendOtpEmail(req.body.email);
        res.status(200).json({ message: 'OTP sent successfully.' });
    } catch (error) { res.status(500).json({ message: error.message || 'Failed to send OTP.' }); }
});

app.post('/api/institutions/signup', async (req, res) => {
    try {
        const { name, type, state, city, email, contactPerson, website, password, otp } = req.body;
        const storedOtpData = otpStore[email];
        if (!storedOtpData || Date.now() > storedOtpData.expiry || storedOtpData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        if (await Institution.findOne({ email })) return res.status(400).json({ message: 'Institution with this email already registered.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        await Institution.create({ name, type, state, city, email, contactPerson, website, password: hashedPassword });
        delete otpStore[email];
        res.status(201).json({ message: 'Registration submitted successfully!' });
    } catch (error) { res.status(500).json({ message: 'Server error during institution signup.' }); }
});

app.post('/api/institutions/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const institution = await Institution.findOne({ email });
        if (!institution || !(await bcrypt.compare(password, institution.password))) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const token = jwt.sign({ id: institution._id, name: institution.name }, JWT_SECRET, { expiresIn: '24h' });
        res.status(200).json({ message: 'Login successful!', token: token });
    } catch (error) { res.status(500).json({ message: 'Server error during institution login.' }); }
});

// --- Protected Institution Dashboard Endpoints ---
app.get('/api/institutions/profile', authMiddleware, async (req, res) => {
    try {
        const institution = await Institution.findById(req.institution.id).select('-password');
        if (!institution) return res.status(404).json({ message: 'Institution not found.' });
        res.status(200).json(institution);
    } catch (error) { res.status(500).json({ message: 'Server error fetching profile.' }); }
});

app.get('/api/institutions/student-count', authMiddleware, async (req, res) => {
    try {
        const count = await Student.countDocuments({ institution: req.institution.name });
        res.status(200).json({ count: count });
    } catch (error) { res.status(500).json({ message: 'Server error fetching student count.' }); }
});

app.get('/api/institutions/session-count', authMiddleware, async (req, res) => {
    try {
        const count = await Session.countDocuments({ institutionId: req.institution.id });
        res.status(200).json({ count });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/institutions/sessions', authMiddleware, async (req, res) => {
    try {
        const newSession = await Session.create({ ...req.body, institutionId: req.institution.id });
        res.status(201).json({ message: 'Session created successfully!', session: newSession });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/institutions/event-count', authMiddleware, async (req, res) => {
    try {
        const count = await Event.countDocuments({ institutionId: req.institution.id });
        res.json({ count });
    } catch(error) { res.status(500).json({message: 'Server Error'})}
});

app.post('/api/institutions/events', authMiddleware, async (req, res) => {
    try {
        const newEvent = await Event.create({ ...req.body, institutionId: req.institution.id });
        res.status(201).json({ message: 'Event created successfully!', event: newEvent });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/institutions/alumni-count', authMiddleware, async (req, res) => {
    try {
        const count = await Alumni.countDocuments({ institutionId: req.institution.id });
        res.json({ count });
    } catch(error) { res.status(500).json({message: 'Server Error'})}
});

app.post('/api/institutions/alumni', authMiddleware, async (req, res) => {
    try {
        const newAlumni = await Alumni.create({ ...req.body, institutionId: req.institution.id });
        res.status(201).json({ message: 'Alumnus registered successfully!', alumni: newAlumni });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});


// --- Protected Student Dashboard Endpoints ---
app.get('/api/students/profile', studentAuthMiddleware, async (req, res) => {
    const student = await Student.findById(req.student.id).select('-password');
    res.json(student);
});

app.post('/api/students/hub-submission', studentAuthMiddleware, async (req, res) => {
    const { helpType, financialSupport, description } = req.body;
    const newSubmission = await HubSubmission.create({ helpType, financialSupport, description, studentId: req.student.id });
    res.status(201).json({ message: 'Your submission was received!' });
});


// --- Razorpay Payment Endpoints (Protected) ---
app.post('/api/students/create-order', studentAuthMiddleware, async (req, res) => {
    try {
        const options = { amount: 21300, currency: "INR", receipt: `receipt_sipe_${Date.now()}` };
        const order = await razorpay.orders.create(options);
        res.json(order);
    } catch (error) {
        console.error("Razorpay order creation error:", error);
        res.status(500).send("Server error while creating payment order.");
    }
});

app.post('/api/students/verify-payment', studentAuthMiddleware, async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const generated_signature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(razorpay_order_id + "|" + razorpay_payment_id).digest('hex');

    if (generated_signature === razorpay_signature) {
        await Student.findByIdAndUpdate(req.student.id, {
            isPremiumMember: true,
            razorpayPaymentId: razorpay_payment_id,
        });
        res.status(200).json({ success: true, message: "Payment verified successfully!" });
    } else {
        res.status(400).json({ success: false, message: "Payment verification failed." });
    }
});

app.get('/api/students/premium-status', studentAuthMiddleware, async (req, res) => {
    try {
        const student = await Student.findById(req.student.id);
        res.status(200).json({ isPremium: student ? student.isPremiumMember : false });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});


// =================================================================
// --- 6. START THE SERVER ---
// =================================================================
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});