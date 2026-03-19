require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const admin = require('firebase-admin');

// Initialize Express App
const app = express();
const PORT = process.env.PORT || 3000;

// Setup DOMPurify with JSDOM
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// Initialize Firebase Admin (Backend Authentication & Database)
// The private key must handle newlines correctly from the .env file
if (process.env.FIREBASE_PROJECT_ID) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
        })
    });
} else {
    console.warn('⚠️ Firebase Admin not initialized. Please set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY in .env');
}

const db = admin.firestore ? admin.firestore() : null;

// --- 1. SECURITY MIDDLEWARE ---

// Helmet helps secure Express apps by setting various HTTP headers
// We configure Content Security Policy (CSP) to allow our required external scripts and inline logic
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'", "https://*.firebaseio.com", "wss://*.firebaseio.com", "https://*.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://*.firebaseio.com", "https://*.googleapis.com", "https://www.gstatic.com", "https://apis.google.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:", "blob:", "https://images.unsplash.com", "https://*.google.com", "https://*.googleapis.com", "https://image2url.com"],
            connectSrc: ["'self'", "https://*.googleapis.com", "https://*.firebaseio.com", "wss://*.firebaseio.com", "https://api.emailjs.com", "https://api.ipify.org", "https://cdn.jsdelivr.net"],
            frameSrc: ["'self'", "https://*.firebaseapp.com", "https://*.google.com"],
        },
    },
}));

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Serve static files (HTML, CSS, JS) from the current directory
app.use(express.static('./'));


// --- 2. RATE LIMITING ---
// Restrict to maximum 100 requests per 15 minutes per IP address
const rsvpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: { error: 'Too many RSVP requests from this IP. Please try again in 15 minutes.' }
});


// --- 3. INPUT VALIDATION (Zod Schema) ---
// Define exactly what the RSVP data should look like
const rsvpSchema = z.object({
    first_name: z.string().min(1, 'First name is required').max(50).trim(),
    last_name: z.string().min(1, 'Last name is required').max(50).trim(),
    email: z.string().email('Invalid email address').trim(),
    phone: z.string().min(10, 'Phone must be at least 10 digits').max(15).trim(),
    is_attending: z.boolean(),
    guests: z.array(z.object({
        first_name: z.string().min(1).max(50).trim(),
        last_name: z.string().min(1).max(50).trim()
    })).optional().default([]),
    days_attending: z.array(z.enum(['day1', 'day2', 'day3'])).optional().default([]),
    message: z.string().max(1000).optional()
});


// --- 4. API ROUTES ---

// Submit RSVP Endpoint
app.post('/api/rsvp', rsvpLimiter, async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ error: 'Database connection not initialized. Please configure server.' });
        }

        // Validate Input using Zod
        const validatedData = rsvpSchema.parse(req.body);

        // Sanitize Message Field using DOMPurify (Prevent XSS/HTML Injection)
        const sanitizedMessage = validatedData.message ? purify.sanitize(validatedData.message) : '';

        // Generate ID and Timestamp securely on the backend
        const rsvp_id = 'RSVP-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
        
        // Prepare safe data for Firestore
        const safeData = {
            ...validatedData,
            message: sanitizedMessage, // Replace with sanitized version
            rsvp_id: rsvp_id,
            created_at: new Date().toISOString()
        };

        // Save to Database
        await db.collection('guests').add(safeData);

        // Return success response to frontend
        return res.status(200).json({ 
            success: true, 
            message: 'RSVP successfully saved',
            rsvp_id: rsvp_id
        });

    } catch (error) {
        console.error('RSVP Submission Error:', error);
        
        // Handle Zod Validation Errors
        if (error instanceof z.ZodError) {
            return res.status(400).json({ 
                error: 'Invalid input data', 
                details: error.errors 
            });
        }

        // Generic Server Error
        return res.status(500).json({ error: 'Server error while processing RSVP.' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Serving static files and API at /api/rsvp`);
});
