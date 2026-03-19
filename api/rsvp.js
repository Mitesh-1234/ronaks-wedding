const { z } = require('zod');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const admin = require('firebase-admin');

// Setup DOMPurify
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// Initialize Firebase Admin (only once, reused across warm invocations)
if (!admin.apps.length) {
    if (process.env.FIREBASE_PROJECT_ID) {
        admin.initializeApp({
            credential: admin.credential.cert({
                projectId: process.env.FIREBASE_PROJECT_ID,
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
            })
        });
    } else {
        console.warn('⚠️ Firebase Admin not initialized. Set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY in Vercel environment variables.');
    }
}

const db = admin.apps.length ? admin.firestore() : null;

// Zod validation schema
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

export default async function handler(req, res) {
    // Only allow POST
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    try {
        if (!db) {
            return res.status(500).json({ error: 'Database not initialized. Check Vercel environment variables.' });
        }

        // Validate input
        const validatedData = rsvpSchema.parse(req.body);

        // Sanitize message
        const sanitizedMessage = validatedData.message ? purify.sanitize(validatedData.message) : '';

        // Generate RSVP ID
        const rsvp_id = 'RSVP-' + Date.now() + '-' + Math.floor(Math.random() * 1000);

        const safeData = {
            ...validatedData,
            message: sanitizedMessage,
            rsvp_id,
            created_at: new Date().toISOString()
        };

        // Save to Firestore
        await db.collection('guests').add(safeData);

        return res.status(200).json({
            success: true,
            message: 'RSVP successfully saved',
            rsvp_id
        });

    } catch (error) {
        console.error('RSVP Error:', error);

        if (error instanceof z.ZodError) {
            return res.status(400).json({
                error: 'Invalid input data',
                details: error.errors
            });
        }

        return res.status(500).json({ error: 'Server error while processing RSVP.' });
    }
}
