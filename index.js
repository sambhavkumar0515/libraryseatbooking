/**
 * MASTER DEVELOPMENT FILE — SHIVANGI DIGITAL LIBRARY
 * Contains Backend Express Server, MongoDB Schemas, Security Middleware, API Routes,
 * and completely embedded Vanilla JS/CSS/HTML for both Public and Admin applications.
 */

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

// ==========================================
// 1. ENVIRONMENT & CONFIGURATION
// ==========================================
const app = express();
app.use(express.json({ limit: '1mb' }));

// We disable strict CSP to allow our single-file inline scripts and styles to execute cleanly.
app.use(helmet({ contentSecurityPolicy: false }));

const adminConfig = JSON.parse(fs.readFileSync(path.join(__dirname, 'admin.json'), 'utf-8'));

// Rate limiters
const publicLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { success: false, message: "Too many requests" } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { success: false, message: "Too many login attempts" } });

// ==========================================
// 2. MONGODB CONNECTION MANAGEMENT
// ==========================================
let cachedDb = null;
async function connectDB() {
    if (cachedDb) return cachedDb;
    if (!process.env.MONGODB_URI) {
        console.error("CRITICAL: MONGODB_URI is missing.");
        return null;
    }
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000
        });
        cachedDb = conn;
        await initializeInventory();
        return conn;
    } catch (error) {
        console.error("MongoDB Connection Error:", error);
        return null;
    }
}

// ==========================================
// 3. MONGOOSE SCHEMAS & MODELS
// ==========================================
const seatSchema = new mongoose.Schema({
    seatNumber: { type: Number, required: true, unique: true, min: 1, max: adminConfig.totalSeats },
    rowName: { type: String, required: true },
    isBlocked: { type: Boolean, default: false },
    blockReason: { type: String, default: "" }
}, { timestamps: true });

const bookingSchema = new mongoose.Schema({
    bookingReference: { type: String, required: true, unique: true },
    studentName: { type: String, required: true, trim: true },
    mobileNumber: { type: String, required: true, match: /^[6-9]\d{9}$/ },
    seatNumber: { type: Number, required: true, min: 1, max: adminConfig.totalSeats },
    batch: { type: String, required: true, enum: ['day', 'night'] },
    bookingDate: { type: Date, default: Date.now },
    status: { type: String, enum: ['reserved', 'cancelled', 'released'], default: 'reserved' },
    cancelledAt: { type: Date }
}, { timestamps: true });

// Crucial: Partial unique compound index prevents double active reservations for same seat + batch
bookingSchema.index(
    { seatNumber: 1, batch: 1 },
    { unique: true, partialFilterExpression: { status: 'reserved' } }
);

const Seat = mongoose.models.Seat || mongoose.model('Seat', seatSchema);
const Booking = mongoose.models.Booking || mongoose.model('Booking', bookingSchema);

// ==========================================
// 4. INVENTORY INITIALIZATION
// ==========================================
async function initializeInventory() {
    const count = await Seat.countDocuments();
    if (count === adminConfig.totalSeats) return;
    
    const seatsToInsert = [];
    adminConfig.layout.rows.forEach(row => {
        for (let i = row.startSeat; i <= row.endSeat; i++) {
            seatsToInsert.push({
                seatNumber: i,
                rowName: row.name,
                isBlocked: false
            });
        }
    });

    for (const seat of seatsToInsert) {
        await Seat.updateOne(
            { seatNumber: seat.seatNumber },
            { $setOnInsert: seat },
            { upsert: true }
        );
    }
}

// ==========================================
// 5. SECURITY & AUTH MIDDLEWARE
// ==========================================
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: "Unauthorized: Missing token" });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.ADMIN_JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token" });
    }
};

// Ensure DB is connected for every API route
app.use('/api', async (req, res, next) => {
    const db = await connectDB();
    if (!db) return res.status(503).json({ success: false, message: "Database temporarily unavailable." });
    next();
});

// ==========================================
// 6. PUBLIC API ROUTES
// ==========================================
app.get('/api/health', (req, res) => res.json({ success: true, message: "System operational" }));

app.get('/api/config', (req, res) => {
    res.json({ success: true, data: adminConfig });
});

app.get('/api/seats', publicLimiter, async (req, res) => {
    try {
        const { batch } = req.query;
        if (!['day', 'night'].includes(batch)) {
            return res.status(400).json({ success: false, message: "Invalid batch selection" });
        }

        const seats = await Seat.find().sort({ seatNumber: 1 }).lean();
        const activeBookings = await Booking.find({ batch, status: 'reserved' }).lean();

        const bookedSeatNumbers = new Set(activeBookings.map(b => b.seatNumber));
        
        const availability = seats.map(seat => ({
            seatNumber: seat.seatNumber,
            rowName: seat.rowName,
            isBlocked: seat.isBlocked,
            isReserved: bookedSeatNumbers.has(seat.seatNumber)
        }));

        res.json({ success: true, data: availability });
    } catch (error) {
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

app.post('/api/bookings', publicLimiter, async (req, res) => {
    try {
        const { studentName, mobileNumber, seatNumber, batch } = req.body;
        
        if (!studentName || studentName.trim().length === 0) return res.status(400).json({ success: false, message: "Student name is required" });
        if (!/^[6-9]\d{9}$/.test(mobileNumber)) return res.status(400).json({ success: false, message: "Valid 10-digit Indian mobile number is required" });
        if (!['day', 'night'].includes(batch)) return res.status(400).json({ success: false, message: "Invalid batch" });
        if (seatNumber < 1 || seatNumber > adminConfig.totalSeats) return res.status(400).json({ success: false, message: "Invalid seat number" });

        // Check if physical seat is blocked
        const seat = await Seat.findOne({ seatNumber });
        if (!seat) return res.status(404).json({ success: false, message: "Seat not found" });
        if (seat.isBlocked) return res.status(400).json({ success: false, message: "Seat is blocked by administration" });

        const bookingReference = 'SDL-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Date.now().toString().slice(-4);

        const newBooking = new Booking({
            bookingReference,
            studentName: studentName.trim(),
            mobileNumber,
            seatNumber,
            batch,
            status: 'reserved'
        });

        await newBooking.save(); // Relies on MongoDB unique partial index to prevent duplicates securely
        
        res.json({ success: true, message: "Seat reserved successfully", data: {
            bookingReference, studentName: newBooking.studentName, seatNumber, batch, date: newBooking.bookingDate
        }});
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({ success: false, message: "Seat has just been reserved by another student. Please select another seat." });
        }
        res.status(500).json({ success: false, message: "Internal server error during booking" });
    }
});

app.get('/api/bookings/:reference', publicLimiter, async (req, res) => {
    try {
        const booking = await Booking.findOne({ bookingReference: req.params.reference }).lean();
        if (!booking) return res.status(404).json({ success: false, message: "Booking not found" });
        
        // Mask mobile number for public response
        const maskedMobile = booking.mobileNumber.substring(0, 2) + '******' + booking.mobileNumber.substring(8);
        res.json({ success: true, data: { ...booking, mobileNumber: maskedMobile } });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error retrieving booking" });
    }
});

// ==========================================
// 7. ADMIN API ROUTES
// ==========================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD_HASH || !process.env.ADMIN_JWT_SECRET) {
        return res.status(500).json({ success: false, message: "Server misconfiguration: Admin credentials not set" });
    }

    if (username !== process.env.ADMIN_USERNAME) {
        return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    if (!isMatch) {
        return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign({ admin: username }, process.env.ADMIN_JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, data: { token } });
});

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
    try {
        const totalPhysical = adminConfig.totalSeats;
        const blockedSeats = await Seat.countDocuments({ isBlocked: true });
        
        const activeDay = await Booking.countDocuments({ batch: 'day', status: 'reserved' });
        const activeNight = await Booking.countDocuments({ batch: 'night', status: 'reserved' });
        const totalCancelled = await Booking.countDocuments({ status: { $in: ['cancelled', 'released'] } });

        res.json({
            success: true,
            data: {
                totalPhysical,
                blockedSeats,
                activeDay,
                availableDay: totalPhysical - blockedSeats - activeDay,
                activeNight,
                availableNight: totalPhysical - blockedSeats - activeNight,
                totalActive: activeDay + activeNight,
                totalCancelled
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error loading dashboard statistics" });
    }
});

app.get('/api/admin/bookings', authenticateAdmin, async (req, res) => {
    try {
        // Simple search/filter implementation
        const { search, batch, status, limit = 50, page = 1 } = req.query;
        let query = {};
        
        if (batch) query.batch = batch;
        if (status) query.status = status;
        
        if (search) {
            const isNumber = !isNaN(search);
            query.$or = [
                { studentName: { $regex: search, $options: 'i' } },
                { bookingReference: { $regex: search, $options: 'i' } },
                { mobileNumber: { $regex: search, $options: 'i' } }
            ];
            if (isNumber && search.length < 3) {
                query.$or.push({ seatNumber: parseInt(search) });
            }
        }

        const skip = (page - 1) * limit;
        const bookings = await Booking.find(query).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit)).lean();
        const total = await Booking.countDocuments(query);
        
        res.json({ success: true, data: { bookings, total, pages: Math.ceil(total / limit) } });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error fetching bookings" });
    }
});

app.post('/api/admin/bookings/:id/release', authenticateAdmin, async (req, res) => {
    try {
        const booking = await Booking.findByIdAndUpdate(
            req.params.id,
            { status: 'released', cancelledAt: new Date() },
            { new: true }
        );
        if (!booking) return res.status(404).json({ success: false, message: "Booking not found" });
        res.json({ success: true, message: "Reservation released successfully" });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error releasing booking" });
    }
});

app.post('/api/admin/seats/:seatNumber/block', authenticateAdmin, async (req, res) => {
    try {
        const { block } = req.body;
        const seat = await Seat.findOneAndUpdate(
            { seatNumber: req.params.seatNumber },
            { isBlocked: block },
            { new: true }
        );
        res.json({ success: true, message: block ? "Seat blocked" : "Seat unblocked", data: seat });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error modifying seat status" });
    }
});

// ==========================================
// 8. CLAYMORPHISM CSS SYSTEM (Embedded)
// ==========================================
const clayCss = `
:root {
    --primary: #7866E8;
    --primary-hover: #5A48C4;
    --secondary: #00D2D3;
    --bg-color: #F7F4FF;
    --surface: #FFFFFF;
    --text-main: #2D3436;
    --text-muted: #636E72;
    --success: #00B894;
    --error: #FF7675;
    --card-radius: 24px;
    --btn-radius: 16px;
    --seat-radius: 12px;
    --clay-shadow-out: 8px 8px 16px #E0DBF0, -8px -8px 16px #FFFFFF;
    --clay-shadow-in: inset 6px 6px 12px #E0DBF0, inset -6px -6px 12px #FFFFFF;
    --clay-shadow-hover: 10px 10px 20px #E0DBF0, -10px -10px 20px #FFFFFF;
    --font-stack: 'Inter', system-ui, -apple-system, sans-serif;
    --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
}

@media (prefers-reduced-motion: reduce) {
    * { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font-stack); background-color: var(--bg-color); color: var(--text-main); line-height: 1.6; overflow-x: hidden; }

.clay-nav { padding: 1.2rem 2rem; background: var(--surface); box-shadow: var(--clay-shadow-out); border-radius: 0 0 24px 24px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; margin-bottom: 2rem;}
.clay-nav .logo { font-size: 1.5rem; font-weight: 800; color: var(--primary); display: flex; align-items: center; gap: 8px; text-decoration: none;}
.clay-nav-links { display: flex; gap: 20px; }
.clay-nav-links a { text-decoration: none; color: var(--text-muted); font-weight: 600; transition: var(--transition); }
.clay-nav-links a:hover { color: var(--primary); }

.container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
.hero { text-align: center; margin: 4rem 0; animation: fadeInUp 0.8s ease; }
.hero h1 { font-size: 3rem; font-weight: 800; color: var(--primary); margin-bottom: 1rem; }
.hero p { font-size: 1.2rem; color: var(--text-muted); max-width: 600px; margin: 0 auto 2rem auto; }

.clay-card { background: var(--surface); border-radius: var(--card-radius); box-shadow: var(--clay-shadow-out); padding: 2rem; transition: var(--transition); margin-bottom: 2rem;}
.clay-card:hover { box-shadow: var(--clay-shadow-hover); transform: translateY(-3px); }

.clay-btn { background: var(--primary); color: white; border: none; padding: 12px 28px; border-radius: var(--btn-radius); font-size: 1rem; font-weight: 600; cursor: pointer; box-shadow: var(--clay-shadow-out); transition: var(--transition); display: inline-flex; justify-content: center; align-items: center; gap: 8px; text-decoration: none;}
.clay-btn:hover:not(:disabled) { background: var(--primary-hover); transform: translateY(-2px); }
.clay-btn:active:not(:disabled) { box-shadow: var(--clay-shadow-in); transform: translateY(1px); }
.clay-btn:disabled { background: #B2BEC3; cursor: not-allowed; box-shadow: none; }
.clay-btn.secondary { background: var(--surface); color: var(--primary); }

.batch-selector { display: flex; gap: 2rem; justify-content: center; margin: 3rem 0; flex-wrap: wrap;}
.batch-card { flex: 1; min-width: 280px; text-align: center; cursor: pointer; border: 3px solid transparent; }
.batch-card.active { border-color: var(--primary); box-shadow: var(--clay-shadow-in); }
.batch-card h2 { font-size: 1.5rem; margin-bottom: 0.5rem; }
.batch-card .icon { font-size: 3rem; margin-bottom: 1rem; }

.library-layout { display: flex; flex-direction: column; align-items: center; background: var(--surface); border-radius: var(--card-radius); padding: 3rem 2rem; box-shadow: var(--clay-shadow-in); position: relative; margin: 3rem 0; border: 8px solid #E0DBF0; overflow-x: auto; min-height: 400px;}
.library-doors { display: flex; justify-content: space-between; width: 100%; position: absolute; top: 50%; transform: translateY(-50%); pointer-events: none; padding: 0 10px;}
.door { background: #DFE6E9; padding: 20px 10px; border-radius: 8px; font-weight: bold; color: #2D3436; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; box-shadow: var(--clay-shadow-out); pointer-events: auto;}

.row-container { display: flex; justify-content: center; gap: 10px; margin-bottom: 2rem; flex-wrap: wrap; width: 100%; max-width: 900px;}
.row-label { width: 100%; text-align: center; font-size: 0.9rem; font-weight: bold; color: var(--text-muted); margin-bottom: 10px; text-transform: uppercase;}

.seat { width: 45px; height: 45px; border-radius: var(--seat-radius); display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 0.9rem; cursor: pointer; box-shadow: var(--clay-shadow-out); transition: var(--transition); background: var(--surface); user-select: none; position: relative;}
.seat:hover:not(.unavailable):not(.reserved):not(.blocked) { transform: scale(1.1); z-index: 10; }
.seat.available { background: #E8F6EF; color: var(--success); }
.seat.selected { background: var(--primary); color: white; box-shadow: var(--clay-shadow-in); transform: scale(1.1); z-index: 10;}
.seat.reserved { background: #FFEAA7; color: #D63031; cursor: not-allowed; opacity: 0.8; box-shadow: inset 2px 2px 5px rgba(0,0,0,0.05); }
.seat.blocked { background: #DFE6E9; color: #636E72; cursor: not-allowed; text-decoration: line-through; }

.legend { display: flex; gap: 15px; justify-content: center; margin-top: 2rem; flex-wrap: wrap; }
.legend-item { display: flex; align-items: center; gap: 8px; font-size: 0.9rem; font-weight: 600; }
.legend-box { width: 20px; height: 20px; border-radius: 6px; box-shadow: var(--clay-shadow-out); }

.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(247, 244, 255, 0.8); backdrop-filter: blur(5px); z-index: 1000; display: flex; justify-content: center; align-items: center; opacity: 0; pointer-events: none; transition: var(--transition); }
.modal-overlay.active { opacity: 1; pointer-events: auto; }
.modal-content { max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto; transform: translateY(20px); transition: var(--transition); }
.modal-overlay.active .modal-content { transform: translateY(0); }

.form-group { margin-bottom: 1.5rem; text-align: left; }
.form-group label { display: block; font-weight: 600; margin-bottom: 0.5rem; color: var(--text-main); }
.form-control { width: 100%; padding: 12px 16px; border-radius: 12px; border: none; background: var(--bg-color); box-shadow: var(--clay-shadow-in); font-family: var(--font-stack); font-size: 1rem; color: var(--text-main); outline: none; transition: var(--transition); }
.form-control:focus { box-shadow: inset 8px 8px 16px #E0DBF0, inset -8px -8px 16px #FFFFFF, 0 0 0 2px var(--primary); }
.form-control:read-only { opacity: 0.7; cursor: not-allowed; }

.summary-card { background: var(--bg-color); border-radius: 16px; padding: 15px; margin-bottom: 20px; box-shadow: var(--clay-shadow-in); display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.summary-item { display: flex; flex-direction: column; }
.summary-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; font-weight: bold; }
.summary-value { font-size: 1.1rem; font-weight: 800; color: var(--primary); }

.toast { position: fixed; bottom: 20px; right: 20px; padding: 15px 25px; border-radius: 12px; background: var(--surface); box-shadow: var(--clay-shadow-hover); font-weight: 600; transform: translateY(100px); opacity: 0; transition: var(--transition); z-index: 9999; }
.toast.show { transform: translateY(0); opacity: 1; }
.toast.success { border-left: 5px solid var(--success); }
.toast.error { border-left: 5px solid var(--error); }

.loader { border: 4px solid var(--bg-color); border-top: 4px solid var(--primary); border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 2rem auto; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
@keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

/* Admin specifics */
.admin-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 2rem;}
.stat-card { text-align: center; }
.stat-card .value { font-size: 2.5rem; font-weight: 800; color: var(--primary); margin: 10px 0; }

.data-table-wrapper { overflow-x: auto; background: var(--surface); border-radius: var(--card-radius); box-shadow: var(--clay-shadow-out); padding: 1rem;}
.data-table { width: 100%; border-collapse: collapse; min-width: 600px; }
.data-table th, .data-table td { padding: 12px 15px; text-align: left; border-bottom: 2px solid var(--bg-color); }
.data-table th { font-weight: 700; color: var(--text-muted); text-transform: uppercase; font-size: 0.85rem; }
.data-table tbody tr:hover { background-color: var(--bg-color); }
.badge { padding: 5px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
.badge.reserved { background: #E8F6EF; color: var(--success); }
.badge.cancelled { background: #FFEEEE; color: var(--error); }
.badge.released { background: #DFE6E9; color: var(--text-muted); }

@media print {
    body { background: white; }
    .clay-nav, .hero, .clay-btn:not(.print-btn), footer, .batch-selector { display: none !important; }
    .clay-card { box-shadow: none; border: 1px solid #ccc; }
    .print-btn { display: none !important; }
}
@media (max-width: 768px) {
    .hero h1 { font-size: 2rem; }
    .row-container { width: 100%; }
    .library-layout { padding: 2rem 1rem; border-width: 4px; }
    .library-doors { display: none; }
}
`;

// ==========================================
// 9. PUBLIC FRONTEND HTML/JS INJECTION
// ==========================================
const renderPublicUI = () => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${adminConfig.libraryName}</title>
    <style>${clayCss}</style>
</head>
<body>
    <nav class="clay-nav">
        <a href="/" class="logo">📚 ${adminConfig.libraryName}</a>
        <div class="clay-nav-links">
            <a href="/">Home</a>
            <a href="/admin">Admin Login</a>
        </div>
    </nav>

    <div class="container">
        <header class="hero">
            <h1>Your Study Space, Your Way.</h1>
            <p>Find and reserve your preferred study seat. Choose your batch, select an available seat, and confirm your reservation securely.</p>
            <button class="clay-btn" onclick="scrollToBatches()">Reserve Your Seat</button>
            <div style="margin-top: 2rem; display: inline-block;" class="clay-card">
                <h3 style="color: var(--primary);">Total Physical Seats</h3>
                <h1 style="font-size: 3rem;">${adminConfig.totalSeats}</h1>
            </div>
        </header>

        <section id="batches" class="batch-selector">
            ${adminConfig.batches.map(b => `
                <div class="clay-card batch-card" id="batch-card-${b.id}" onclick="selectBatch('${b.id}')">
                    <div class="icon">${b.id === 'day' ? '☀️' : '🌙'}</div>
                    <h2>${b.label}</h2>
                    <p>${b.timing}</p>
                    <button class="clay-btn secondary" style="margin-top: 1rem;">Select</button>
                </div>
            `).join('')}
        </section>

        <section id="seat-map-section" style="display: none; animation: fadeInUp 0.5s ease;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2>Select Your Seat</h2>
                <button class="clay-btn secondary" onclick="loadSeats()">🔄 Refresh</button>
            </div>
            
            <div class="library-layout" id="library-layout">
                <div class="library-doors">
                    <div class="door">🚪 Entry (${adminConfig.layout.entry})</div>
                    <div class="door">Exit (${adminConfig.layout.exit}) 🚪</div>
                </div>
                <div id="seat-grid-container" style="width: 100%;">
                    <!-- Populated by JS -->
                </div>
            </div>

            <div class="legend">
                <div class="legend-item"><div class="legend-box seat available"></div> Available</div>
                <div class="legend-item"><div class="legend-box seat selected"></div> Selected</div>
                <div class="legend-item"><div class="legend-box seat reserved"></div> Reserved</div>
                <div class="legend-item"><div class="legend-box seat blocked"></div> Blocked</div>
            </div>

            <div id="selection-panel" class="clay-card" style="margin-top: 2rem; text-align: center; display: none;">
                <h3>Seat <span id="lbl-selected-seat" style="color: var(--primary); font-size: 1.5rem;">-</span> Selected</h3>
                <p style="margin-bottom: 1rem;">Batch: <strong id="lbl-selected-batch">-</strong></p>
                <button class="clay-btn" onclick="openBookingForm()">Continue to Booking</button>
            </div>
        </section>
    </div>

    <!-- Booking Modal -->
    <div class="modal-overlay" id="booking-modal">
        <div class="clay-card modal-content">
            <h2 style="margin-bottom: 1.5rem; color: var(--primary);">Confirm Reservation</h2>
            <div class="summary-card">
                <div class="summary-item"><span class="summary-label">Seat</span><span class="summary-value" id="form-seat">-</span></div>
                <div class="summary-item"><span class="summary-label">Batch</span><span class="summary-value" id="form-batch">-</span></div>
            </div>
            <form id="booking-form" onsubmit="submitBooking(event)">
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" id="student-name" class="form-control" required placeholder="Enter your full name">
                </div>
                <div class="form-group">
                    <label>Mobile Number</label>
                    <input type="tel" id="mobile-number" class="form-control" required pattern="^[6-9]\\d{9}$" placeholder="10-digit mobile number" title="Valid Indian Mobile Number">
                </div>
                <div style="margin-top: 1rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 10px;">
                    <input type="checkbox" id="terms" required style="width: 18px; height: 18px;">
                    <label for="terms" style="font-size: 0.9rem; color: var(--text-muted);">I agree to library rules and reserve this seat.</label>
                </div>
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="clay-btn secondary" onclick="closeModal('booking-modal')">Back</button>
                    <button type="submit" class="clay-btn" id="btn-confirm">Confirm Reservation</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Success Modal -->
    <div class="modal-overlay" id="success-modal">
        <div class="clay-card modal-content" style="text-align: center;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">✅</div>
            <h2 style="color: var(--success); margin-bottom: 0.5rem;">Booking Confirmed!</h2>
            <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Your seat has been reserved successfully.</p>
            
            <div class="summary-card" style="text-align: left; background: var(--surface);">
                <div class="summary-item"><span class="summary-label">Reference ID</span><span class="summary-value" id="succ-ref">-</span></div>
                <div class="summary-item"><span class="summary-label">Date</span><span class="summary-value" id="succ-date">-</span></div>
                <div class="summary-item"><span class="summary-label">Name</span><span class="summary-value" id="succ-name">-</span></div>
                <div class="summary-item"><span class="summary-label">Seat & Batch</span><span class="summary-value"><span id="succ-seat"></span> (<span id="succ-batch"></span>)</span></div>
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: center; margin-top: 2rem;">
                <button class="clay-btn secondary" onclick="window.print()">🖨️ Print Receipt</button>
                <button class="clay-btn" onclick="finishBooking()">Return Home</button>
            </div>
        </div>
    </div>

    <div class="toast" id="toast"></div>

    <footer style="text-align: center; padding: 3rem 0 1rem 0; color: var(--text-muted); font-size: 0.9rem;">
        <p>&copy; ${new Date().getFullYear()} ${adminConfig.libraryName} - Online Seat Reservation System.</p>
    </footer>

    <script>
        const config = ${JSON.stringify(adminConfig)};
        let activeBatch = null;
        let selectedSeat = null;
        let currentSeatsData = [];

        function showToast(msg, type='success') {
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.className = 'toast show ' + type;
            setTimeout(() => t.className = 'toast', 3000);
        }

        function scrollToBatches() {
            document.getElementById('batches').scrollIntoView({ behavior: 'smooth' });
        }

        function selectBatch(batchId) {
            activeBatch = batchId;
            selectedSeat = null;
            document.querySelectorAll('.batch-card').forEach(el => el.classList.remove('active'));
            document.getElementById('batch-card-' + batchId).classList.add('active');
            document.getElementById('seat-map-section').style.display = 'block';
            document.getElementById('selection-panel').style.display = 'none';
            document.getElementById('library-layout').scrollIntoView({ behavior: 'smooth', block: 'center' });
            loadSeats();
        }

        async function loadSeats() {
            if (!activeBatch) return;
            const container = document.getElementById('seat-grid-container');
            container.innerHTML = '<div class="loader"></div>';
            
            try {
                const res = await fetch('/api/seats?batch=' + activeBatch);
                const json = await res.json();
                if (!json.success) throw new Error(json.message);
                currentSeatsData = json.data;
                renderSeatMap();
            } catch (err) {
                showToast("Failed to load seats. " + err.message, "error");
                container.innerHTML = '<p style="text-align:center;color:red;">Error loading layout</p>';
            }
        }

        function renderSeatMap() {
            const container = document.getElementById('seat-grid-container');
            container.innerHTML = '';

            config.layout.rows.forEach(row => {
                const rowDiv = document.createElement('div');
                rowDiv.className = 'row-container';
                rowDiv.innerHTML = \`<div class="row-label">\${row.label}</div>\`;
                
                for (let i = row.startSeat; i <= row.endSeat; i++) {
                    const seatData = currentSeatsData.find(s => s.seatNumber === i);
                    if (!seatData) continue;
                    
                    const btn = document.createElement('div');
                    let stateClass = 'available';
                    if (seatData.isBlocked) stateClass = 'blocked';
                    else if (seatData.isReserved) stateClass = 'reserved';
                    
                    if (selectedSeat === i) stateClass = 'selected';

                    btn.className = \`seat \${stateClass}\`;
                    btn.textContent = i;
                    
                    if (stateClass === 'available' || stateClass === 'selected') {
                        btn.onclick = () => toggleSeat(i);
                    } else if (stateClass === 'reserved') {
                        btn.title = "Already reserved for " + activeBatch + " batch";
                    }
                    
                    rowDiv.appendChild(btn);
                }
                container.appendChild(rowDiv);
            });
        }

        function toggleSeat(seatNum) {
            if (selectedSeat === seatNum) {
                selectedSeat = null; // deselect
                document.getElementById('selection-panel').style.display = 'none';
            } else {
                selectedSeat = seatNum;
                document.getElementById('lbl-selected-seat').textContent = seatNum;
                document.getElementById('lbl-selected-batch').textContent = activeBatch.toUpperCase();
                document.getElementById('selection-panel').style.display = 'block';
            }
            renderSeatMap();
        }

        function openBookingForm() {
            if (!selectedSeat || !activeBatch) return;
            document.getElementById('form-seat').textContent = selectedSeat;
            document.getElementById('form-batch').textContent = activeBatch.toUpperCase();
            document.getElementById('student-name').value = '';
            document.getElementById('mobile-number').value = '';
            document.getElementById('terms').checked = false;
            document.getElementById('booking-modal').classList.add('active');
        }

        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        async function submitBooking(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-confirm');
            btn.disabled = true;
            btn.textContent = "Processing...";

            const payload = {
                studentName: document.getElementById('student-name').value,
                mobileNumber: document.getElementById('mobile-number').value,
                seatNumber: selectedSeat,
                batch: activeBatch
            };

            try {
                const res = await fetch('/api/bookings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const json = await res.json();
                
                if (json.success) {
                    closeModal('booking-modal');
                    document.getElementById('succ-ref').textContent = json.data.bookingReference;
                    document.getElementById('succ-name').textContent = json.data.studentName;
                    document.getElementById('succ-seat').textContent = json.data.seatNumber;
                    document.getElementById('succ-batch').textContent = json.data.batch.toUpperCase();
                    document.getElementById('succ-date').textContent = new Date(json.data.date).toLocaleDateString();
                    document.getElementById('success-modal').classList.add('active');
                } else {
                    showToast(json.message, "error");
                    if (json.message.includes("reserved by another")) {
                        closeModal('booking-modal');
                        selectedSeat = null;
                        document.getElementById('selection-panel').style.display = 'none';
                        loadSeats();
                    }
                }
            } catch (err) {
                showToast("Network error. Try again.", "error");
            } finally {
                btn.disabled = false;
                btn.textContent = "Confirm Reservation";
            }
        }

        function finishBooking() {
            closeModal('success-modal');
            selectedSeat = null;
            document.getElementById('selection-panel').style.display = 'none';
            loadSeats();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    </script>
</body>
</html>
`;

// ==========================================
// 10. ADMIN FRONTEND HTML/JS INJECTION
// ==========================================
const renderAdminUI = () => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - ${adminConfig.libraryName}</title>
    <style>${clayCss}</style>
</head>
<body>
    <nav class="clay-nav">
        <a href="/admin" class="logo">⚙️ Admin Control</a>
        <div class="clay-nav-links">
            <a href="/" target="_blank">Public View</a>
            <a href="#" id="logout-btn" style="display:none;" onclick="logout()">Logout</a>
        </div>
    </nav>

    <div class="container" id="login-view">
        <div class="clay-card" style="max-width: 400px; margin: 4rem auto; text-align: center;">
            <h2 style="color: var(--primary); margin-bottom: 2rem;">Secure Login</h2>
            <form id="login-form" onsubmit="login(event)">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="username" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <div style="position:relative;">
                        <input type="password" id="password" class="form-control" required>
                        <button type="button" onclick="togglePassword()" style="position:absolute; right:10px; top:12px; background:none; border:none; cursor:pointer;">👁️</button>
                    </div>
                </div>
                <button type="submit" class="clay-btn" style="width: 100%; margin-top: 1rem;" id="btn-login">Sign In</button>
            </form>
        </div>
    </div>

    <div class="container" id="dashboard-view" style="display:none;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 2rem;">
            <h2>Dashboard Overview</h2>
            <button class="clay-btn secondary" onclick="loadDashboard()">🔄 Refresh Data</button>
        </div>

        <div class="admin-grid" id="stats-container">
            <!-- Stats populated by JS -->
        </div>

        <div class="clay-card">
            <h3 style="margin-bottom: 1.5rem;">Booking Management</h3>
            <div style="display:flex; gap:10px; margin-bottom: 1.5rem; flex-wrap: wrap;">
                <input type="text" id="search-input" class="form-control" placeholder="Search Name, Ref, Mobile..." style="flex:1; min-width:200px;">
                <select id="filter-batch" class="form-control" style="width:auto;">
                    <option value="">All Batches</option>
                    <option value="day">Day</option>
                    <option value="night">Night</option>
                </select>
                <select id="filter-status" class="form-control" style="width:auto;">
                    <option value="">All Statuses</option>
                    <option value="reserved" selected>Reserved</option>
                    <option value="released">Released/Cancelled</option>
                </select>
                <button class="clay-btn" onclick="loadBookings()">Search</button>
            </div>

            <div class="data-table-wrapper">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Ref / Date</th>
                            <th>Student</th>
                            <th>Seat & Batch</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="bookings-tbody">
                        <tr><td colspan="5" style="text-align:center;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="clay-card">
            <h3>Physical Seat Admin Map</h3>
            <p style="color:var(--text-muted); margin-bottom:1rem;">Click a seat to manually Block/Unblock it for all batches.</p>
            <div class="library-layout">
                <div id="admin-seat-grid" style="width:100%;"></div>
            </div>
        </div>
    </div>

    <div class="toast" id="toast"></div>

    <script>
        const config = ${JSON.stringify(adminConfig)};
        let token = localStorage.getItem('sdl_admin_token');

        function togglePassword() {
            const p = document.getElementById('password');
            p.type = p.type === 'password' ? 'text' : 'password';
        }

        function showToast(msg, type='success') {
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.className = 'toast show ' + type;
            setTimeout(() => t.className = 'toast', 3000);
        }

        function authFetch(url, options = {}) {
            options.headers = { ...options.headers, 'Authorization': 'Bearer ' + token };
            return fetch(url, options).then(res => {
                if(res.status === 401) { logout(); throw new Error("Session expired"); }
                return res;
            });
        }

        async function login(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-login');
            btn.textContent = 'Authenticating...';
            btn.disabled = true;

            try {
                const res = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value
                    })
                });
                const json = await res.json();
                if (json.success) {
                    token = json.data.token;
                    localStorage.setItem('sdl_admin_token', token);
                    initDashboard();
                } else {
                    showToast(json.message, 'error');
                }
            } catch (err) {
                showToast("Network error", 'error');
            } finally {
                btn.textContent = 'Sign In';
                btn.disabled = false;
            }
        }

        function logout() {
            token = null;
            localStorage.removeItem('sdl_admin_token');
            document.getElementById('login-view').style.display = 'block';
            document.getElementById('dashboard-view').style.display = 'none';
            document.getElementById('logout-btn').style.display = 'none';
        }

        function initDashboard() {
            if (!token) return;
            document.getElementById('login-view').style.display = 'none';
            document.getElementById('dashboard-view').style.display = 'block';
            document.getElementById('logout-btn').style.display = 'block';
            loadDashboard();
            loadBookings();
            loadAdminSeatMap();
        }

        async function loadDashboard() {
            try {
                const res = await authFetch('/api/admin/dashboard');
                const json = await res.json();
                if(!json.success) throw new Error(json.message);
                
                const d = json.data;
                document.getElementById('stats-container').innerHTML = \`
                    <div class="clay-card stat-card"><div class="summary-label">Total / Blocked</div><div class="value">\${d.totalPhysical} / \${d.blockedSeats}</div></div>
                    <div class="clay-card stat-card"><div class="summary-label">Day Reserved / Avail</div><div class="value" style="color:#F39C12;">\${d.activeDay} / \${d.availableDay}</div></div>
                    <div class="clay-card stat-card"><div class="summary-label">Night Reserved / Avail</div><div class="value" style="color:#9B59B6;">\${d.activeNight} / \${d.availableNight}</div></div>
                    <div class="clay-card stat-card"><div class="summary-label">Total Active Bookings</div><div class="value" style="color:var(--success);">\${d.totalActive}</div></div>
                \`;
            } catch (err) {
                showToast(err.message, 'error');
            }
        }

        async function loadBookings() {
            const search = document.getElementById('search-input').value;
            const batch = document.getElementById('filter-batch').value;
            const status = document.getElementById('filter-status').value;
            
            try {
                const res = await authFetch(\`/api/admin/bookings?search=\${search}&batch=\${batch}&status=\${status}\`);
                const json = await res.json();
                if(!json.success) return;

                const tbody = document.getElementById('bookings-tbody');
                tbody.innerHTML = '';
                
                if(json.data.bookings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No bookings found</td></tr>';
                    return;
                }

                json.data.bookings.forEach(b => {
                    const tr = document.createElement('tr');
                    const d = new Date(b.createdAt).toLocaleDateString();
                    tr.innerHTML = \`
                        <td><strong>\${b.bookingReference}</strong><br><small>\${d}</small></td>
                        <td>\${b.studentName}<br><small>📞 \${b.mobileNumber}</small></td>
                        <td>Seat <strong>\${b.seatNumber}</strong><br><small>\${b.batch.toUpperCase()}</small></td>
                        <td><span class="badge \${b.status}">\${b.status}</span></td>
                        <td>
                            \${b.status === 'reserved' ? \`<button class="clay-btn secondary" style="padding: 5px 10px; font-size:0.8rem;" onclick="releaseBooking('\${b._id}')">Release</button>\` : '-'}
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                console.error(err);
            }
        }

        async function releaseBooking(id) {
            if(!confirm("Are you sure you want to release this active reservation?")) return;
            try {
                const res = await authFetch('/api/admin/bookings/' + id + '/release', { method: 'POST' });
                const json = await res.json();
                if(json.success) {
                    showToast("Released successfully");
                    loadDashboard();
                    loadBookings();
                } else {
                    showToast(json.message, 'error');
                }
            } catch (err) {
                showToast("Error releasing", 'error');
            }
        }

        async function loadAdminSeatMap() {
            try {
                const res = await authFetch('/api/seats?batch=day'); // Just to get block states
                const json = await res.json();
                if(!json.success) return;
                
                const container = document.getElementById('admin-seat-grid');
                container.innerHTML = '';
                
                config.layout.rows.forEach(row => {
                    const rowDiv = document.createElement('div');
                    rowDiv.className = 'row-container';
                    rowDiv.innerHTML = \`<div class="row-label">\${row.label}</div>\`;
                    
                    for (let i = row.startSeat; i <= row.endSeat; i++) {
                        const seatData = json.data.find(s => s.seatNumber === i);
                        if (!seatData) continue;
                        
                        const btn = document.createElement('div');
                        btn.className = \`seat \${seatData.isBlocked ? 'blocked' : 'available'}\`;
                        btn.textContent = i;
                        btn.title = seatData.isBlocked ? "Blocked" : "Active";
                        
                        btn.onclick = () => toggleSeatBlock(i, !seatData.isBlocked);
                        rowDiv.appendChild(btn);
                    }
                    container.appendChild(rowDiv);
                });
            } catch (err) {}
        }

        async function toggleSeatBlock(seatNumber, shouldBlock) {
            const action = shouldBlock ? "block" : "unblock";
            if(!confirm(\`Are you sure you want to \${action} physical Seat \${seatNumber}? This affects both batches.\`)) return;
            
            try {
                const res = await authFetch('/api/admin/seats/' + seatNumber + '/block', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ block: shouldBlock })
                });
                const json = await res.json();
                if(json.success) {
                    showToast("Seat status updated");
                    loadAdminSeatMap();
                    loadDashboard();
                } else {
                    showToast(json.message, 'error');
                }
            } catch(err) {
                showToast("Error updating seat", 'error');
            }
        }

        // Auto init if token exists
        if(token) initDashboard();
    </script>
</body>
</html>
`;

// ==========================================
// 11. EXPRESS ROUTES FOR FRONTEND VIEWS
// ==========================================
app.get('/', (req, res) => {
    res.send(renderPublicUI());
});

app.get('/admin', (req, res) => {
    res.send(renderAdminUI());
});

// ==========================================
// 12. ERROR HANDLING MIDDLEWARE
// ==========================================
app.use((req, res) => {
    res.status(404).json({ success: false, message: "Endpoint not found" });
});

app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err);
    res.status(500).json({ success: false, message: "An unexpected server error occurred." });
});

// ==========================================
// 13. EXPORT FOR VERCEL
// ==========================================
module.exports = app;

// For local testing
if (require.main === module) {
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`Server running locally on port ${port}`));
}
