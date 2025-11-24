const express = require('express');
const app = express();
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const hostname = '0.0.0.0';
const port = process.env.PORT || 4000;

// CORS Configuration
app.use(cors({
    origin: '*', // For production, specify exact domains
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(express.json());
app.use(express.static('public'));

// Serve static files from root for login page
app.use('/style', express.static('style'));
app.use('/js', express.static('js'));

const JWT_SECRET = process.env.JWT_SECRET || 'stroke_rehab_secret_key_2024';

// Database Connection Pool
const createConnection = async () => {
    const connection = await mysql.createConnection({
        host: 'gateway01.ap-northeast-1.prod.aws.tidbcloud.com',
        user: '3HZNLzyS4E2dJfG.root',
        password: '1CmpzXSMTQxYdngG',
        database: 'stroke_rehab_db',
        ssl: { minVersion: 'TLSv1.2' },
        timezone: '+07:00',
        connectTimeout: 10000
    });
    
    await connection.execute("SET time_zone = '+07:00'");
    await connection.execute("SET SESSION time_zone = '+07:00'");
    
    return connection;
};

// Test database connection on startup
(async () => {
    try {
        const connection = await createConnection();
        console.log('✅ Database connected successfully');
        await connection.end();
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
    }
})();

// ========================
// Middleware: JWT Authentication
// ========================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'ต้องระบุ Access token' 
        });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('❌ Token verification failed:', err.message);
            return res.status(403).json({ 
                success: false, 
                message: 'Token ไม่ถูกต้อง หรือหมดอายุ' 
            });
        }
        
        // Ensure user_id is a number
        if (user.user_id) {
            user.user_id = parseInt(user.user_id);
        }
        
        console.log('✅ Token verified:', { 
            user_id: user.user_id, 
            role: user.role 
        });
        
        req.user = user;
        next();
    });
};

// ========================
// Health Check & Info Routes
// ========================
app.get('/', (req, res) => {
    res.json({ 
        message: 'ระบบติดตามการบำบัดทางกายภาพที่บ้าน',
        version: '1.0.0',
        status: 'online',
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        server: 'Stroke Rehabilitation System',
        port: port,
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// ========================
// Authentication Routes
// ========================

// Login
app.post('/api/auth/login', async (req, res) => {
    let connection;
    
    try {
        const { phone, password } = req.body;
        
        console.log('🔍 Login attempt:', { phone, hasPassword: !!password });
        
        // Validation
        if (!phone || !password) {
            return res.status(400).json({
                success: false,
                message: 'กรุณากรอกเบอร์โทรศัพท์และรหัสผ่าน'
            });
        }

        if (!/^[0-9]{10}$/.test(phone)) {
            return res.status(400).json({
                success: false,
                message: 'รูปแบบเบอร์โทรศัพท์ไม่ถูกต้อง (ต้องเป็นตัวเลข 10 หลัก)'
            });
        }

        connection = await createConnection();
        
        // Get user
        const [users] = await connection.execute(
            'SELECT user_id, phone, password_hash, full_name, role FROM Users WHERE phone = ?',
            [phone]
        );

        if (users.length === 0) {
            // Record failed login
            await recordLoginAttempt(connection, null, req.ip, 'Failed - User Not Found');
            
            return res.status(401).json({
                success: false,
                message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
            });
        }

        const user = users[0];
        
        // Verify password
        let isValidPassword = false;
        try {
            isValidPassword = await bcrypt.compare(password, user.password_hash);
        } catch (bcryptError) {
            console.error('❌ Bcrypt error:', bcryptError);
            return res.status(500).json({
                success: false,
                message: 'เกิดข้อผิดพลาดในการตรวจสอบรหัสผ่าน'
            });
        }
        
        if (!isValidPassword) {
            // Record failed login
            await recordLoginAttempt(connection, user.user_id, req.ip, 'Failed - Wrong Password');
            
            return res.status(401).json({
                success: false,
                message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
            });
        }

        // Create JWT Token
        const token = jwt.sign(
            { 
                user_id: parseInt(user.user_id),
                phone: user.phone, 
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Record successful login
        await recordLoginAttempt(connection, user.user_id, req.ip, 'Success');

        console.log('✅ Login successful:', { 
            phone: user.phone, 
            role: user.role,
            user_id: user.user_id 
        });

        res.json({
            success: true,
            message: 'เข้าสู่ระบบสำเร็จ',
            user: {
                user_id: parseInt(user.user_id),
                phone: user.phone,
                full_name: user.full_name,
                role: user.role
            },
            token: token
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ',
            debug: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (connection) {
            try {
                await connection.end();
            } catch (e) {
                console.error('Error closing connection:', e);
            }
        }
    }
});

// Helper function to record login attempts
async function recordLoginAttempt(connection, userId, ipAddress, status) {
    try {
        await connection.execute(
            'INSERT INTO Login_History (user_id, ip_address, status, login_time) VALUES (?, ?, ?, NOW())',
            [userId || null, ipAddress || '0.0.0.0', status]
        );
    } catch (error) {
        console.error('Failed to record login attempt:', error);
    }
}

// ========================
// Caregiver APIs
// ========================

// Get patient details
app.get('/api/caregiver/patient/:patientId', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        
        connection = await createConnection();
        
        // Get patient details
        const [patients] = await connection.execute(`
            SELECT 
                p.*,
                u.phone,
                u.full_name,
                u.role
            FROM Patients p
            JOIN Users u ON p.user_id = u.user_id
            WHERE p.patient_id = ?
        `, [patientId]);
        
        if (patients.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'ไม่พบข้อมูลผู้ป่วย'
            });
        }

        res.json({
            success: true,
            data: patients[0]
        });

    } catch (error) {
        console.error('❌ Error fetching patient details:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// Get exercise history for patient
app.get('/api/caregiver/patient/:patientId/exercises', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        const limit = req.query.limit || 10;
        
        connection = await createConnection();
        
        // Get exercise sessions
        const [exercises] = await connection.execute(`
            SELECT 
                es.*,
                e.exercise_name,
                e.description,
                DATE_FORMAT(es.session_date, '%Y-%m-%d') as session_date_formatted,
                DATE_FORMAT(es.session_date, '%H:%i') as session_time
            FROM Exercise_Sessions es
            JOIN Exercises e ON es.exercise_id = e.exercise_id
            WHERE es.patient_id = ?
            ORDER BY es.session_date DESC
            LIMIT ?
        `, [patientId, parseInt(limit)]);

        res.json({
            success: true,
            data: exercises,
            count: exercises.length
        });

    } catch (error) {
        console.error('❌ Error fetching exercises:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลการฝึก'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// Get weekly progress
app.get('/api/caregiver/patient/:patientId/progress/weekly', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        
        connection = await createConnection();
        
        // Get last 7 days of exercise data
        const [progress] = await connection.execute(`
            SELECT 
                DATE(session_date) as date,
                COUNT(*) as session_count,
                AVG(duration_minutes) as avg_duration,
                SUM(repetitions_completed) as total_reps
            FROM Exercise_Sessions
            WHERE patient_id = ?
            AND session_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(session_date)
            ORDER BY date DESC
        `, [patientId]);

        res.json({
            success: true,
            data: progress
        });

    } catch (error) {
        console.error('❌ Error fetching progress:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลความคืบหน้า'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// Get caregiver notes
app.get('/api/caregiver/patient/:patientId/notes', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        const limit = req.query.limit || 10;
        
        connection = await createConnection();
        
        const [notes] = await connection.execute(`
            SELECT 
                cn.*,
                u.full_name as caregiver_name,
                DATE_FORMAT(cn.created_at, '%Y-%m-%d %H:%i') as created_at_formatted
            FROM Caregiver_Notes cn
            JOIN Caregivers c ON cn.caregiver_id = c.caregiver_id
            JOIN Users u ON c.user_id = u.user_id
            WHERE cn.patient_id = ?
            ORDER BY cn.created_at DESC
            LIMIT ?
        `, [patientId, parseInt(limit)]);

        res.json({
            success: true,
            data: notes,
            count: notes.length
        });

    } catch (error) {
        console.error('❌ Error fetching notes:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลบันทึก'
        });
    } finally {
        if (connection) await connection.end();
    }
});


// Get exercise history for patient
app.get('/api/caregiver/patient/:patientId/exercises', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        const limit = req.query.limit || 10;
        
        connection = await createConnection();
        
        // Get exercise sessions
        const [exercises] = await connection.execute(`
            SELECT 
                es.*,
                e.exercise_name,
                e.description,
                DATE_FORMAT(es.session_date, '%Y-%m-%d') as session_date_formatted,
                DATE_FORMAT(es.session_date, '%H:%i') as session_time
            FROM Exercise_Sessions es
            JOIN Exercises e ON es.exercise_id = e.exercise_id
            WHERE es.patient_id = ?
            ORDER BY es.session_date DESC
            LIMIT ?
        `, [patientId, parseInt(limit)]);

        res.json({
            success: true,
            data: exercises,
            count: exercises.length
        });

    } catch (error) {
        console.error('❌ Error fetching exercises:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลการฝึก'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// Get weekly progress
app.get('/api/caregiver/patient/:patientId/progress/weekly', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        
        connection = await createConnection();
        
        // Get last 7 days of exercise data
        const [progress] = await connection.execute(`
            SELECT 
                DATE(session_date) as date,
                COUNT(*) as session_count,
                AVG(duration_minutes) as avg_duration,
                SUM(repetitions_completed) as total_reps
            FROM Exercise_Sessions
            WHERE patient_id = ?
            AND session_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(session_date)
            ORDER BY date DESC
        `, [patientId]);

        res.json({
            success: true,
            data: progress
        });

    } catch (error) {
        console.error('❌ Error fetching progress:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลความคืบหน้า'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// Save caregiver note
app.post('/api/caregiver/notes', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const { patient_id, note_text } = req.body;
        
        if (!patient_id || !note_text) {
            return res.status(400).json({
                success: false,
                message: 'กรุณาระบุข้อมูลให้ครบถ้วน'
            });
        }

        connection = await createConnection();
        
        // Insert note
        await connection.execute(`
            INSERT INTO Caregiver_Notes (caregiver_id, patient_id, note_text, created_at)
            SELECT c.caregiver_id, ?, ?, NOW()
            FROM Caregivers c
            WHERE c.user_id = ?
        `, [patient_id, note_text, req.user.user_id]);

        res.json({
            success: true,
            message: 'บันทึกสำเร็จ'
        });

    } catch (error) {
        console.error('❌ Error saving note:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการบันทึก'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// Get caregiver notes
app.get('/api/caregiver/patient/:patientId/notes', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        const limit = req.query.limit || 10;
        
        connection = await createConnection();
        
        const [notes] = await connection.execute(`
            SELECT 
                cn.*,
                u.full_name as caregiver_name,
                DATE_FORMAT(cn.created_at, '%Y-%m-%d %H:%i') as created_at_formatted
            FROM Caregiver_Notes cn
            JOIN Caregivers c ON cn.caregiver_id = c.caregiver_id
            JOIN Users u ON c.user_id = u.user_id
            WHERE cn.patient_id = ?
            ORDER BY cn.created_at DESC
            LIMIT ?
        `, [patientId, parseInt(limit)]);

        res.json({
            success: true,
            data: notes,
            count: notes.length
        });

    } catch (error) {
        console.error('❌ Error fetching notes:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลบันทึก'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// ========================
// Error Handlers
// ========================

// 404 Handler
app.use((req, res, next) => {
    res.status(404).json({
        success: false,
        message: 'ไม่พบเส้นทาง API ที่ระบุ',
        path: req.originalUrl,
        method: req.method
    });
});

// Global Error Handler
app.use((error, req, res, next) => {
    console.error('❌ Server error:', error);
    
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    res.status(500).json({
        success: false,
        message: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์',
        ...(isDevelopment && { 
            error: error.message, 
            stack: error.stack 
        })
    });
});

// ========================
// Start Server
// ========================
app.listen(port, hostname, () => {
    console.log('');
    console.log('========================================');
    console.log('  🏥 Stroke Rehabilitation System');
    console.log('========================================');
    console.log(`✅ Server running on ${hostname}:${port}`);
    console.log(`📡 API URL: http://${hostname}:${port}/api`);
    console.log(`🔒 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
    console.log('========================================');
    console.log('');
});

module.exports = app;