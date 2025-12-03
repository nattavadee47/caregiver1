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
// Patient Search API (ต้องอยู่ก่อน Error Handlers)
// ========================
app.post('/api/patients/search', async (req, res) => {
    let connection;
    
    try {
        const { patient_phone } = req.body;
        
        if (!patient_phone || patient_phone.trim() === '') {
            return res.status(400).json({ 
                success: false, 
                message: 'กรุณากรอกเบอร์โทรศัพท์' 
            });
        }

        // ตรวจสอบรูปแบบเบอร์โทร
        const phoneRegex = /^0[0-9]{9}$/;
        if (!phoneRegex.test(patient_phone)) {
            return res.status(400).json({ 
                success: false, 
                message: 'รูปแบบเบอร์โทรศัพท์ไม่ถูกต้อง' 
            });
        }

        console.log('🔍 Searching for phone:', patient_phone);

        connection = await createConnection();
        
        // ✅ ค้นหาด้วย MySQL (ใช้ patient_phone ตาม schema)
        const [patients] = await connection.execute(
            `SELECT 
                patient_id,
                CONCAT(first_name, ' ', last_name) as full_name,
                patient_phone,
                birth_date as date_of_birth,
                gender
             FROM Patients 
             WHERE patient_phone = ?`,
            [patient_phone]
        );

        if (patients.length === 0) {
            return res.json({ 
                success: false, 
                message: 'ไม่พบข้อมูลผู้ป่วย' 
            });
        }

        const patient = patients[0];
        console.log('✅ Patient found:', patient.patient_id);

        res.json({ 
            success: true, 
            patient: {
                patient_id: patient.patient_id,
                full_name: patient.full_name,
                phone: patient.patient_phone,
                dateOfBirth: patient.date_of_birth,
                gender: patient.gender
            }
        });

    } catch (error) {
        console.error('❌ Search error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'เกิดข้อผิดพลาดในการค้นหา',
            error: error.message 
        });
    } finally {
        if (connection) await connection.end();
    }
});

// ========================
// Caregiver APIs
// ========================

// Get patients for caregiver
app.get('/api/caregiver/patients', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const caregiverPhone = req.user.phone;
        console.log('👨‍⚕️ Fetching patients for caregiver:', caregiverPhone);
        
        connection = await createConnection();
        
        const [patients] = await connection.execute(`
            SELECT 
                p.patient_id,
                p.first_name,
                p.last_name,
                p.birth_date as date_of_birth,
                p.patient_phone as phone_number,
                c.relationship,
                c.contact_name as caregiver_name,
                DATE_FORMAT(p.birth_date, '%Y-%m-%d') as dob_formatted,
                TIMESTAMPDIFF(YEAR, p.birth_date, CURDATE()) as age,
                p.gender
            FROM Patients p
            INNER JOIN Caregivers c ON p.user_id = c.user_id
            WHERE c.contact_phone = ?
            ORDER BY p.first_name, p.last_name
        `, [caregiverPhone]);

        console.log('✅ Found patients:', patients.length);
        res.json(patients);
    } catch (error) {
        console.error('❌ Error fetching patients:', error);
        res.status(500).json({ 
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย' 
        });
    } finally {
        if (connection) await connection.end();
    }
});
// Get patient dashboard
app.get('/api/caregiver/patient/:patientId/dashboard', authenticateToken, async (req, res) => {
    let connection;
    
    try {
        const patientId = req.params.patientId;
        
        connection = await createConnection();
        
        // Get patient info (แก้ไข: ไม่ต้อง JOIN Caregivers)
        const [patients] = await connection.execute(`
            SELECT 
                p.*,
                p.emergency_contact_name as caregiver_name,
                p.emergency_contact_relation as relationship,
                DATE_FORMAT(p.birth_date, '%Y-%m-%d') as dob_formatted,
                TIMESTAMPDIFF(YEAR, p.birth_date, CURDATE()) as age
            FROM Patients p
            WHERE p.patient_id = ?
        `, [patientId]);

        if (patients.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'ไม่พบข้อมูลผู้ป่วย'
            });
        }

        // Get exercise stats
        const [exerciseStats] = await connection.execute(`
            SELECT 
                COUNT(*) as total_sessions,
                SUM(duration_minutes) as total_minutes,
                AVG(duration_minutes) as avg_duration
            FROM Exercise_Sessions
            WHERE patient_id = ?
            AND session_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        `, [patientId]);

        // Get recent exercises
        const [recentExercises] = await connection.execute(`
            SELECT 
                es.*,
                e.name_th as exercise_name,
                e.name_en,
                DATE_FORMAT(es.session_date, '%Y-%m-%d') as session_date_formatted,
                DATE_FORMAT(es.session_date, '%H:%i') as session_time
            FROM Exercise_Sessions es
            JOIN Exercises e ON es.exercise_id = e.exercise_id
            WHERE es.patient_id = ?
            ORDER BY es.session_date DESC
            LIMIT 5
        `, [patientId]);

        res.json({
            success: true,
            data: {
                patient: patients[0],
                stats: exerciseStats[0],
                recent_exercises: recentExercises
            }
        });

    } catch (error) {
        console.error('❌ Error fetching dashboard:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูล Dashboard'
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
        
        // ✅ แก้ไข SQL query - ใช้ connection.execute และแก้ชื่อ column
        const [exercises] = await connection.execute(`
            SELECT 
                es.*,
                e.name_th as exercise_name,
                e.name_en,
                e.description,
                e.angle_range,
                e.hold_time,
                e.repetitions,
                e.sets,
                e.rest_time,
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
// Registration APIs
// ========================

// Register caregiver
app.post('/api/register/caregiver', async (req, res) => {
    let connection;
    
    try {
        const { phone, password, contact_name, relationship, patient_id } = req.body;

        // ตรวจสอบข้อมูลที่จำเป็น
        if (!phone || !password || !contact_name || !relationship || !patient_id) {
            return res.status(400).json({ 
                success: false, 
                message: 'กรุณากรอกข้อมูลให้ครบถ้วน' 
            });
        }

        // ตรวจสอบรูปแบบเบอร์โทร
        const phoneRegex = /^0[0-9]{9}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).json({ 
                success: false, 
                message: 'รูปแบบเบอร์โทรศัพท์ไม่ถูกต้อง' 
            });
        }

        connection = await createConnection();

        // ตรวจสอบว่าเบอร์โทรซ้ำหรือไม่
        const [existingUser] = await connection.execute(
            'SELECT user_id FROM Users WHERE phone = ?',
            [phone]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'เบอร์โทรศัพท์นี้ถูกใช้งานแล้ว' 
            });
        }

        // ตรวจสอบว่าผู้ป่วยมีอยู่จริง
        const [patient] = await connection.execute(
            'SELECT patient_id FROM Patients WHERE patient_id = ?',
            [patient_id]
        );

        if (patient.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'ไม่พบข้อมูลผู้ป่วย' 
            });
        }

        // เข้ารหัสรหัสผ่าน
        const hashedPassword = await bcrypt.hash(password, 10);

        // เริ่ม Transaction
        await connection.beginTransaction();

        try {
            // สร้างผู้ใช้ใหม่ (ใช้ default role จาก database)
            console.log('📝 Creating user with phone:', phone);
            const [userResult] = await connection.execute(
                `INSERT INTO Users (phone, password_hash) 
                 VALUES (?, ?)`,
                [phone, hashedPassword]
            );

            const userId = userResult.insertId;
            console.log('✅ User created with ID:', userId);

            // สร้างข้อมูลผู้ดูแล
            console.log('📝 Creating caregiver record...');
            const [caregiverResult] = await connection.execute(
                `INSERT INTO Caregivers (user_id, relationship, contact_name, contact_phone, is_external_contact) 
                 VALUES (?, ?, ?, ?, 0)`,
                [userId, relationship, contact_name, phone]
            );
            const caregiverId = caregiverResult.insertId;
            console.log('✅ Caregiver record created with ID:', caregiverId);

            // อัพเดทข้อมูล Emergency Contact ในตาราง Patients
            console.log('📝 Updating patient emergency contact...');
            await connection.execute(
                `UPDATE Patients 
                 SET emergency_contact_name = ?, 
                     emergency_contact_phone = ?,
                     emergency_contact_relation = ?
                 WHERE patient_id = ?`,
                [contact_name, phone, relationship, patient_id]
            );
            console.log('✅ Patient emergency contact updated');

            // Commit Transaction
            await connection.commit();
            console.log('✅ Transaction committed');

            res.json({ 
                success: true, 
                message: 'สมัครสมาชิกสำเร็จ',
                user_id: userId
            });

        } catch (error) {
            // Rollback ถ้าเกิดข้อผิดพลาด
            console.error('❌ Transaction error:', error);
            console.error('❌ Error details:', {
                message: error.message,
                code: error.code,
                sqlState: error.sqlState
            });
            await connection.rollback();
            throw error;
        }

    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'เกิดข้อผิดพลาดในการสมัครสมาชิก',
            error: error.message
        });
    } finally {
        if (connection) await connection.end();
    }
});

// Get patients list
app.get('/api/patients/list', async (req, res) => {
    let connection;
    
    try {
        connection = await createConnection();
        
        const [patients] = await connection.execute(
            `SELECT patient_id, 
                    CONCAT(first_name, ' ', last_name) as full_name,
                    patient_phone as phone_number
             FROM Patients
             ORDER BY first_name, last_name`
        );

        res.json({ 
            success: true, 
            patients: patients 
        });

    } catch (error) {
        console.error('❌ Error fetching patients:', error);
        res.status(500).json({ 
            success: false, 
            message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย' 
        });
    } finally {
        if (connection) await connection.end();
    }
});

// ========================
// Error Handlers (ต้องอยู่ท้ายสุดเสมอ!)
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