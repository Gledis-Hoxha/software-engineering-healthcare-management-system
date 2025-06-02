const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database connection
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'healthcare_management',
  password: 'yourpassword', // Change this to your PostgreSQL password
  port: 5432,
});

// JWT Secret
const JWT_SECRET = 'your_jwt_secret'; // In production, use environment variable

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Add this near the top, after app initialization
app.get('/', (req, res) => {
  res.json({ 
    message: "Healthcare API is running",
    version: "1.0.0",
    endpoints: {
      auth: "/api/login",
      patients: "/api/patients",
      // Add other key endpoints
    }
  });
});

// Add error handling middleware to index.js (right before app.listen)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role, patientData, providerData } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Start transaction
    await pool.query('BEGIN');
    
    // Insert user
    const userResult = await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id',
      [username, hashedPassword, role]
    );
    
    const userId = userResult.rows[0].id;
    
    // Insert role-specific data
    if (role === 'patient' && patientData) {
      await pool.query(
        `INSERT INTO patients (
          user_id, first_name, last_name, date_of_birth, gender, 
          address, phone, email, insurance_provider, insurance_number
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          userId, patientData.first_name, patientData.last_name, patientData.date_of_birth,
          patientData.gender, patientData.address, patientData.phone, patientData.email,
          patientData.insurance_provider, patientData.insurance_number
        ]
      );
    } else if ((role === 'doctor' || role === 'nurse') && providerData) {
      await pool.query(
        `INSERT INTO healthcare_providers (
          user_id, first_name, last_name, specialization, 
          phone, email, department
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          userId, providerData.first_name, providerData.last_name, providerData.specialization,
          providerData.phone, providerData.email, providerData.department
        ]
      );
    }
    
    await pool.query('COMMIT');
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Get user from database
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ token, role: user.role });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get all patients (admin only)
app.get('/api/patients', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  
  try {
    const result = await pool.query(`
      SELECT p.*, u.username 
      FROM patients p
      JOIN users u ON p.user_id = u.id
    `);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch patients' });
  }
});

// Get patient by ID
app.get('/api/patients/:id', authenticateToken, async (req, res) => {
  try {
    // Only allow if requester is admin, or the patient themselves, or their provider
    const patientId = parseInt(req.params.id);
    
    if (req.user.role === 'patient') {
      // Get the patient's own user ID
      const patientUser = await pool.query(
        'SELECT user_id FROM patients WHERE id = $1', 
        [patientId]
      );
      
      if (patientUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    }
    
    const result = await pool.query(`
      SELECT p.*, u.username 
      FROM patients p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = $1
    `, [patientId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Patient not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch patient' });
  }
});

// Update patient information
app.put('/api/patients/:id', authenticateToken, async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);
    const { first_name, last_name, date_of_birth, gender, address, phone, email, insurance_provider, insurance_number } = req.body;
    
    // Verify permissions
    if (req.user.role === 'patient') {
      const patientUser = await pool.query(
        'SELECT user_id FROM patients WHERE id = $1', 
        [patientId]
      );
      
      if (patientUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    } else if (req.user.role !== 'admin') {
      return res.sendStatus(403);
    }
    
    const result = await pool.query(`
      UPDATE patients SET
        first_name = $1,
        last_name = $2,
        date_of_birth = $3,
        gender = $4,
        address = $5,
        phone = $6,
        email = $7,
        insurance_provider = $8,
        insurance_number = $9
      WHERE id = $10
      RETURNING *
    `, [
      first_name, last_name, date_of_birth, gender, 
      address, phone, email, insurance_provider, 
      insurance_number, patientId
    ]);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update patient' });
  }
});

// Get all healthcare providers
app.get('/api/providers', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT hp.*, u.username 
      FROM healthcare_providers hp
      JOIN users u ON hp.user_id = u.id
    `);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch providers' });
  }
});

// Get provider by ID
app.get('/api/providers/:id', authenticateToken, async (req, res) => {
  try {
    const providerId = parseInt(req.params.id);
    const result = await pool.query(`
      SELECT hp.*, u.username 
      FROM healthcare_providers hp
      JOIN users u ON hp.user_id = u.id
      WHERE hp.id = $1
    `, [providerId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Provider not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch provider' });
  }
});

// Create appointment
app.post('/api/appointments', authenticateToken, async (req, res) => {
  try {
    const { patient_id, provider_id, appointment_date, appointment_time, reason } = req.body;
    
    // Verify permissions - patients can only create their own appointments
    if (req.user.role === 'patient') {
      const patientUser = await pool.query(
        'SELECT user_id FROM patients WHERE id = $1', 
        [patient_id]
      );
      
      if (patientUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    }
    
    const result = await pool.query(`
      INSERT INTO appointments (
        patient_id, provider_id, appointment_date, 
        appointment_time, reason, status
      ) VALUES ($1, $2, $3, $4, $5, 'Scheduled')
      RETURNING *
    `, [patient_id, provider_id, appointment_date, appointment_time, reason]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create appointment' });
  }
});

// Get appointments for a patient
app.get('/api/patients/:id/appointments', authenticateToken, async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);
    
    // Verify permissions
    if (req.user.role === 'patient') {
      const patientUser = await pool.query(
        'SELECT user_id FROM patients WHERE id = $1', 
        [patientId]
      );
      
      if (patientUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    }
    
    const result = await pool.query(`
      SELECT a.*, 
        p.first_name as patient_first_name, p.last_name as patient_last_name,
        hp.first_name as provider_first_name, hp.last_name as provider_last_name,
        hp.specialization as provider_specialization
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      JOIN healthcare_providers hp ON a.provider_id = hp.id
      WHERE a.patient_id = $1
      ORDER BY a.appointment_date, a.appointment_time
    `, [patientId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

// Get appointments for a provider
app.get('/api/providers/:id/appointments', authenticateToken, async (req, res) => {
  try {
    const providerId = parseInt(req.params.id);
    
    // Verify permissions
    if (req.user.role === 'doctor' || req.user.role === 'nurse') {
      const providerUser = await pool.query(
        'SELECT user_id FROM healthcare_providers WHERE id = $1', 
        [providerId]
      );
      
      if (providerUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    }
    
    const result = await pool.query(`
      SELECT a.*, 
        p.first_name as patient_first_name, p.last_name as patient_last_name
      FROM appointments a
      JOIN patients p ON a.patient_id = p.id
      WHERE a.provider_id = $1
      ORDER BY a.appointment_date, a.appointment_time
    `, [providerId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

// Update appointment status
app.put('/api/appointments/:id/status', authenticateToken, async (req, res) => {
  try {
    const appointmentId = parseInt(req.params.id);
    const { status } = req.body;
    
    // Only providers can update status
    if (req.user.role !== 'doctor' && req.user.role !== 'nurse') {
      return res.sendStatus(403);
    }
    
    const result = await pool.query(`
      UPDATE appointments SET
        status = $1
      WHERE id = $2
      RETURNING *
    `, [status, appointmentId]);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update appointment' });
  }
});

// Create medical record
app.post('/api/medical-records', authenticateToken, async (req, res) => {
  try {
    // Only providers can create medical records
    if (req.user.role !== 'doctor' && req.user.role !== 'nurse') {
      return res.sendStatus(403);
    }
    
    const { patient_id, appointment_id, diagnosis, treatment, notes } = req.body;
    
    const result = await pool.query(`
      INSERT INTO medical_records (
        patient_id, appointment_id, diagnosis, treatment, notes
      ) VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [patient_id, appointment_id, diagnosis, treatment, notes]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create medical record' });
  }
});

// Get medical records for a patient
app.get('/api/patients/:id/medical-records', authenticateToken, async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);
    
    // Verify permissions
    if (req.user.role === 'patient') {
      const patientUser = await pool.query(
        'SELECT user_id FROM patients WHERE id = $1', 
        [patientId]
      );
      
      if (patientUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    } else if (req.user.role !== 'admin' && req.user.role !== 'doctor' && req.user.role !== 'nurse') {
      return res.sendStatus(403);
    }
    
    const result = await pool.query(`
      SELECT mr.*, 
        a.appointment_date, a.appointment_time,
        hp.first_name as provider_first_name, hp.last_name as provider_last_name,
        hp.specialization as provider_specialization
      FROM medical_records mr
      JOIN appointments a ON mr.appointment_id = a.id
      JOIN healthcare_providers hp ON a.provider_id = hp.id
      WHERE mr.patient_id = $1
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `, [patientId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch medical records' });
  }
});

// Create prescription
app.post('/api/prescriptions', authenticateToken, async (req, res) => {
  try {
    // Only providers can create prescriptions
    if (req.user.role !== 'doctor' && req.user.role !== 'nurse') {
      return res.sendStatus(403);
    }
    
    const { patient_id, appointment_id, medication_name, dosage, frequency, duration, instructions } = req.body;
    
    // Get provider ID from user ID
    const providerResult = await pool.query(
      'SELECT id FROM healthcare_providers WHERE user_id = $1',
      [req.user.id]
    );
    
    if (providerResult.rows.length === 0) {
      return res.status(403).json({ error: 'Only healthcare providers can create prescriptions' });
    }
    
    const provider_id = providerResult.rows[0].id;
    
    const result = await pool.query(`
      INSERT INTO prescriptions (
        patient_id, provider_id, appointment_id, 
        medication_name, dosage, frequency, duration, instructions
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [
      patient_id, provider_id, appointment_id, 
      medication_name, dosage, frequency, duration, instructions
    ]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create prescription' });
  }
});

// Get prescriptions for a patient
app.get('/api/patients/:id/prescriptions', authenticateToken, async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);
    
    // Verify permissions
    if (req.user.role === 'patient') {
      const patientUser = await pool.query(
        'SELECT user_id FROM patients WHERE id = $1', 
        [patientId]
      );
      
      if (patientUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    } else if (req.user.role !== 'admin' && req.user.role !== 'doctor' && req.user.role !== 'nurse') {
      return res.sendStatus(403);
    }
    
    const result = await pool.query(`
      SELECT pr.*, 
        a.appointment_date,
        hp.first_name as provider_first_name, hp.last_name as provider_last_name,
        hp.specialization as provider_specialization
      FROM prescriptions pr
      JOIN appointments a ON pr.appointment_id = a.id
      JOIN healthcare_providers hp ON pr.provider_id = hp.id
      WHERE pr.patient_id = $1
      ORDER BY pr.prescribed_date DESC
    `, [patientId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch prescriptions' });
  }
});

// Create billing record
app.post('/api/billing', authenticateToken, async (req, res) => {
  try {
    // Only admin or staff can create billing records
    if (req.user.role !== 'admin' && req.user.role !== 'staff') {
      return res.sendStatus(403);
    }
    
    const { patient_id, appointment_id, amount, status, payment_method, insurance_claim_details } = req.body;
    
    const result = await pool.query(`
      INSERT INTO billing (
        patient_id, appointment_id, amount, status, 
        payment_method, insurance_claim_details
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [
      patient_id, appointment_id, amount, status, 
      payment_method, insurance_claim_details
    ]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create billing record' });
  }
});

// Get billing records for a patient
app.get('/api/patients/:id/billing', authenticateToken, async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);
    
    // Verify permissions
    if (req.user.role === 'patient') {
      const patientUser = await pool.query(
        'SELECT user_id FROM patients WHERE id = $1', 
        [patientId]
      );
      
      if (patientUser.rows[0].user_id !== req.user.id) {
        return res.sendStatus(403);
      }
    } else if (req.user.role !== 'admin' && req.user.role !== 'staff') {
      return res.sendStatus(403);
    }
    
    const result = await pool.query(`
      SELECT b.*, 
        a.appointment_date,
        p.first_name as patient_first_name, p.last_name as patient_last_name
      FROM billing b
      JOIN appointments a ON b.appointment_id = a.id
      JOIN patients p ON b.patient_id = p.id
      WHERE b.patient_id = $1
      ORDER BY b.created_at DESC
    `, [patientId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch billing records' });
  }
});

// Update billing status
app.put('/api/billing/:id/status', authenticateToken, async (req, res) => {
  try {
    const billingId = parseInt(req.params.id);
    const { status, payment_method, payment_date } = req.body;
    
    // Only admin or staff can update billing
    if (req.user.role !== 'admin' && req.user.role !== 'staff') {
      return res.sendStatus(403);
    }
    
    const result = await pool.query(`
      UPDATE billing SET
        status = $1,
        payment_method = $2,
        payment_date = $3
      WHERE id = $4
      RETURNING *
    `, [status, payment_method, payment_date, billingId]);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update billing record' });
  }
});

// Get appointment statistics
app.get('/api/reports/appointments', authenticateToken, async (req, res) => {
  try {
    // Only admin can view reports
    if (req.user.role !== 'admin') {
      return res.sendStatus(403);
    }
    
    const { start_date, end_date } = req.query;
    
    const query = {
      text: `
        SELECT 
          status, COUNT(*) as count
        FROM appointments
        WHERE appointment_date BETWEEN $1 AND $2
        GROUP BY status
      `,
      values: [start_date, end_date]
    };
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch appointment statistics' });
  }
});

// Get revenue report
app.get('/api/reports/revenue', authenticateToken, async (req, res) => {
  try {
    // Only admin can view reports
    if (req.user.role !== 'admin') {
      return res.sendStatus(403);
    }
    
    const { start_date, end_date } = req.query;
    
    const query = {
      text: `
        SELECT 
          status, SUM(amount) as total_amount, COUNT(*) as count
        FROM billing
        WHERE created_at BETWEEN $1 AND $2
        GROUP BY status
      `,
      values: [start_date, end_date]
    };
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch revenue report' });
  }
});

