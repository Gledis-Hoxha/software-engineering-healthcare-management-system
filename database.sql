-- Database creation
CREATE DATABASE healthcare_management;

-- Users table (for authentication)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse', 'patient', 'staff')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Patients table
CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    date_of_birth DATE NOT NULL,
    gender VARCHAR(10) CHECK (gender IN ('Male', 'Female', 'Other')),
    address TEXT,
    phone VARCHAR(20),
    email VARCHAR(100),
    insurance_provider VARCHAR(100),
    insurance_number VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Healthcare providers table
CREATE TABLE healthcare_providers (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    specialization VARCHAR(100),
    phone VARCHAR(20),
    email VARCHAR(100),
    department VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Appointments table
CREATE TABLE appointments (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    provider_id INTEGER REFERENCES healthcare_providers(id),
    appointment_date DATE NOT NULL,
    appointment_time TIME NOT NULL,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'Scheduled' CHECK (status IN ('Scheduled', 'Completed', 'Cancelled', 'No-Show')),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Medical records table
CREATE TABLE medical_records (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    appointment_id INTEGER REFERENCES appointments(id),
    diagnosis TEXT,
    treatment TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Prescriptions table
CREATE TABLE prescriptions (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    provider_id INTEGER REFERENCES healthcare_providers(id),
    appointment_id INTEGER REFERENCES appointments(id),
    medication_name VARCHAR(100) NOT NULL,
    dosage VARCHAR(50) NOT NULL,
    frequency VARCHAR(50) NOT NULL,
    duration VARCHAR(50) NOT NULL,
    instructions TEXT,
    prescribed_date DATE DEFAULT CURRENT_DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Billing table
CREATE TABLE billing (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(id),
    appointment_id INTEGER REFERENCES appointments(id),
    amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'Pending' CHECK (status IN ('Pending', 'Paid', 'Insurance Claim')),
    payment_method VARCHAR(50),
    payment_date DATE,
    insurance_claim_details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);