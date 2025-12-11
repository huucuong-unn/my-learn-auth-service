-- V1__Create_auth_users_table.sql

-- Creates the core table for storing user authentication data.
CREATE TABLE auth_users (
    -- Primary key, using UUID as defined in the JPA entity.
                            id UUID PRIMARY KEY,

    -- Unique email address, required for login.
                            email VARCHAR(255) NOT NULL UNIQUE,

    -- Securely hashed password.
                            password_hash VARCHAR(255) NOT NULL,

    -- User role (LEARNER, INSTRUCTOR, ADMIN), stored as text.
                            role VARCHAR(50) NOT NULL,

    -- Stores the current refresh token. This should ideally be in Redis for security/performance,
    -- but storing it here for the initial simplified setup.
                            refresh_token VARCHAR(512),

    -- Timestamps for auditing purposes.
                            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                            updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Index on email for faster lookup during login
CREATE UNIQUE INDEX idx_auth_users_email ON auth_users (email);