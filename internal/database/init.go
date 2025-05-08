package database

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// InitDatabase zorgt ervoor dat de benodigde database bestaat
func InitDatabase() (*sql.DB, error) {
	// Verbind met de standaard postgres database
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=postgres sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to postgres database: %w", err)
	}
	defer db.Close()

	// Test de verbinding
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("could not ping postgres database: %w", err)
	}

	// Controleer of database bestaat
	dbName := os.Getenv("DB_NAME")
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbName).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("error checking if database exists: %w", err)
	}

	// Maak database aan als deze niet bestaat
	if !exists {
		_, err := db.Exec("CREATE DATABASE " + dbName)
		if err != nil {
			return nil, fmt.Errorf("could not create database %s: %w", dbName, err)
		}
		fmt.Printf("Database '%s' successfully created\n", dbName)
	} else {
		fmt.Printf("Database '%s' already exists\n", dbName)
	}

	// Verbind met de nieuwe database om tabellen aan te maken
	connStr = fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		dbName,
	)

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to new database: %w", err)
	}

	// Hier kun je tabellen aanmaken
	if err := createTables(db); err != nil {
		return nil, err
	}

	// Update users table
	if err := UpdateUserTables(db); err != nil {
		return nil, fmt.Errorf("could not update users table: %w", err)
	}

	// Bij het retourneren, geef ook de database verbinding terug:
	return db, nil
}

// createTables maakt de benodigde tabellen aan
func createTables(db *sql.DB) error {
	// Users tabel
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100)  NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            google_id VARCHAR(255) UNIQUE,
            is_verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		return fmt.Errorf("could not create users table: %w", err)
	}

	// Sessions tabel
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		return fmt.Errorf("could not create sessions table: %w", err)
	}

	// Email verification tokens
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS verification_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		return fmt.Errorf("could not create verification_tokens table: %w", err)
	}

	// Password reset tokens
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		return fmt.Errorf("could not create password_reset_tokens table: %w", err)
	}

	fmt.Println("Database tables successfully created or already exist")
	return nil
}

// UpdateUserTables ensures the users table has the necessary fields for OAuth
func UpdateUserTables(db *sql.DB) error {
	// Add Google ID column to users table if it doesn't exist
	_, err := db.Exec(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS google_id VARCHAR(255) UNIQUE,
        ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE
    `)
	return err
}
