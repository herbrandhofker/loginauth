package auth

import (
	"crypto/rand" // Voor random token generatie
	"database/sql"
	"encoding/base64" // Voor token encoding
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt" // Voor wachtwoord hashing

	"loginauth/internal/models"
)

type AuthService struct {
	DB           *sql.DB
	EmailService *EmailService
}

// Wijzig dit in service.go
func NewAuthService(db *sql.DB, emailService *EmailService) *AuthService {
	return &AuthService{
		DB:           db,
		EmailService: emailService,
	}
}

// RegisterUser registers a new user with username, email and password
func (s *AuthService) RegisterUser(username, email, password string) error {
	// Check if email already exists
	var existingCount int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&existingCount)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	if existingCount > 0 {
		return errors.New("email already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("password hashing failed: %w", err)
	}

	// Begin een transactie
	tx, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("transaction start failed: %w", err)
	}
	defer tx.Rollback() // Rollback bij fout of aan het einde

	// Insert user into database
	// FIXED: Toegevoegd ontbrekende haakje aan het eind van de SQL statement
	_, err = tx.Exec(
		`INSERT INTO users (username, email, password_hash, is_verified, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		username, email, string(hashedPassword), false,
	)
	if err != nil {
		return fmt.Errorf("user creation failed: %w", err)
	}

	// Commit de transactie
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("transaction commit failed: %w", err)
	}

	// Aan het einde, na succesvolle registratie:
	if s.EmailService != nil {
		// Maak een verificatie token aan
		token, err := s.CreateVerificationToken(email)
		if err != nil {
			// Log de fout maar laat de registratie slagen
			log.Printf("Failed to create verification token: %v", err)
		} else {
			// Stuur verificatie email
			err = s.EmailService.SendVerificationEmail(email, username, token)
			if err != nil {
				log.Printf("Failed to send verification email: %v", err)
			}
		}
	}

	return nil
}

// Helper function to generate a random token
func generateRandomToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

// VerifyEmail verifies a user's email with a token
func (s *AuthService) VerifyEmail(token string) error {
	// Find token
	var userID int64
	var expiresAt time.Time

	err := s.DB.QueryRow(`
        SELECT user_id, expires_at FROM verification_tokens
        WHERE token = $1
    `, token).Scan(&userID, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("invalid verification token")
		}
		return err
	}

	// Check if token is expired
	if time.Now().After(expiresAt) {
		return errors.New("verification token has expired")
	}

	// Update user to verified
	_, err = s.DB.Exec(`
        UPDATE users SET is_verified = TRUE 
        WHERE id = $1
    `, userID)
	if err != nil {
		return err
	}

	// Delete used token
	_, err = s.DB.Exec(`
        DELETE FROM verification_tokens
        WHERE token = $1
    `, token)

	return err
}

// LoginUser authenticates a user with email and password
func (s *AuthService) LoginUser(email, password string) (*models.Session, error) {
	// Find user by email
	var user models.User
	err := s.DB.QueryRow(`
        SELECT id, username, email, password_hash, is_verified FROM users WHERE email = $1
    `, email).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.IsVerified)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid email or password")
		}
		return nil, err
	}

	// Check if user is verified
	if !user.IsVerified {
		return nil, errors.New("please verify your email before logging in")
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	// Create session
	return s.CreateSession(user.ID)
}

// CreateSession creates a new session for a user
func (s *AuthService) CreateSession(userID int64) (*models.Session, error) {
	// Generate session token
	token := uuid.New().String()

	// Session expiration (e.g., 30 days)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	// Insert session into database
	var session models.Session
	err := s.DB.QueryRow(`
        INSERT INTO sessions (user_id, token, expires_at, created_at)
        VALUES ($1, $2, $3, NOW())
        RETURNING id, user_id, token, expires_at, created_at
    `, userID, token, expiresAt).Scan(
		&session.ID, &session.UserID, &session.Token, &session.ExpiresAt, &session.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// GetUserBySession retrieves a user by session token
func (s *AuthService) GetUserBySession(token string) (*models.User, error) {
	// Find valid session
	var userID int64
	err := s.DB.QueryRow(`
        SELECT user_id FROM sessions 
        WHERE token = $1 AND expires_at > NOW()
    `, token).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid or expired session")
		}
		return nil, err
	}

	// Get user
	var user models.User
	err = s.DB.QueryRow(`
        SELECT id, username, email, created_at, updated_at FROM users 
        WHERE id = $1
    `, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// RequestPasswordReset initiates a password reset
func (s *AuthService) RequestPasswordReset(email string) error {
	// Find user by email
	var userID int64
	var isVerified bool
	var username string // Voeg username toe
	err := s.DB.QueryRow(`
        SELECT id, is_verified, username FROM users WHERE email = $1
    `, email).Scan(&userID, &isVerified, &username) // Scan nu ook username

	if err != nil {
		if err == sql.ErrNoRows {
			// Don't reveal if email exists or not
			return nil
		}
		return err
	}

	// Only allow password resets for verified accounts
	if !isVerified {
		return errors.New("account not verified")
	}

	// Generate reset token
	token := uuid.New().String()
	expiresAt := time.Now().Add(1 * time.Hour) // 1 hour expiration

	// Remove any existing tokens for this user
	_, err = s.DB.Exec(`
        DELETE FROM password_reset_tokens WHERE user_id = $1
    `, userID)
	if err != nil {
		return err
	}

	// Insert new token
	_, err = s.DB.Exec(`
        INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at)
        VALUES ($1, $2, $3, NOW())
    `, userID, token, expiresAt)
	if err != nil {
		return err
	}

	// Send password reset email
	return s.EmailService.SendPasswordResetEmail(email, username, token) // Nu met username
}

// ResetPassword changes a user's password using a reset token
func (s *AuthService) ResetPassword(token, newPassword string) error {
	// Find token
	var userID int64
	var expiresAt time.Time

	err := s.DB.QueryRow(`
        SELECT user_id, expires_at FROM password_reset_tokens
        WHERE token = $1
    `, token).Scan(&userID, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("invalid or expired reset token")
		}
		return err
	}

	// Check if token is expired
	if time.Now().After(expiresAt) {
		return errors.New("reset token has expired")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password
	_, err = s.DB.Exec(`
        UPDATE users SET password_hash = $1, updated_at = NOW()
        WHERE id = $2
    `, string(hashedPassword), userID)
	if err != nil {
		return err
	}

	// Delete used token
	_, err = s.DB.Exec(`
        DELETE FROM password_reset_tokens
        WHERE token = $1
    `, token)

	return err
}

// CreateVerificationToken maakt een nieuw verificatie token aan voor een gebruiker
func (s *AuthService) CreateVerificationToken(email string) (string, error) {
	// Haal user ID op
	var userID int64
	var username string

	err := s.DB.QueryRow("SELECT id, username FROM users WHERE email = $1", email).Scan(&userID, &username)
	if err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	// Begin een transactie
	tx, err := s.DB.Begin()
	if err != nil {
		return "", fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Genereer een random token
	token := generateRandomToken()

	// Bereken vervaldatum (24 uur vanaf nu)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Verwijder eventueel eerdere tokens voor deze gebruiker
	_, err = tx.Exec("DELETE FROM verification_tokens WHERE user_id = $1", userID)
	if err != nil {
		return "", fmt.Errorf("failed to remove old tokens: %w", err)
	}

	// Sla het nieuwe token op
	_, err = tx.Exec(
		"INSERT INTO verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
		userID, token, expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("failed to store verification token: %w", err)
	}

	// Commit de transactie
	err = tx.Commit()
	if err != nil {
		return "", fmt.Errorf("could not commit transaction: %w", err)
	}

	return token, nil
}
