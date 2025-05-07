package interfaces

import (
    "loginauth/internal/models"
)

// OAuthProvider defines methods that any OAuth provider must implement
type OAuthProvider interface {
    GetAuthURL(state string) string
    HandleCallback(code string) (*models.Session, error)
}

// SessionCreator defines the method to create a new session
type SessionCreator interface {
    CreateSession(userID int64) (*models.Session, error)
}