package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"loginauth/internal/interfaces"
	"loginauth/internal/models"
)

// GoogleProvider implements OAuth for Google
type GoogleProvider struct {
	config         *oauth2.Config
	db             *sql.DB
	sessionCreator interfaces.SessionCreator
}

// GoogleUser represents the user info from Google
type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// NewGoogleProvider creates a new Google OAuth provider
func NewGoogleProvider(db *sql.DB, sessionCreator interfaces.SessionCreator) *GoogleProvider {
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
		db:             db,
		sessionCreator: sessionCreator,
	}
}

// GetAuthURL returns the URL to redirect the user to for authentication
func (p *GoogleProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// HandleCallback processes the OAuth callback
func (p *GoogleProvider) HandleCallback(code string) (*models.Session, error) {
	// Exchange code for token
	token, err := p.config.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	// Get user info from Google
	googleUser, err := p.getUserInfo(token.AccessToken)
	if err != nil {
		return nil, err
	}

	// Find or create user in database
	var userID int64
	err = p.db.QueryRow(`
        SELECT id FROM users WHERE google_id = $1
    `, googleUser.ID).Scan(&userID)

	if err == sql.ErrNoRows {
		// User doesn't exist, create a new one
		err = p.db.QueryRow(`
            INSERT INTO users (username, email, google_id, is_verified, created_at, updated_at)
            VALUES ($1, $2, $3, TRUE, NOW(), NOW())
            RETURNING id
        `, googleUser.Name, googleUser.Email, googleUser.ID).Scan(&userID)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	// Create a session using the SessionCreator interface
	return p.sessionCreator.CreateSession(userID)
}

// getUserInfo fetches the user information from Google API
func (p *GoogleProvider) getUserInfo(accessToken string) (*GoogleUser, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user GoogleUser
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}
