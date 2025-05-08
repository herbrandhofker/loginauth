package auth

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url" // Nieuw voor url.QueryEscape
	"os"      // Nieuw voor os.Getenv
	"time"

	"loginauth/internal/interfaces"
)

type AuthHandler struct {
	AuthService    *AuthService
	GoogleProvider interfaces.OAuthProvider
}

func NewAuthHandler(authService *AuthService, googleProvider interfaces.OAuthProvider) *AuthHandler {
	return &AuthHandler{
		AuthService:    authService,
		GoogleProvider: googleProvider,
	}
}

// RegisterHandler handles user registration
func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Debug info
	fmt.Printf("RegisterHandler called with method: %s\n", r.Method)

	if r.Method == http.MethodGet {
		// Template data met bedrijfsgegevens
		data := map[string]interface{}{
			"CompanyName":   h.getEnvDefault("COMPANY_NAME", "LoginAuth"),
			"CompanySlogan": h.getEnvDefault("COMPANY_SLOGAN", "A simple authentication system"),
			"CompanyEmail":  h.getEnvDefault("COMPANY_EMAIL", ""),
			"CurrentYear":   time.Now().Year(),
			"Error":         "", // Zorg dat Error altijd gedefinieerd is
		}

		tmpl, err := template.ParseFiles(
			"templates/register.html",
			"templates/partials/footer.html", // Correcte path naar footer
		)
		if err != nil {
			http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Voeg cache headers toe om te voorkomen dat de browser de pagina cachet
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
		}
	} else if r.Method == http.MethodPost {
		fmt.Println("Processing POST register")
		// Parse formulierdata
		err := r.ParseForm()
		if err != nil {
			fmt.Printf("Form parse error: %v\n", err)
			h.renderError(w, r, "Ongeldige formuliergegevens", http.StatusBadRequest)
			return
		}

		// Haal formulierwaarden op
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		fmt.Printf("Form values: username=%s, email=%s, password=[HIDDEN]\n", username, email)

		// Valideer invoer (alleen op lege velden, niet meer op matching passwords)
		if username == "" || email == "" || password == "" {
			fmt.Println("Validation failed: empty fields")
			h.renderError(w, r, "Alle velden zijn verplicht", http.StatusBadRequest)
			return
		}

		// Poging om gebruiker te registreren
		fmt.Println("Attempting to register user")
		err = h.AuthService.RegisterUser(username, email, password)
		if err != nil {
			fmt.Printf("Registration failed: %v\n", err)

			// Check voor specifieke fouten
			if err.Error() == "email already exists" {
				h.renderError(w, r, "Dit e-mailadres is al geregistreerd", http.StatusConflict)
				return
			}

			h.renderError(w, r, "Registratie mislukt: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Geslaagde registratie - redirect
		fmt.Println("Registration successful, redirecting to login")

		// URL met email coderen voor veilig doorgeven
		emailParam := url.QueryEscape(email)

		// Voor HTMX requests
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login?registered=true&email="+emailParam)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Voor reguliere form submits
		http.Redirect(w, r, "/login?registered=true&email="+emailParam, http.StatusSeeOther)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// LoginHandler handles user login
func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Template data met bedrijfsgegevens
		data := map[string]interface{}{
			"CompanyName":   h.getEnvDefault("COMPANY_NAME", "LoginAuth"),
			"CompanySlogan": h.getEnvDefault("COMPANY_SLOGAN", "A simple authentication system"),
			"CompanyEmail":  h.getEnvDefault("COMPANY_EMAIL", ""),
			"CurrentYear":   time.Now().Year(),
			"Registered":    r.URL.Query().Get("registered") == "true",
			"Email":         r.URL.Query().Get("email"), // Haal email uit URL params
		}

		tmpl, err := template.ParseFiles(
			"templates/login.html",
			"templates/partials/footer.html",
		)
		if err != nil {
			http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
		}
	} else if r.Method == http.MethodPost {
		// Login logica
		// ...
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// GoogleLoginHandler initiates Google OAuth flow
func (h *AuthHandler) GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate a state token to prevent CSRF
	state := generateRandomState()

	// Store state in cookie for validation
	stateCookie := http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Expires:  time.Now().Add(15 * time.Minute),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	}
	http.SetCookie(w, &stateCookie)

	// Redirect to Google's OAuth page
	authURL := h.GoogleProvider.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleCallbackHandler processes the Google OAuth callback
func (h *AuthHandler) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Validate state to prevent CSRF
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})

	// Get the code from the callback
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	// Exchange code for session
	session, err := h.GoogleProvider.HandleCallback(code)
	if err != nil {
		http.Error(w, "Failed to complete OAuth flow: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set session cookie
	cookie := http.Cookie{
		Name:     "session_token",
		Value:    session.Token,
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	}
	http.SetCookie(w, &cookie)

	// Redirect to home page or dashboard
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler handles user logout
func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// VerifyEmailHandler handles email verification
func (h *AuthHandler) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "No token provided", http.StatusBadRequest)
		return
	}

	err := h.AuthService.VerifyEmail(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Render verification success page
	http.ServeFile(w, r, "templates/verify-email.html")
}

// ForgotPasswordHandler handles password reset requests
func (h *AuthHandler) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Display forgot password form
		http.ServeFile(w, r, "templates/forgot-password.html")
		return
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		if email == "" {
			http.Error(w, "Email is required", http.StatusBadRequest)
			return
		}

		err := h.AuthService.RequestPasswordReset(email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Always show success even if email doesn't exist (for security)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If your email is registered, you will receive password reset instructions",
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// ResetPasswordHandler handles the password reset form and submission
func (h *AuthHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "No token provided", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		// Display reset password form
		data := struct {
			Token string
		}{
			Token: token,
		}
		tmpl, _ := template.ParseFiles("templates/reset-password.html")
		tmpl.Execute(w, data)
		return
	}

	if r.Method == http.MethodPost {
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		if password == "" {
			http.Error(w, "Password is required", http.StatusBadRequest)
			return
		}

		if password != confirmPassword {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		err := h.AuthService.ResetPassword(token, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Redirect to login page with success message
		http.Redirect(w, r, "/login?reset=success", http.StatusFound)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// generateRandomState generates a random state string for OAuth CSRF protection
func generateRandomState() string {
	// In a real app, use a secure random generator
	return "state" + time.Now().String()
}

// Helper functions for the handler
func (h *AuthHandler) getEnvDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// renderError is een methode van AuthHandler voor consistente foutafhandeling
func (h *AuthHandler) renderError(w http.ResponseWriter, r *http.Request, message string, statusCode int) {
	fmt.Printf("Error: %s (status: %d)\n", message, statusCode)

	isHtmx := r.Header.Get("HX-Request") == "true"

	if isHtmx {
		// Voor HTMX requests, stuur alleen het foutbericht HTML fragment
		w.Header().Set("Content-Type", "text/html")

		// Belangrijk: verwijder of wijzig Content-Type header niet na deze regel!

		// Statuscode kan 200 zijn voor HTMX om de swap uit te voeren
		w.WriteHeader(200) // WIJZIGING: gebruik altijd 200 OK voor HTMX

		errorHTML := fmt.Sprintf(`
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                %s
            </div>
        `, message)

		fmt.Println("Stuur HTMX error response:", errorHTML)
		w.Write([]byte(errorHTML))
		return
	}

	// Voor normale requests, toon de hele pagina opnieuw met een fout
	data := map[string]interface{}{
		"CompanyName":   h.getEnvDefault("COMPANY_NAME", "LoginAuth"),
		"CompanySlogan": h.getEnvDefault("COMPANY_SLOGAN", "A simple authentication system"),
		"CompanyEmail":  h.getEnvDefault("COMPANY_EMAIL", ""),
		"CurrentYear":   time.Now().Year(),
		"Error":         message,
	}

	fmt.Printf("Rendering register template with error: %s\n", message)

	tmpl, err := template.ParseFiles(
		"templates/register.html",
		"templates/partials/footer.html",
	)
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(statusCode)
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}
