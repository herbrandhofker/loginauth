package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"loginauth/internal/auth"
	"loginauth/internal/database"
	"loginauth/internal/models"
	"loginauth/internal/oauth"
)

func main() {
	// Kill eventuele processen die poort 8082 gebruiken
	killProcessOnPort("8082")

	// Laad .env bestand
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Initialiseer database
	db, err := database.InitDatabase()
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	// Update database schema
	if err := database.UpdateUserTables(db); err != nil {
		log.Fatalf("Failed to update user tables: %v", err)
	}

	// Initialize services
	emailService := auth.NewEmailService()
	authService := auth.NewAuthService(db, emailService)
	googleProvider := oauth.NewGoogleProvider(db, authService)
	authHandler := auth.NewAuthHandler(authService, googleProvider)

	// Set up HTTP routes
	// Auth routes
	http.HandleFunc("/register", authHandler.RegisterHandler)
	http.HandleFunc("/login", authHandler.LoginHandler)
	http.HandleFunc("/logout", authHandler.LogoutHandler)
	http.HandleFunc("/verify-email", authHandler.VerifyEmailHandler)
	http.HandleFunc("/forgot-password", authHandler.ForgotPasswordHandler)
	http.HandleFunc("/reset-password", authHandler.ResetPasswordHandler)
	http.HandleFunc("/auth/google", authHandler.GoogleLoginHandler)
	http.HandleFunc("/auth/google/callback", authHandler.GoogleCallbackHandler)

	// Protected routes
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/dashboard", dashboardHandler)
	http.Handle("/dashboard", authHandler.AuthMiddleware(protectedMux))

	// Public routes
	http.HandleFunc("/", homeHandler)

	// Static files
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Debug static files
	http.HandleFunc("/debug-static", func(w http.ResponseWriter, r *http.Request) {
		// Controleer of CSS-bestand bestaat
		_, err := os.Stat("./static/css/output.css")
		if err != nil {
			fmt.Fprintf(w, "CSS file error: %v", err)
			return
		}

		fmt.Fprintf(w, "Static files should be working. CSS file exists.")
	})

	// Start server
	port := "8082" // Verander naar een andere poort
	fmt.Printf("Server starting on http://localhost:%s\n", port)
	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func killProcessOnPort(port string) {
	fmt.Printf("Controleren of poort %s al in gebruik is...\n", port)

	cmd := exec.Command("cmd", "/c", fmt.Sprintf("netstat -ano | findstr :%s", port))
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Geen proces gevonden of commando mislukt
		fmt.Println("Geen bestaand proces gevonden op deze poort.")
		return
	}

	// Parse output om PID te vinden
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTENING") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				pid := fields[4]
				fmt.Printf("Beëindigen van proces met PID %s op poort %s\n", pid, port)
				killCmd := exec.Command("taskkill", "/F", "/PID", pid)
				err := killCmd.Run()
				if err != nil {
					fmt.Printf("Kon proces niet beëindigen: %v\n", err)
				} else {
					fmt.Printf("Proces succesvol beëindigd\n")
					// Wacht even om het OS tijd te geven de poort vrij te geven
					time.Sleep(500 * time.Millisecond)
				}
				break
			}
		}
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Bescherm tegen andere paden die beginnen met "/"
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Haal alle bedrijfsgegevens op uit environment
	companyName := getEnvWithDefault("COMPANY_NAME", "LoginAuth")
	companySlogan := getEnvWithDefault("COMPANY_SLOGAN", "A simple authentication system")
	companyVAT := getEnvWithDefault("COMPANY_VAT", "")
	companyAddress := getEnvWithDefault("COMPANY_ADDRESS", "")
	companyZip := getEnvWithDefault("COMPANY_ZIP", "")
	companyCity := getEnvWithDefault("COMPANY_CITY", "")
	companyPhone := getEnvWithDefault("COMPANY_PHONE", "")
	companyEmail := getEnvWithDefault("COMPANY_EMAIL", "")

	// Bereid template data voor
	data := struct {
		CompanyName    string
		CompanySlogan  string
		CompanyVAT     string
		CompanyAddress string
		CompanyZip     string
		CompanyCity    string
		CompanyPhone   string
		CompanyEmail   string
		CurrentYear    int
	}{
		CompanyName:    companyName,
		CompanySlogan:  companySlogan,
		CompanyVAT:     companyVAT,
		CompanyAddress: companyAddress,
		CompanyZip:     companyZip,
		CompanyCity:    companyCity,
		CompanyPhone:   companyPhone,
		CompanyEmail:   companyEmail,
		CurrentYear:    time.Now().Year(),
	}

	// Parse en render template
	tmpl := template.New("index.html")

	// Parse de templates en geef de footer een naam
	tmpl, err := tmpl.ParseFiles(
		"templates/index.html",
		"templates/partials/footer.html",
	)

	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Definieer de footer met een naam die je kunt gebruiken
	_, err = tmpl.New("footer").ParseFiles("templates/partials/footer.html")
	if err != nil {
		http.Error(w, "Error loading footer template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Helper functie voor environment variabelen met default waarde
func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user, ok := r.Context().Value("user").(*models.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Render dashboard with user info
	fmt.Fprintf(w, "Welcome to your dashboard, %s!", user.Username)
}
