package auth

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
	"os"
)

// EmailService voor het versturen van emails
type EmailService struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
}

// NewEmailService maakt een nieuwe email service aan
func NewEmailService() *EmailService {
	// Log belangrijke configuratiedetails
	log.Println("Initializing email service...")
	log.Printf("SMTP Host: %s", os.Getenv("SMTP_HOST"))
	log.Printf("SMTP Port: %s", os.Getenv("SMTP_PORT"))
	log.Printf("SMTP User: %s", os.Getenv("SMTP_USER"))
	log.Printf("Using password: %t", os.Getenv("SMTP_PASSWORD") != "")

	return &EmailService{
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     os.Getenv("SMTP_PORT"),
		SMTPUsername: os.Getenv("SMTP_USER"), // Let op: gebruikt SMTP_USER, niet SMTP_USERNAME
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		FromEmail:    os.Getenv("EMAIL_FROM"),
	}
}

// SendVerificationEmail stuurt een email met een verificatielink
func (s *EmailService) SendVerificationEmail(toEmail, username, token string) error {
	subject := "Bevestig je email adres"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8082"
	}

	// Maak verificatie link
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", baseURL, token)

	// Opbouwen van eenvoudige HTML email
	htmlBody := fmt.Sprintf(`
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Email verificatie voor %s</h2>
            <p>Hallo %s,</p>
            <p>Bedankt voor je registratie. Klik op de onderstaande link om je email adres te bevestigen:</p>
            <p><a href="%s" style="display: inline-block; background-color: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Email bevestigen</a></p>
            <p>Of gebruik deze link: <a href="%s">%s</a></p>
            <p>Deze link verloopt na 24 uur.</p>
            <p>Met vriendelijke groet,<br>Het team van %s</p>
        </div>
    </body>
    </html>
    `, os.Getenv("COMPANY_NAME"), username, verificationLink, verificationLink, verificationLink, os.Getenv("COMPANY_NAME"))

	return s.sendEmail(toEmail, subject, htmlBody)
}

// sendEmail verstuurt een email met verbeterde error handling
func (s *EmailService) sendEmail(to, subject, body string) error {
	// Extra debugging
	log.Printf("Sending email to: %s", to)
	log.Printf("Using SMTP server: %s:%s", s.SMTPHost, s.SMTPPort)
	log.Printf("Authenticating with username: %s", s.SMTPUsername)

	// Als er geen SMTP configuratie is, log dan de mail voor debug
	if s.SMTPHost == "" || s.SMTPPassword == "" {
		log.Printf("SMTP not configured. Would send email with subject: %s", subject)
		return nil
	}

	// Freedom.nl specifieke setup
	addr := fmt.Sprintf("%s:%s", s.SMTPHost, s.SMTPPort)

	// Verbeterde SMTP met TLS
	// Create TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.SMTPHost,
	}

	// Connect to SMTP server
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial error: %w", err)
	}
	defer c.Close()

	// Start TLS
	if err = c.StartTLS(tlsconfig); err != nil {
		log.Printf("TLS start failed, trying without TLS: %v", err)
		// Als TLS mislukt, probeer zonder TLS (niet ideaal maar kan werken voor debug)
		c.Close()
		c, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("second SMTP dial error: %w", err)
		}
		defer c.Close()
	}

	// Authenticate with SMTP server
	auth := smtp.PlainAuth("", s.SMTPUsername, s.SMTPPassword, s.SMTPHost)
	if err = c.Auth(auth); err != nil {
		// Als authenticatie mislukt, probeer een andere methode voor Freedom.nl
		log.Printf("Standard authentication failed: %v", err)
		log.Printf("Trying alternative authentication...")

		// Probeer direct inloggen zonder TLS eerst
		c.Close()
		c, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("alternative SMTP dial error: %w", err)
		}
		defer c.Close()

		auth := smtp.PlainAuth("", s.SMTPUsername, s.SMTPPassword, s.SMTPHost)
		if err = c.Auth(auth); err != nil {
			return fmt.Errorf("all authentication methods failed: %w", err)
		}
	}

	// Set sender and recipient
	if err = c.Mail(s.FromEmail); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	if err = c.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	// Send email
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("failed to open email data writer: %w", err)
	}
	defer w.Close()

	// Compose headers and body
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", s.FromEmail, to, subject, body)

	if _, err = w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to write email: %w", err)
	}

	log.Println("Email sent successfully!")
	return nil
}

// SendPasswordResetEmail sends an email with password reset link
func (s *EmailService) SendPasswordResetEmail(toEmail, username, token string) error {
	subject := "Wachtwoord reset verzoek"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8082"
	}

	// Create reset link
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)

	// Build HTML email
	htmlBody := fmt.Sprintf(`
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Wachtwoord reset voor %s</h2>
            <p>Hallo %s,</p>
            <p>We hebben een verzoek ontvangen om je wachtwoord te resetten. Klik op de onderstaande link om een nieuw wachtwoord in te stellen:</p>
            <p><a href="%s" style="display: inline-block; background-color: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Wachtwoord resetten</a></p>
            <p>Of gebruik deze link: <a href="%s">%s</a></p>
            <p>Deze link verloopt na 24 uur. Als je geen wachtwoord reset hebt aangevraagd, kun je deze email negeren.</p>
            <p>Met vriendelijke groet,<br>Het team van %s</p>
        </div>
    </body>
    </html>
    `, os.Getenv("COMPANY_NAME"), username, resetLink, resetLink, resetLink, os.Getenv("COMPANY_NAME"))

	return s.sendEmail(toEmail, subject, htmlBody)
}
