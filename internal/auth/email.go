package auth

import (
	"fmt"
	"net/smtp"
	"os"
)

type EmailService struct {
	host     string
	port     string
	username string
	password string
	from     string
	appURL   string
}

func NewEmailService() *EmailService {
	return &EmailService{
		host:     os.Getenv("EMAIL_HOST"),
		port:     os.Getenv("EMAIL_PORT"),
		username: os.Getenv("EMAIL_USER"),
		password: os.Getenv("EMAIL_PASSWORD"),
		from:     os.Getenv("EMAIL_FROM"),
		appURL:   os.Getenv("APP_URL"),
	}
}

// SendVerificationEmail sends an email with a verification link
func (s *EmailService) SendVerificationEmail(to, token string) error {
	subject := "Verify your account"
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.appURL, token)

	htmlBody := fmt.Sprintf(`
    <html>
    <head>
        <style>
            .container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
            .button { background-color: #4CAF50; border: none; color: white; padding: 15px 32px; 
                      text-align: center; text-decoration: none; display: inline-block; font-size: 16px; 
                      margin: 4px 2px; cursor: pointer; border-radius: 4px; }
            .footer { font-size: 12px; color: #777; margin-top: 30px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Welcome to LoginAuth!</h2>
            <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
            <p><a href="%s" class="button">Verify Email Address</a></p>
            <p>Or copy and paste this link in your browser:</p>
            <p>%s</p>
            <div class="footer">
                <p>If you did not create this account, please ignore this email.</p>
            </div>
        </div>
    </body>
    </html>
    `, verificationURL, verificationURL)

	return s.sendEmail(to, subject, htmlBody)
}

// SendPasswordResetEmail sends an email with password reset link
func (s *EmailService) SendPasswordResetEmail(to, token string) error {
	subject := "Reset your password"
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.appURL, token)

	htmlBody := fmt.Sprintf(`
    <html>
    <head>
        <style>
            .container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
            .button { background-color: #2196F3; border: none; color: white; padding: 15px 32px; 
                      text-align: center; text-decoration: none; display: inline-block; font-size: 16px; 
                      margin: 4px 2px; cursor: pointer; border-radius: 4px; }
            .footer { font-size: 12px; color: #777; margin-top: 30px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p><a href="%s" class="button">Reset Password</a></p>
            <p>Or copy and paste this link in your browser:</p>
            <p>%s</p>
            <div class="footer">
                <p>If you did not request a password reset, please ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
            </div>
        </div>
    </body>
    </html>
    `, resetURL, resetURL)

	return s.sendEmail(to, subject, htmlBody)
}

// sendEmail sends an HTML email
func (s *EmailService) sendEmail(to, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%s", s.host, s.port)
	auth := smtp.PlainAuth("", s.username, s.password, s.host)

	headers := make(map[string]string)
	headers["From"] = s.from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	message := ""
	for key, value := range headers {
		message += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	message += "\r\n" + htmlBody

	return smtp.SendMail(
		addr,
		auth,
		s.from,
		[]string{to},
		[]byte(message),
	)
}
