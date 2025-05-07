package main

import (
	"fmt"
	"log"
	"loginauth/internal/database"

	"github.com/joho/godotenv"
)

func main() {
	// Laad .env bestand
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Initialiseer database
	if err := database.InitDatabase(); err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	fmt.Println("Server starting...")

	// Hier start je je webserver/applicatie
	// ...
}
