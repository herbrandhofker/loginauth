# LoginAuth Project

A web application built with Golang, HTMX, PostgreSQL, and TailwindCSS featuring user authentication with both traditional login and Google OAuth.

## Tech Stack

- **Backend**: [Golang](https://golang.org/)
- **Frontend Interactivity**: [HTMX](https://htmx.org/)
- **Database**: [PostgreSQL](https://www.postgresql.org/)
- **CSS Framework**: [TailwindCSS](https://tailwindcss.com/)
- **Authentication**: Email/Password + Google OAuth
- **Email Service**: SMTP for account verification and password resets

## Features

- User registration with email verification
- Email and password login
- Google OAuth integration
- Session management
- Password reset functionality
- Protected routes
- Modern responsive UI with TailwindCSS
- HTMX for interactive experiences without writing JavaScript

## Project Setup

### Prerequisites

- Go 1.24+
- PostgreSQL
- Node.js and NPM

### Environment Configuration

This project uses environment variables for configuration. These should be stored in a `.env` file in the project root.

1. Copy the example environment file:

```bash
cp .env.example .env
```

## Development with Hot Reload

This project uses [Air](https://github.com/cosmtrek/air) for hot reloading during development.

### Setup

1. Install Air:

```bash
go install github.com/cosmtrek/air@latest
```
