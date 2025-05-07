package auth

import (
    "context"
    "net/http"
)

// AuthMiddleware creates middleware to protect routes
func (h *AuthHandler) AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get session cookie
        cookie, err := r.Cookie("session_token")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }

        // Validate session
        user, err := h.AuthService.GetUserBySession(cookie.Value)
        if err != nil {
            // Clear invalid cookie
            http.SetCookie(w, &http.Cookie{
                Name:     "session_token",
                Value:    "",
                MaxAge:   -1,
                Path:     "/",
                HttpOnly: true,
            })
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }

        // Set user in request context
        ctx := context.WithValue(r.Context(), "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}