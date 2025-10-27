package middleware

import (
	"encoding/json"
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Helper para respostas de erro
func abortWithError(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, gin.H{"detail": message})
}

// AuthMiddleware (porta de get_current_active_user)
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			abortWithError(c, http.StatusUnauthorized, "Could not validate credentials")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			abortWithError(c, http.StatusUnauthorized, "Invalid authorization scheme. Use 'Bearer'.")
			return
		}

		tokenString := parts[1]
		cfg := config.AppConfig
		
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.SecretKey), nil
		}, jwt.WithIssuer(cfg.JWTIssuer), jwt.WithAudience(cfg.JWTAudience))

		if err != nil || !token.Valid {
			abortWithError(c, http.StatusUnauthorized, "Could not validate credentials")
			return
		}

		// Buscar usuário
		var user models.User
		if err := database.DB.First(&user, "id = ?", claims.Subject).Error; err != nil {
			abortWithError(c, http.StatusUnauthorized, "Could not validate credentials")
			return
		}

		if !user.IsActive {
			abortWithError(c, http.StatusForbidden, "Inactive user")
			return
		}

		// Anexar o usuário (ou ID) ao contexto
		c.Set("currentUser", &user)
		c.Next()
	}
}

// AdminMiddleware (porta de get_current_admin_user)
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Este middleware DEVE rodar DEPOIS do AuthMiddleware
		userInterface, exists := c.Get("currentUser")
		if !exists {
			abortWithError(c, http.StatusUnauthorized, "Authentication required")
			return
		}
		
		user, ok := userInterface.(*models.User)
		if !ok {
			abortWithError(c, http.StatusInternalServerError, "Error processing user")
			return
		}

		// Verificar Custom Claims
		if user.CustomClaims == nil {
			abortWithError(c, http.StatusForbidden, "Not authorized. Requires administrator privileges.")
			return
		}

		var claimsMap map[string]interface{}
		if err := json.Unmarshal(user.CustomClaims, &claimsMap); err != nil {
			abortWithError(c, http.StatusForbidden, "Not authorized. Invalid claims.")
			return
		}

		rolesInterface, ok := claimsMap["roles"]
		if !ok {
			abortWithError(c, http.StatusForbidden, "Not authorized. No roles found.")
			return
		}

		roles, ok := rolesInterface.([]interface{})
		if !ok {
			abortWithError(c, http.StatusForbidden, "Not authorized. Invalid roles format.")
			return
		}

		isAdmin := false
		for _, roleInterface := range roles {
			if role, ok := roleInterface.(string); ok && role == "admin" {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			abortWithError(c, http.StatusForbidden, "Not authorized. Requires administrator privileges.")
			return
		}

		c.Next()
	}
}


// MgmtMiddleware (porta de get_api_key)
func MgmtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		cfg := config.AppConfig
		
		if cfg.InternalAPIKey == "" {
			abortWithError(c, http.StatusInternalServerError, "INTERNAL_API_KEY not configured on server")
			return
		}

		// (Em Go, a comparação de string simples é segura contra timing attacks)
		if apiKey != cfg.InternalAPIKey {
			abortWithError(c, http.StatusUnauthorized, "Invalid or missing API Key")
			return
		}
		
		c.Next()
	}
}