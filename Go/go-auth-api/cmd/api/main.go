package main

import (
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/handlers"
	"go-auth-api/internal/middleware"
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// 1. Carregar Configuração
	config.LoadConfig()

	// 2. Iniciar Banco de Dados e Migrações
	database.InitDatabase()

	// 3. Iniciar Roteador Gin
	r := gin.Default()

	// 4. Configurar CORS (similar ao Python)
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-API-Key"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// 5. Definir Rotas
	apiV1 := r.Group("/api/v1")
	{
		// --- Auth Routes (Públicas e Protegidas) ---
		auth := apiV1.Group("/auth")
		{
			// Públicas
			auth.POST("/token", handlers.Login) // (Form-Data)
			auth.POST("/google/callback", handlers.GoogleCallback)
			auth.GET("/google/login-url", handlers.GetGoogleLoginURL)
			auth.POST("/mfa/verify", handlers.VerifyMFALogin)
			auth.POST("/mfa/verify-recovery", handlers.VerifyMFARecoveryLogin)
			auth.POST("/logout", handlers.Logout)
			// (Faltando: refresh, forgot-password, reset-password, verify-email)

			// Protegidas (requerem JWT válido)
			authProtected := auth.Group("/")
			authProtected.Use(middleware.AuthMiddleware())
			{
				authProtected.GET("/me", handlers.ReadUserMe)
				// (Faltando: mfa/enable, mfa/confirm, mfa/disable)
				// (Faltando: sessions, sessions/all, sessions/{id})
				// (Faltando: devices, devices/{id})
			}
		}

		// --- User Routes (Públicas e Protegidas) ---
		users := apiV1.Group("/users")
		{
			// Pública
			users.POST("/", handlers.CreateUser)
			
			// Protegidas por Admin
			users.GET("/", middleware.AuthMiddleware(), middleware.AdminMiddleware(), handlers.ReadUsers)
			// (Faltando: GET /{user_id})
		}
		
		// --- Management Routes (Protegidas por API Key) ---
		mgmt := apiV1.Group("/mgmt")
		mgmt.Use(middleware.MgmtMiddleware())
		{
			mgmt.PATCH("/users/:user_id_or_email/claims", handlers.UpdateUserClaims)
		}
	}
	
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Auth API (Go) is running!"})
	})


	// 6. Rodar o Servidor
	log.Println("Servidor Go rodando na porta 8001...")
	if err := r.Run(":8001"); err != nil {
		log.Fatalf("Falha ao iniciar o servidor: %v", err)
	}
}