package main

import (
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/handlers"
	"go-auth-api/internal/middleware"
	"log"
	"net/http" // Necessário para http.StatusOK

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
	// Permitir origens específicas ou usar AllowAllOrigins para desenvolvimento
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:3000", "http://localhost:5173", "http://localhost:8000"} // Adicione as origens do seu frontend
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = append(corsConfig.AllowHeaders, "Authorization", "X-API-Key") // Garantir que headers customizados são permitidos
	r.Use(cors.New(corsConfig))


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
			auth.GET("/verify-email/:token", handlers.VerifyEmail) // Rota de verificação
			auth.POST("/forgot-password", handlers.ForgotPassword) // <-- NOVA ROTA
			auth.POST("/reset-password", handlers.ResetPassword)
			auth.POST("/refresh", handlers.RefreshToken) // <-- NOVA ROTA

			// (Faltando: refresh, forgot-password, reset-password)

			// Protegidas (requerem JWT válido via AuthMiddleware)
			authProtected := auth.Group("/")
			authProtected.Use(middleware.AuthMiddleware())
			{
				authProtected.GET("/me", handlers.ReadUserMe)
				authProtected.POST("/mfa/enable", handlers.EnableMFAStart)     // <-- NOVA ROTA PROTEGIDA
				authProtected.POST("/mfa/confirm", handlers.EnableMFAConfirm)   // <-- NOVA ROTA PROTEGIDA
				authProtected.POST("/mfa/disable", handlers.DisableMFA)
			}
		}

		// --- User Routes (Públicas e Protegidas) ---
		users := apiV1.Group("/users")
		{
			// Pública
			users.POST("/", handlers.CreateUser)

			// Protegidas por Admin (AuthMiddleware + AdminMiddleware)
			adminProtected := users.Group("/")
			adminProtected.Use(middleware.AuthMiddleware(), middleware.AdminMiddleware())
			{
				adminProtected.GET("/", handlers.ReadUsers)
				adminProtected.GET("/:user_id", handlers.ReadUserByID) // Rota para buscar por ID
			}

			// Protegidas por Utilizador Logado (Apenas AuthMiddleware)
			userProtected := users.Group("/")
			userProtected.Use(middleware.AuthMiddleware())
			{
				userProtected.PUT("/me", handlers.UpdateUserMe) // Rota para atualizar próprio utilizador
			}
		}

		// --- Management Routes (Protegidas por API Key via MgmtMiddleware) ---
		mgmt := apiV1.Group("/mgmt")
		mgmt.Use(middleware.MgmtMiddleware())
		{
			mgmt.PATCH("/users/:user_id_or_email/claims", handlers.UpdateUserClaims)
		}
	}

	// Rota Raiz
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Auth API (Go) is running!"})
	})

	// 6. Rodar o Servidor
	port := "8001" // Pode vir da config se desejar
	log.Printf("Servidor Go rodando na porta %s...", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Falha ao iniciar o servidor: %v", err)
	}
}