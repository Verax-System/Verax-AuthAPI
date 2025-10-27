package handlers

import (
	"crypto/rand" // Para gerar o token
	"encoding/hex" // Para converter o token para string
	"errors"
	"fmt" // Para formatar o erro
	"go-auth-api/internal/config" // Importar config
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"go-auth-api/internal/schemas"
	"go-auth-api/internal/services"
	"log"
	"net/http"
	"time" // Para a expiração do token

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Função auxiliar para gerar um token seguro
func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}


// CreateUser (porta de create_user)
func CreateUser(c *gin.Context) {
	var input schemas.UserCreate
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	db := database.DB
	// Verificar se o utilizador já existe
	var existingUser models.User
	if err := db.Where("email = ?", input.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "The user with this email already exists."})
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Printf("Erro DB ao verificar existência do utilizador: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error checking user existence"})
		return
	}

	// Hash da senha
	hashedPassword, err := services.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error hashing password"})
		return
	}

	// --- Geração do Token de Verificação ---
	verificationTokenPlain, err := generateSecureToken(32) // Gera 64 caracteres hex
	if err != nil {
		log.Printf("Erro ao gerar token de verificação: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not generate verification token"})
		return
	}
	verificationTokenHash := services.HashToken(verificationTokenPlain) // Usar a mesma função de hash dos refresh tokens

	expiresAt := time.Now().UTC().Add(config.AppConfig.EmailVerifyTokenMinutes)
	// --- Fim Geração Token ---

	newUser := models.User{
		Email:                      input.Email,
		HashedPassword:             &hashedPassword,
		FullName:                   &input.FullName,
		IsActive:                   false, // Inativo até verificar email
		IsVerified:                 false,
		VerificationTokenHash:      &verificationTokenHash, // Guardar o hash
		VerificationTokenExpires:   &expiresAt,            // Guardar a expiração
		CustomClaims:               []byte("{}"), // Inicializar claims como JSON vazio
	}

	if err := db.Create(&newUser).Error; err != nil {
		log.Printf("Erro ao criar utilizador no DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not create user"})
		return
	}

	// Enviar email de verificação em background
	go services.SendVerificationEmail(newUser.Email, verificationTokenPlain) // Enviar o token em texto simples
	log.Printf("Utilizador criado (ID: %d). Email de verificação enviado (em background) para %s", newUser.ID, newUser.Email)


	c.JSON(http.StatusCreated, schemas.FormatUserResponse(&newUser))
}

// ReadUsers (porta de read_users - protegido por AdminMiddleware na rota)
func ReadUsers(c *gin.Context) {
	var users []models.User
	db := database.DB

	// (Query params skip/limit omitidos para brevidade)
	if err := db.Find(&users).Error; err != nil {
		log.Printf("Erro DB ao ler utilizadores: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error reading users"})
		return
	}

	responseUsers := make([]schemas.UserResponse, len(users))
	for i, user := range users {
		responseUsers[i] = schemas.FormatUserResponse(&user)
	}

	c.JSON(http.StatusOK, responseUsers)
}

// ReadUserMe (porta de read_users_me - protegido por AuthMiddleware na rota)
func ReadUserMe(c *gin.Context) {
	userInterface, exists := c.Get("currentUser")
	// Esta verificação é redundante se o AuthMiddleware sempre definir, mas boa prática
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "User not found in context"})
		return
	}
	user, ok := userInterface.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Invalid user type in context"})
		return
	}

	c.JSON(http.StatusOK, schemas.FormatUserResponse(user))
}

// ReadUserByID (protegido por AdminMiddleware na rota)
func ReadUserByID(c *gin.Context) {
	userID := c.Param("user_id") // Gin pega parâmetros da rota assim

	db := database.DB
	var user models.User

	// Tenta buscar por ID
	if err := db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"detail": "User not found"})
			return
		}
		log.Printf("Erro DB ao buscar utilizador por ID %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error fetching user"})
		return
	}

	c.JSON(http.StatusOK, schemas.FormatUserResponse(&user))
}

// UpdateUserMe (protegido por AuthMiddleware na rota)
func UpdateUserMe(c *gin.Context) {
	var input schemas.UserUpdate // Usar um schema de update
	if err := c.ShouldBindJSON(&input); err != nil {
		// Retorna 422 se a validação do schema falhar (ex: email inválido)
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": fmt.Sprintf("Validation error: %v", err)})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)
	db := database.DB

	// Atualizar campos permitidos
	updated := false
	if input.FullName != nil && *input.FullName != *currentUser.FullName { // Verificar se houve mudança real
		currentUser.FullName = input.FullName
		updated = true
	}

	// Lógica para atualizar senha (se fornecida e válida)
	if input.Password != nil && *input.Password != "" {
		// TODO: Adicionar validação de força da senha aqui (similar ao Python)
		// if !isPasswordStrongEnough(*input.Password) {
		// 	c.JSON(http.StatusBadRequest, gin.H{"detail": "Password does not meet strength requirements."})
		//  return
		// }

		newHashedPassword, err := services.HashPassword(*input.Password)
		if err != nil {
			log.Printf("Erro ao fazer hash da nova senha para o utilizador ID %d: %v", currentUser.ID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error updating password"})
			return
		}
		// Verificar se o hash é diferente do antigo para evitar saves desnecessários
		if currentUser.HashedPassword == nil || newHashedPassword != *currentUser.HashedPassword {
			currentUser.HashedPassword = &newHashedPassword
			updated = true
			log.Printf("Senha atualizada para o utilizador ID: %d", currentUser.ID)
			// TODO: Idealmente, revogar todos os refresh tokens existentes aqui
			// revokedCount, err := services.RevokeAllRefreshTokensForUser(currentUser.ID, "")
		}
	}


	// Lógica para atualizar email (se fornecido, válido e diferente)
	if input.Email != nil && *input.Email != currentUser.Email {
		// Verificar se o novo email já existe
		var existingUser models.User
		if err := db.Where("email = ? AND id != ?", *input.Email, currentUser.ID).First(&existingUser).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Email already registered by another user."})
			return
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Erro DB ao verificar duplicidade de email para %s: %v", *input.Email, err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error checking email"})
			return
		}

		// Atualizar email e marcar como não verificado
		currentUser.Email = *input.Email
		currentUser.IsVerified = false
		currentUser.VerificationTokenHash = nil // Limpar tokens antigos
		currentUser.VerificationTokenExpires = nil

		// Gerar novo token de verificação
		verificationTokenPlain, err := generateSecureToken(32)
		if err != nil {
			log.Printf("Erro ao gerar token de verificação para novo email: %v", err)
			// Continua mesmo assim, mas loga o erro
		} else {
			verificationTokenHash := services.HashToken(verificationTokenPlain)
			expiresAt := time.Now().UTC().Add(config.AppConfig.EmailVerifyTokenMinutes)
			currentUser.VerificationTokenHash = &verificationTokenHash
			currentUser.VerificationTokenExpires = &expiresAt

			// Enviar email de verificação para o NOVO endereço
			go services.SendVerificationEmail(currentUser.Email, verificationTokenPlain)
			log.Printf("Email atualizado para %s (utilizador ID: %d). Novo email de verificação enviado.", currentUser.Email, currentUser.ID)
		}
		updated = true
	}


	if !updated {
		c.JSON(http.StatusOK, schemas.FormatUserResponse(currentUser)) // Nenhuma mudança
		return
	}

	// Salvar mudanças
	if err := db.Save(&currentUser).Error; err != nil {
		log.Printf("Erro ao salvar atualizações do utilizador ID %d: %v", currentUser.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error saving user updates"})
		return
	}

	c.JSON(http.StatusOK, schemas.FormatUserResponse(currentUser))
}