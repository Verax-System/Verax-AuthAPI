package handlers

import (
	"errors"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"go-auth-api/internal/schemas"
	"go-auth-api/internal/services"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// CreateUser (porta de create_user)
func CreateUser(c *gin.Context) {
	var input schemas.UserCreate
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	db := database.DB
	// Verificar se o usuário já existe
	var existingUser models.User
	if err := db.Where("email = ?", input.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "The user with this email already exists."})
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error"})
		return
	}

	// Hash da senha
	hashedPassword, err := services.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error hashing password"})
		return
	}

	// Gerar token de verificação (aqui estamos simplificando, 
	// idealmente o serviço faria isso)
	// (Lógica de token de verificação omitida para brevidade - deve ser adicionada)
	// verificationToken := "..."
	
	newUser := models.User{
		Email:          input.Email,
		HashedPassword: &hashedPassword,
		FullName:       &input.FullName,
		IsActive:       false, // Inativo até verificar email
		IsVerified:     false,
	}

	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not create user"})
		return
	}

	// Enviar email de verificação
	// services.SendVerificationEmail(newUser.Email, verificationToken)
	log.Printf("TODO: Enviar email de verificação para %s", newUser.Email)

	c.JSON(http.StatusCreated, schemas.FormatUserResponse(&newUser))
}

// ReadUsers (porta de read_users - protegido por AdminMiddleware na rota)
func ReadUsers(c *gin.Context) {
	var users []models.User
	db := database.DB
	
	// (Query params skip/limit omitidos para brevidade)
	if err := db.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error"})
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
	user, _ := c.Get("currentUser") // Sabemos que existe por causa do middleware
	
	c.JSON(http.StatusOK, schemas.FormatUserResponse(user.(*models.User)))
}