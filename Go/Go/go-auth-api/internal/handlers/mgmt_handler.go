package handlers

import (
	"encoding/json"
	"errors"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"go-auth-api/internal/schemas"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// @Summary      Update user claims (Management)
// @Description  Updates (merges) custom claims for a user identified by ID or email. Requires X-API-Key.
// @Tags         Management
// @Accept       json
// @Produce      json
// @Param        user_id_or_email path string true "User ID or Email"
// @Param        claims body map[string]interface{} true "Claims to merge"
// @Success      200 {object} schemas.UserResponse "User claims updated successfully"
// @Failure      401 {object} map[string]string "Unauthorized (Invalid API Key)"
// @Failure      404 {object} map[string]string "User not found"
// @Failure      422 {object} map[string]string "Invalid input data"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     ApiKeyAuth
// @Router       /mgmt/users/{user_id_or_email}/claims [patch]
func UpdateUserClaims(c *gin.Context) {
	userIDOrEmail := c.Param("user_id_or_email")
	
	var claimsIn map[string]interface{}
	if err := c.ShouldBindJSON(&claimsIn); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	db := database.DB
	var user models.User

	// Encontrar usuário (lógica de get_user_by_id_or_email)
	if userID, err := strconv.Atoi(userIDOrEmail); err == nil {
		// É um ID
		if err := db.First(&user, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"detail": "User not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error"})
			return
		}
	} else {
		// É um email
		if err := db.Where("email = ?", userIDOrEmail).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"detail": "User not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Database error"})
			return
		}
	}

	// Mesclar claims
	var existingClaims map[string]interface{}
	if user.CustomClaims != nil && len(user.CustomClaims) > 0 {
		// Tentar desempacotar JSON existente
		if err := json.Unmarshal(user.CustomClaims, &existingClaims); err != nil {
			// Se o JSON existente for inválido (ex: "null" ou "{}"), começar do zero
			existingClaims = make(map[string]interface{})
		}
	} else {
		existingClaims = make(map[string]interface{})
	}

	for k, v := range claimsIn {
		existingClaims[k] = v
	}
	
	newClaimsJSON, err := json.Marshal(existingClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error processing claims"})
		return
	}

	user.CustomClaims = datatypes.JSON(newClaimsJSON)
	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error saving user"})
		return
	}
	
	c.JSON(http.StatusOK, schemas.FormatUserResponse(&user))
}