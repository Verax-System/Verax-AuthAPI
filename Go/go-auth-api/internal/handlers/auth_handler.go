package handlers

import (
	"errors"
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"go-auth-api/internal/schemas"
	"go-auth-api/internal/services"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

// Helper para obter IP/UserAgent
func getSessionDetails(c *gin.Context) (ip string, ua string) {
	ip = c.ClientIP()
	ua = c.Request.UserAgent()
	return
}

// Helper para criar tokens e salvar no DB
func createAndStoreTokens(c *gin.Context, user *models.User, mfaPassed bool) (schemas.TokenResponse, error) {
	db := database.DB
	
	// 1. Criar Access Token
	// (Lógica de Scopes omitida para brevidade)
	accessToken, err := services.CreateAccessToken(user, mfaPassed, nil)
	if err != nil {
		return schemas.TokenResponse{}, err
	}

	// 2. Criar Refresh Token
	refreshTokenString, expiresAt, err := services.CreateRefreshToken(user.ID)
	if err != nil {
		return schemas.TokenResponse{}, err
	}
	
	// 3. Armazenar Refresh Token
	ip, ua := getSessionDetails(c)
	refreshTokenHash := services.HashToken(refreshTokenString)
	
	dbToken := models.RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		ExpiresAt: expiresAt,
		IPAddress: &ip,
		UserAgent: &ua,
	}
	
	if err := db.Create(&dbToken).Error; err != nil {
		return schemas.TokenResponse{}, err
	}

	return schemas.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		TokenType:    "bearer",
	}, nil
}

// Helper para setar o cookie de device trust
func setTrustedDeviceCookie(c *gin.Context, user *models.User) (string, error) {
	db := database.DB
	cfg := config.AppConfig

	// (Lógica de crud_trusted_device.create_trusted_device)
	plainToken := "..." // (Gerar token seguro, ex: crypto/rand)
	tokenHash := services.HashToken(plainToken)
	ip, ua := getSessionDetails(c)
	
	dbDevice := models.TrustedDevice{
		UserID:          user.ID,
		DeviceTokenHash: tokenHash,
		IPAddress:       &ip,
		UserAgent:       &ua,
		Description:     &ua, // Simplificado
		LastUsedAt:      &time.Time{}, // (now)
	}

	if err := db.Create(&dbDevice).Error; err != nil {
		return "", err
	}

	c.SetCookie(
		cfg.CookieName,
		plainToken,
		int(cfg.TrustedDeviceCookieMaxAge.Seconds()),
		"/",
		"", // host
		true, // secure (mude para false em dev http)
		true, // httpOnly
	)
	
	return plainToken, nil
}


// Login (porta de login_for_access_token)
func Login(c *gin.Context) {
	var input schemas.LoginRequest
	// Usar ShouldBind() pois é form-data
	if err := c.ShouldBind(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Autenticar (porta de crud_user.authenticate)
	user, err := services.AuthenticateUser(input.Username, input.Password)
	if err != nil {
		if strings.Contains(err.Error(), "account locked") {
			c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// 2. Lógica de Device Trust
	isDeviceTrusted := false
	cookie, err := c.Cookie(config.AppConfig.CookieName)
	if err == nil && cookie != "" {
		tokenHash := services.HashToken(cookie)
		var trustedDevice models.TrustedDevice
		// (Porta de crud_trusted_device.get_trusted_device_by_token)
		if err := database.DB.Where("device_token_hash = ?", tokenHash).First(&trustedDevice).Error; err == nil {
			if trustedDevice.UserID == user.ID {
				isDeviceTrusted = true
				// (Atualizar last_used_at omitido)
			}
		}
	}

	// 3. Verificar se MFA é necessário
	if user.IsMfaEnabled && !isDeviceTrusted {
		mfaChallengeToken, err := services.CreateMFAChallengeToken(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not create MFA challenge"})
			return
		}
		
		// Retorna 200 OK com o challenge (como no Python)
		c.JSON(http.StatusOK, schemas.MFARequiredResponse{
			Detail:            "MFA verification required",
			MFAChallengeToken: mfaChallengeToken,
		})
		return
	}

	// 4. Login bem-sucedido (MFA não habilitado ou device confiável)
	tokenResponse, err := createAndStoreTokens(c, user, user.IsMfaEnabled) // mfa_passed=true se estava habilitado
	if err != nil {
		log.Printf("Erro ao criar tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	// (Cookie só é setado no /mfa/verify)
	c.JSON(http.StatusOK, tokenResponse)
}

// VerifyMFALogin (porta de verify_mfa_login)
func VerifyMFALogin(c *gin.Context) {
	var input schemas.MFAVerifyRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Validar challenge token
	userIDStr, err := services.ValidateMFAChallengeToken(input.MFAChallengeToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired MFA challenge token."})
		return
	}

	// 2. Encontrar usuário
	var user models.User
	if err := database.DB.First(&user, "id = ?", userIDStr).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid user"})
		return
	}
	
	if !user.IsMfaEnabled || user.OtpSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MFA is not enabled for this user."})
		return
	}

	// 3. Validar OTP
	if !services.ValidateOTP(*user.OtpSecret, input.OTPCode) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid OTP code."})
		return
	}

	// 4. Sucesso! Emitir tokens
	tokenResponse, err := createAndStoreTokens(c, &user, true) // mfa_passed=true
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	// 5. CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE
	// (Lógica omitida para brevidade, mas é aqui que setTrustedDeviceCookie(c, &user) seria chamado)
	log.Println("TODO: Setar cookie de dispositivo confiável")
	
	c.JSON(http.StatusOK, tokenResponse)
}

// VerifyMFARecoveryLogin (porta de verify_mfa_recovery_login)
func VerifyMFARecoveryLogin(c *gin.Context) {
	var input schemas.MFARecoveryRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Validar challenge token
	userIDStr, err := services.ValidateMFAChallengeToken(input.MFAChallengeToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired MFA challenge token."})
		return
	}
	
	// 2. Encontrar usuário
	var user models.User
	if err := database.DB.First(&user, "id = ?", userIDStr).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid user"})
		return
	}

	// 3. Validar Recovery Code (porta de crud_mfa_recovery_code.get_valid_recovery_code)
	var validCode models.MFARecoveryCode
	var foundCode bool = false
	
	var codes []models.MFARecoveryCode
	database.DB.Where("user_id = ? AND is_used = ?", user.ID, false).Find(&codes)

	for _, code := range codes {
		if services.VerifyRecoveryCode(input.RecoveryCode, code.HashedCode) {
			validCode = code
			foundCode = true
			break
		}
	}
	
	if !foundCode {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or used recovery code."})
		return
	}

	// 4. Marcar como usado
	validCode.IsUsed = true
	database.DB.Save(&validCode)

	// 5. Sucesso! Emitir tokens
	tokenResponse, err := createAndStoreTokens(c, &user, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}
	
	// 6. Setar cookie
	log.Println("TODO: Setar cookie de dispositivo confiável")
	
	c.JSON(http.StatusOK, tokenResponse)
}


// (Outros handlers - Logout, Refresh, EnableMFA, GoogleLogin, etc. - seriam adicionados aqui)
// ...

// GetGoogleLoginURL (porta de get_google_login_url)
func GetGoogleLoginURL(c *gin.Context) {
	cfg := config.AppConfig
	if cfg.GoogleClientID == "" || cfg.GoogleRedirectURI == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Google OAuth not configured."})
		return
	}
	
	conf := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURI, // O redirect é o DO FRONTEND
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
	
	// "offline" para refresh token (se necessário), "select_account" para forçar escolha
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce) 
	
	c.JSON(http.StatusOK, schemas.GoogleLoginUrlResponse{URL: url})
}

// GoogleCallback (porta de google_callback)
func GoogleCallback(c *gin.Context) {
	// (Este é um handler complexo que envolve:
	// 1. Bind do `code` do JSON
	// 2. Trocar o `code` por um token do Google (usando http client)
	// 3. Pedir user info do Google com esse token (usando http client)
	// 4. Chamar services.GetOrCreateByEmailOAuth
	// 5. Chamar createAndStoreTokens
	// 6. Chamar setTrustedDeviceCookie
	// 7. Retornar os tokens)
	
	c.JSON(http.StatusNotImplemented, gin.H{"detail": "Google Callback não implementado"})
}


// Logout (porta de logout)
func Logout(c *gin.Context) {
	var input schemas.RefreshTokenRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// (Porta de crud_refresh_token.revoke_refresh_token)
	tokenHash := services.HashToken(input.RefreshToken)
	result := database.DB.Model(&models.RefreshToken{}).Where("token_hash = ?", tokenHash).Update("is_revoked", true)
	
	if result.Error != nil {
		log.Printf("Erro ao revogar token: %v", result.Error)
	}

	// Apagar cookie
	c.SetCookie(config.AppConfig.CookieName, "", -1, "/", "", true, true)
	
	c.Status(http.StatusNoContent)
}