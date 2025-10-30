package handlers

import (
	"encoding/json"
	"errors"
	"fmt" // Importar fmt
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"go-auth-api/internal/schemas"
	"go-auth-api/internal/services"
	"log"
	"math/rand"
	"net/http"
	"encoding/hex" // Para device token
	"strconv"      // Para converter IDs string->uint
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

	// ***** CORREÇÃO PARA O PARSER DO SWAG *****
	// Em vez de: if err := db.Create(&dbToken).Error; err != nil { ... }
	// Separamos a atribuição do 'if' para evitar o erro de parsing do swag
	
	errDb := db.Create(&dbToken).Error
	if errDb != nil {
		log.Printf("Erro DB ao criar refresh token para user ID %d: %v", user.ID, errDb)
		return schemas.TokenResponse{}, errDb
	}
	// ***** FIM DA CORREÇÃO *****


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

	// Gerar token seguro
	plainTokenBytes := make([]byte, 32)
	_, err := rand.Read(plainTokenBytes)
	if err != nil {
		log.Printf("Erro ao gerar bytes aleatórios para device token: %v", err)
		return "", err
	}
	plainToken := hex.EncodeToString(plainTokenBytes) // 64 caracteres hex

	tokenHash := services.HashToken(plainToken)
	ip, ua := getSessionDetails(c)
	now := time.Now().UTC()
	// Tenta extrair info básica do user agent
	desc := ua
	if idx := strings.Index(ua, "("); idx != -1 {
		desc = strings.TrimSpace(ua[:idx])
	}
	if len(desc) > 50 { // Limita o tamanho
		desc = desc[:50]
	}
	desc = fmt.Sprintf("%s (em %s)", desc, now.Format("2006-01-02 15:04"))


	dbDevice := models.TrustedDevice{
		UserID:          user.ID,
		DeviceTokenHash: tokenHash,
		IPAddress:       &ip,
		UserAgent:       &ua,
		Description:     &desc,
		LastUsedAt:      &now, // Marca como usado agora
	}

	// ***** CORREÇÃO PARA O PARSER DO SWAG (Prevenção) *****
	errDb := db.Create(&dbDevice).Error
	if errDb != nil {
		log.Printf("Erro DB ao criar trusted device para user ID %d: %v", user.ID, errDb)
		return "", errDb
	}
	// ***** FIM DA CORREÇÃO *****

	// Determinar Secure baseado no schema (melhor seria verificar X-Forwarded-Proto em produção real)
	isSecure := c.Request.URL.Scheme == "https" || c.Request.Header.Get("X-Forwarded-Proto") == "https"


	c.SetCookie(
		cfg.CookieName,
		plainToken,
		int(cfg.TrustedDeviceCookieMaxAge.Seconds()),
		"/",                      // path
		"",                       // domain (vazio usa o domínio da requisição)
		isSecure,                 // secure
		true,                     // httpOnly
	)
	log.Printf("Cookie de dispositivo confiável (ID: %d) definido para user ID %d", dbDevice.ID, user.ID)

	return plainToken, nil
}

// Helper para limpar o cookie de device trust
func clearTrustedDeviceCookie(c *gin.Context) {
	cfg := config.AppConfig
	isSecure := c.Request.URL.Scheme == "https" || c.Request.Header.Get("X-Forwarded-Proto") == "https"
	c.SetCookie(
		cfg.CookieName,
		"",       // Valor vazio
		-1,       // MaxAge < 0 para expirar imediatamente
		"/",      // Path
		"",       // Domain
		isSecure, // Secure
		true,     // HttpOnly
	)
	log.Println("Cookie de dispositivo confiável removido.")
}


// @Summary      Login for access token
// @Description  Authenticates a user with email and password (form-data). Returns JWT tokens or an MFA challenge.
// @Tags         Authentication
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        credentials body schemas.LoginRequest true "Login Credentials"
// @Success      200 {object} schemas.TokenResponse "Login successful, tokens issued"
// @Success      200 {object} schemas.MFARequiredResponse "MFA verification required"
// @Failure      400 {object} map[string]string "Incorrect email/password, account locked, or inactive"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "Internal server error"
// @Router       /auth/token [post]
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
		// Verifica se o erro é ErrAccountLocked
		if errors.Is(err, services.ErrAccountLocked) {
			c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()}) // Usa a mensagem formatada do erro
		} else {
			// Outros erros de autenticação (email/senha incorreto, inativo, etc.)
			c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		}
		return
	}


	// 2. Lógica de Device Trust
	isDeviceTrusted := false
	cfg := config.AppConfig // Get config for cookie name
	cookie, err := c.Cookie(cfg.CookieName)
	if err == nil && cookie != "" {
		tokenHash := services.HashToken(cookie)
		trustedDevice, errDb := services.GetTrustedDeviceByTokenHash(tokenHash) // Chama a função correta
		if errDb == nil && trustedDevice.UserID == user.ID {
			isDeviceTrusted = true
			log.Printf("Login para %s: Dispositivo confiável detectado (ID: %d).", user.Email, trustedDevice.ID)
		}
	}

	// 3. Verificar se MFA é necessário
	if user.IsMfaEnabled && !isDeviceTrusted {
		mfaChallengeToken, err := services.CreateMFAChallengeToken(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not create MFA challenge"})
			return
		}

		log.Printf("Login para %s: MFA necessário (dispositivo não confiável), challenge token emitido.", user.Email)
		// Retorna 200 OK com o challenge (como no Python)
		c.JSON(http.StatusOK, schemas.MFARequiredResponse{
			Detail:            "MFA verification required",
			MFAChallengeToken: mfaChallengeToken,
		})
		return
	}

	// 4. Login bem-sucedido (MFA não habilitado ou device confiável)
	log.Printf("Login para %s: Sucesso. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, user, user.IsMfaEnabled) // mfa_passed=true se estava habilitado e foi pulado
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// @Summary      Verify MFA (OTP)
// @Description  Verifies the MFA OTP code after a successful password login. Returns JWT tokens on success.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        mfa_data body schemas.MFAVerifyRequest true "MFA Verification Payload (Challenge Token + OTP Code)"
// @Success      200 {object} schemas.TokenResponse "MFA verified, tokens issued"
// @Failure      400 {object} map[string]string "Invalid challenge token, invalid OTP, or user issue"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "Internal server error"
// @Router       /auth/mfa/verify [post]
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

	// 2. Encontrar utilizador
	var user models.User
	if err := database.DB.First(&user, "id = ?", userIDStr).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid user associated with MFA challenge"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "User is inactive"})
		return
	}
	if !user.IsMfaEnabled || user.OtpSecret == nil || *user.OtpSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MFA is not enabled for this user."})
		return
	}

	// 3. Validar OTP
	if !services.ValidateOTP(*user.OtpSecret, input.OTPCode) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid OTP code."})
		return
	}

	// 4. Sucesso! Emitir tokens
	log.Printf("Verificação MFA (OTP) bem-sucedida para %s. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, &user, true) // mfa_passed=true
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	// 5. CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE
	_, errCookie := setTrustedDeviceCookie(c, &user)
	if errCookie != nil {
		// Logar o erro, mas continuar - o login foi bem-sucedido
		log.Printf("AVISO: Falha ao setar cookie de dispositivo confiável para %s após verificação MFA: %v", user.Email, errCookie)
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// @Summary      Verify MFA (Recovery Code)
// @Description  Verifies an MFA recovery code after a successful password login. Returns JWT tokens on success.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        mfa_data body schemas.MFARecoveryRequest true "MFA Recovery Payload (Challenge Token + Recovery Code)"
// @Success      200 {object} schemas.TokenResponse "MFA verified, tokens issued"
// @Failure      400 {object} map[string]string "Invalid challenge token, invalid/used code, or user issue"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "Internal server error"
// @Router       /auth/mfa/verify-recovery [post]
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

	// 2. Encontrar utilizador
	var user models.User
	userID, _ := strconv.ParseUint(userIDStr, 10, 64) // Convert string to uint64 for service call
	if err := database.DB.First(&user, uint(userID)).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid user associated with MFA challenge"})
		return
	}
	if !user.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "User is inactive"})
		return
	}
	if !user.IsMfaEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MFA is not enabled for this user."})
		return
	}

	// 3. Validar Recovery Code
	validDbCode, errCode := services.GetValidRecoveryCode(user.ID, input.RecoveryCode) // Chama a função correta
	if errCode != nil {
		// O erro de GetValidRecoveryCode já indica se é inválido/usado ou erro DB
		c.JSON(http.StatusBadRequest, gin.H{"detail": errCode.Error()})
		return
	}

	// 4. Marcar como usado
	errMark := services.MarkRecoveryCodeAsUsed(validDbCode) // Chama a função correta
	if errMark != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error processing recovery code."})
		return
	}

	// 5. Sucesso! Emitir tokens
	log.Printf("Verificação MFA (RECOVERY CODE) bem-sucedida para %s. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, &user, true) // mfa_passed=true
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating tokens"})
		return
	}

	// 6. CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE
	_, errCookie := setTrustedDeviceCookie(c, &user)
	if errCookie != nil {
		log.Printf("AVISO: Falha ao setar cookie de dispositivo confiável para %s após uso de recovery code: %v", user.Email, errCookie)
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// @Summary      Get Google OAuth Login URL
// @Description  Returns the URL to redirect the user to for Google OAuth login.
// @Tags         Authentication
// @Produce      json
// @Success      200 {object} schemas.GoogleLoginUrlResponse "Google OAuth URL"
// @Failure      500 {object} map[string]string "Google OAuth not configured on server"
// @Router       /auth/google/login-url [get]
func GetGoogleLoginURL(c *gin.Context) {
	cfg := config.AppConfig
	if cfg.GoogleClientID == "" || cfg.GoogleRedirectURI == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Google OAuth not configured on server."})
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
	// TODO: Usar um state real em produção e validá-lo no callback
	url := conf.AuthCodeURL("state-string", oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	c.JSON(http.StatusOK, schemas.GoogleLoginUrlResponse{URL: url})
}

// @Summary      Google OAuth Callback
// @Description  Handles the callback from Google OAuth. Exchanges the code for user info, finds/creates a user, and returns JWT tokens.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        code_data body schemas.GoogleLoginRequest true "Google Auth Code Payload"
// @Success      200 {object} schemas.TokenResponse "Login successful, tokens issued"
// @Failure      400 {object} map[string]string "Invalid code, token, or Google email issue"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "OAuth not configured or Google API error"
// @Router       /auth/google/callback [post]
func GoogleCallback(c *gin.Context) {
	var input schemas.GoogleLoginRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}
	code := input.Code
	// TODO: Validar o parâmetro 'state' aqui se usar um state real

	cfg := config.AppConfig
	if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" || cfg.GoogleRedirectURI == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Google OAuth not configured on server."})
		return
	}

	conf := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURI, // O redirect esperado aqui é o mesmo usado para gerar a URL
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// 1. Trocar o 'code' por um token do Google
	ctx := c.Request.Context() // Usar o contexto da requisição
	googleToken, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Printf("Erro ao trocar código Google: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired authorization code."})
		return
	}

	if !googleToken.Valid() {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid token received from Google."})
		return
	}

	// 2. Obter informações do utilizador da Google
	client := conf.Client(ctx, googleToken)
	userInfoResp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Printf("Erro ao buscar userinfo do Google: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to fetch user info from Google."})
		return
	}
	defer userInfoResp.Body.Close()

	if userInfoResp.StatusCode != http.StatusOK {
		log.Printf("Erro do Google UserInfo API: Status %d", userInfoResp.StatusCode)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to fetch user info from Google."})
		return
	}

	var userInfo struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
		log.Printf("Erro ao decodificar resposta userinfo do Google: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to process user info from Google."})
		return
	}

	if userInfo.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Email not returned by Google."})
		return
	}
	if !userInfo.EmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Google email is not verified."})
		return
	}

	// 3. Encontrar ou Criar o utilizador na nossa BD
	user, err := services.GetOrCreateByEmailOAuth(userInfo.Email, userInfo.Name)
	if err != nil {
		log.Printf("Erro ao buscar/criar utilizador OAuth na BD para %s: %v", userInfo.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal error processing account."})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Account is deactivated."})
		return
	}

	// 4. Emitir os NOSSOS tokens JWT
	log.Printf("Login OAuth bem-sucedido para %s. Emitindo tokens.", user.Email)
	tokenResponse, err := createAndStoreTokens(c, user, true) // Login social é considerado como MFA passado
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error creating API tokens"})
		return
	}

	// 5. CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE
	_, errCookie := setTrustedDeviceCookie(c, user)
	if errCookie != nil {
		log.Printf("AVISO: Falha ao setar cookie de dispositivo confiável para %s após login Google: %v", user.Email, errCookie)
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// @Summary      Logout
// @Description  Revokes the provided refresh token (if any) and clears the trusted device cookie.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        refresh_request body schemas.RefreshTokenRequest false "Refresh Token to revoke"
// @Success      204 "Logout successful"
// @Router       /auth/logout [post]
func Logout(c *gin.Context) {
	var input schemas.RefreshTokenRequest
	// Tenta ler o refresh token do corpo JSON
	err := c.ShouldBindJSON(&input)
	if err == nil && input.RefreshToken != "" {
		// Revogar o refresh token fornecido
		tokenHash := services.HashToken(input.RefreshToken)
		revoked, errRevoke := services.RevokeRefreshTokenByHash(tokenHash) // Chama a função correta
		if errRevoke != nil && !errors.Is(errRevoke, gorm.ErrRecordNotFound) {
			log.Printf("Erro DB ao revogar refresh token: %v", errRevoke)
			// Continua mesmo assim para limpar o cookie
		}
		if revoked {
			log.Printf("Refresh token (hash: %s...) revogado durante logout.", tokenHash[:10])
		} else if errRevoke == nil {
			log.Printf("Refresh token (hash: %s...) não encontrado ou já revogado durante logout.", tokenHash[:10])
		}
	} else {
		// Se não veio refresh token no corpo, loga
		log.Printf("Logout chamado sem refresh token válido no corpo. Apenas limpando cookie.")
	}


	// Apagar cookie de dispositivo confiável independentemente de ter conseguido revogar o token
	clearTrustedDeviceCookie(c)

	c.Status(http.StatusNoContent)
}


// @Summary      Verify Email
// @Description  Activates a user's account using the verification token sent via email.
// @Tags         Authentication
// @Produce      json
// @Param        token path string true "Verification Token"
// @Success      200 {object} schemas.UserResponse "Email verified successfully, user activated"
// @Failure      400 {object} map[string]string "Invalid or expired verification token"
// @Failure      500 {object} map[string]string "Internal server error"
// @Router       /auth/verify-email/{token} [get]
func VerifyEmail(c *gin.Context) {
	token := c.Param("token") // Pega o token do path da URL
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Verification token is missing"})
		return
	}

	tokenHash := services.HashToken(token)
	now := time.Now().UTC()
	db := database.DB
	var user models.User

	// Encontrar utilizador pelo hash do token, verificando expiração e status
	err := db.Where("verification_token_hash = ? AND verification_token_expires > ? AND is_verified = ?", tokenHash, now, false).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or expired verification token"})
			return
		}
		log.Printf("Erro DB ao procurar token de verificação: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Error processing verification"})
		return
	}

	// Utilizador encontrado e token válido, atualizar utilizador
	user.IsActive = true
	user.IsVerified = true
	user.VerificationTokenHash = nil    // Limpar token
	user.VerificationTokenExpires = nil // Limpar expiração

	// ***** CORREÇÃO PARA O PARSER DO SWAG (Prevenção) *****
	errDb := db.Save(&user).Error
	if errDb != nil {
		log.Printf("Erro ao salvar utilizador após verificação: %v", errDb)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not finalize verification"})
		return
	}
	// ***** FIM DA CORREÇÃO *****

	log.Printf("Email verificado com sucesso para utilizador ID: %d (%s)", user.ID, user.Email)
	c.JSON(http.StatusOK, schemas.FormatUserResponse(&user))
}


// @Summary      Refresh Access Token
// @Description  Receives a valid refresh token and returns a new pair of access and refresh tokens (token rotation).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        refresh_request body schemas.RefreshTokenRequest true "Refresh Token Payload"
// @Success      200 {object} schemas.TokenResponse "Tokens refreshed successfully"
// @Failure      401 {object} map[string]string "Could not validate credentials (invalid/expired token)"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "Internal server error"
// @Router       /auth/refresh [post]
func RefreshToken(c *gin.Context) {
	var input schemas.RefreshTokenRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	credentialsException := gin.H{"detail": "Could not validate credentials"} // Mensagem padrão

	// 1. Validar o JWT do refresh token
	claims, err := services.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		log.Printf("Falha na validação do refresh token: %v", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}
	userIDStr := claims.Subject

	// 2. Verificar se o token (hash) existe no DB, não está revogado e não expirou
	tokenHash := services.HashToken(input.RefreshToken)
	dbToken, err := services.GetValidRefreshTokenByHash(tokenHash)
	if err != nil {
		log.Printf("Refresh token inválido (DB check) para user ID %s: %v", userIDStr, err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}

	// 3. Verificar se o User ID do token JWT corresponde ao do DB (segurança extra)
	if fmt.Sprint(dbToken.UserID) != userIDStr {
		log.Printf("ALERTA: User ID do refresh token JWT (%s) não corresponde ao do DB (%d)", userIDStr, dbToken.UserID)
		// Revogar o token suspeito por segurança
		services.RevokeRefreshTokenByHash(tokenHash) // Melhor esforço
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}

	// 4. Revogar o refresh token antigo que foi usado
	revoked, errRevoke := services.RevokeRefreshTokenByHash(tokenHash)
	if errRevoke != nil {
		log.Printf("Erro ao revogar refresh token antigo (hash: %s...) durante refresh: %v", tokenHash[:10], errRevoke)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "Error processing token rotation"})
		return
	}
	if !revoked {
		log.Printf("AVISO: Refresh token (hash: %s...) não encontrado ou já revogado ao tentar revogar durante refresh.", tokenHash[:10])
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException) // Tratar como inválido
		return
	}

	// 5. Buscar os dados do utilizador
	var user models.User
	userID, _ := strconv.ParseUint(userIDStr, 10, 64) // Converte string para uint64
	if err := database.DB.First(&user, uint(userID)).Error; err != nil {
		log.Printf("Utilizador ID %s (do refresh token) não encontrado no DB: %v", userIDStr, err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, credentialsException)
		return
	}

	if !user.IsActive {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "User is inactive"})
		return
	}

	// 6. Criar NOVOS tokens (access e refresh)
	// Ao refrescar, o MFA não foi verificado nesta interação específica
	newTokenResponse, err := createAndStoreTokens(c, &user, false) // mfaPassed = false
	if err != nil {
		log.Printf("Erro ao criar novos tokens durante refresh para user ID %d: %v", user.ID, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "Error generating new tokens"})
		return
	}

	log.Printf("Refresh token bem-sucedido para user ID %d. Novos tokens emitidos.", user.ID)
	c.JSON(http.StatusOK, newTokenResponse)
}

// @Summary      Enable MFA (Start)
// @Description  Starts the MFA enablement process for the authenticated user. Returns OTP URI and QR code.
// @Tags         Authentication
// @Produce      json
// @Success      200 {object} schemas.MFAEnableResponse "MFA setup details"
// @Failure      400 {object} map[string]string "MFA is already enabled"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/mfa/enable [post]
func EnableMFAStart(c *gin.Context) {
	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	if currentUser.IsMfaEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MFA is already enabled."})
		return
	}

	// Gerar segredo OTP
	key, err := services.GenerateOTP() // Função de auth_service.go
	if err != nil {
		log.Printf("Erro ao gerar OTP key para %s: %v", currentUser.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not generate OTP secret."})
		return
	}
	otpSecret := key.Secret()

	// Salvar segredo PENDENTE no utilizador
	err = services.SetPendingOTPSecret(currentUser, otpSecret)
	if err != nil {
		// O erro de SetPendingOTPSecret já é informativo (DB error ou already enabled)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// Gerar URI e QR Code
	otpURI := services.GenerateOTPAuthURL(key, currentUser.Email) // Função de auth_service.go
	qrCodeBase64, errQR := services.GenerateQRCodeBase64(otpURI)   // Função de auth_service.go
	if errQR != nil {
		// Logar erro, mas retornar a URI mesmo assim
		log.Printf("Erro ao gerar QR Code para %s: %v", currentUser.Email, errQR)
		qrCodeBase64 = "" // Retornar vazio se falhar
	}

	log.Printf("Iniciada habilitação MFA para %s. Segredo pendente salvo.", currentUser.Email)
	c.JSON(http.StatusOK, schemas.MFAEnableResponse{
		OTPUri:       otpURI,
		QRCodeBase64: qrCodeBase64,
	})
}


// @Summary      Enable MFA (Confirm)
// @Description  Confirms and activates MFA with the first valid OTP code. Returns user info and recovery codes.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        mfa_data body schemas.MFAConfirmRequest true "MFA Confirmation Payload (OTP Code)"
// @Success      200 {object} schemas.MFAConfirmResponse "MFA enabled, user details, and recovery codes"
// @Failure      400 {object} map[string]string "MFA already enabled or invalid OTP code"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/mfa/confirm [post]
func EnableMFAConfirm(c *gin.Context) {
	var input schemas.MFAConfirmRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	// Chamar o serviço para confirmar
	plainRecoveryCodes, err := services.ConfirmMFAEnable(currentUser, input.OTPCode)
	if err != nil {
		// Erro pode ser "already enabled", "no pending secret", "invalid OTP", ou erro DB/recovery
		statusCode := http.StatusInternalServerError
		if err.Error() == "invalid OTP code" || err.Error() == "MFA is already enabled" || err.Error() == "MFA setup was not initiated (no pending secret)" {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{"detail": err.Error()})
		return
	}

	// Sucesso! Retornar dados do utilizador atualizado e códigos de recuperação
	database.DB.First(&currentUser, currentUser.ID) // Recarregar

	c.JSON(http.StatusOK, schemas.MFAConfirmResponse{
		User:          schemas.FormatUserResponse(currentUser),
		RecoveryCodes: plainRecoveryCodes,
	})
}


// @Summary      Disable MFA
// @Description  Disables MFA for the authenticated user after verifying a current OTP code.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        mfa_data body schemas.MFADisableRequest true "MFA Disable Payload (OTP Code)"
// @Success      200 {object} schemas.UserResponse "MFA disabled successfully"
// @Failure      400 {object} map[string]string "MFA not enabled or invalid OTP code"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/mfa/disable [post]
func DisableMFA(c *gin.Context) {
	var input schemas.MFADisableRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	// Chamar o serviço para desabilitar
	err := services.DisableMFA(currentUser, input.OTPCode)
	if err != nil {
		// Erro pode ser "not enabled" ou "invalid OTP"
		statusCode := http.StatusInternalServerError
		if err.Error() == "invalid OTP code" || err.Error() == "MFA is not enabled" {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{"detail": err.Error()})
		return
	}

	// Sucesso! Retornar dados do utilizador atualizado
	database.DB.First(&currentUser, currentUser.ID) // Recarregar
	c.JSON(http.StatusOK, schemas.FormatUserResponse(currentUser))
}

// @Summary      Forgot Password
// @Description  Requests a password reset email for a user. Always returns 202 Accepted.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        email_request body schemas.ForgotPasswordRequest true "Forgot Password Request (Email)"
// @Success      202 {object} map[string]string "Request accepted"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Router       /auth/forgot-password [post]
func ForgotPassword(c *gin.Context) {
	var input schemas.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	db := database.DB
	var user models.User

	// Procurar utilizador pelo email
	err := db.Where("email = ?", input.Email).First(&user).Error
	// Resposta ambígua de propósito, mesmo que o utilizador não exista ou esteja inativo
	responseMsg := "If a user with that email exists and is active, a password reset link will be sent."

	if err == nil && user.IsActive {
		// Utilizador encontrado e ativo, gerar token e enviar email
		resetTokenPlain, errGen := services.GeneratePasswordResetToken(&user)
		if errGen != nil {
			// Logar o erro interno, mas retornar a mensagem ambígua
			log.Printf("Erro ao gerar token de reset para %s: %v", input.Email, errGen)
		} else {
			// Enviar email em background
			go services.SendPasswordResetEmail(user.Email, resetTokenPlain)
			log.Printf("Solicitação de reset de senha para: %s. Email enviado (em background).", user.Email)
		}
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		// Erro de DB ao procurar o utilizador
		log.Printf("Erro DB ao procurar email %s para forgot password: %v", input.Email, err)
	} else {
		// Utilizador não encontrado ou inativo
		log.Printf("Tentativa de forgot password para email não existente ou inativo: %s", input.Email)
	}

	// Sempre retorna 202 Accepted com a mensagem genérica
	c.JSON(http.StatusAccepted, gin.H{"msg": responseMsg})
}


// @Summary      Reset Password
// @Description  Sets a new password using a valid reset token.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        reset_request body schemas.ResetPasswordRequest true "Reset Password Request (Token + New Password)"
// @Success      200 {object} schemas.UserResponse "Password reset successful"
// @Failure      400 {object} map[string]string "Invalid or expired token"
// @Failure      422 {object} map[string]string "Validation error on input (e.g., weak password)"
// @Failure      500 {object} map[string]string "Internal server error"
// @Router       /auth/reset-password [post]
func ResetPassword(c *gin.Context) {
	var input schemas.ResetPasswordRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}

	// 1. Validar o token e encontrar o utilizador associado
	user, err := services.GetUserByValidResetToken(input.Token)
	if err != nil {
		// O erro de GetUserByValidResetToken já é informativo q.b.
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// 2. Redefinir a senha do utilizador encontrado
	err = services.ResetPassword(user, input.NewPassword)
	if err != nil {
		// O erro de ResetPassword pode ser erro de DB ou processamento
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// 3. Retornar os dados do utilizador atualizado (sem senha)
	c.JSON(http.StatusOK, schemas.FormatUserResponse(user))
}


// @Summary      Get Active Sessions
// @Description  Lists all active login sessions (valid refresh tokens) for the authenticated user.
// @Tags         Authentication
// @Produce      json
// @Success      200 {array} schemas.SessionInfo "List of active sessions"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/sessions [get]
func GetActiveSessions(c *gin.Context) {
	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	sessions, err := services.GetActiveSessionsForUser(currentUser.ID) // Chama a função correta
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to retrieve sessions."})
		return
	}

	// Mapear para o schema de resposta
	responseSessions := make([]schemas.SessionInfo, len(sessions))
	for i, s := range sessions {
		responseSessions[i] = schemas.SessionInfo{
			ID:        s.ID,
			UserAgent: s.UserAgent,
			IPAddress: s.IPAddress,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
		}
	}

	c.JSON(http.StatusOK, responseSessions)
}

// @Summary      Logout All Sessions
// @Description  Logs out the user from all devices by revoking all refresh tokens and clearing the current trusted device cookie.
// @Tags         Authentication
// @Produce      json
// @Success      204 "Logout successful"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/sessions/all [delete]
func LogoutAllSessions(c *gin.Context) {
	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	revokedCount, err := services.RevokeAllRefreshTokensForUser(currentUser.ID, "") // "" para não excluir nenhum
	if err != nil {
		log.Printf("Erro ao revogar todas as sessoes para user ID %d: %v", currentUser.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to revoke sessions."})
		return
	}
	log.Printf("Utilizador %s revogou todas as %d sessoes.", currentUser.Email, revokedCount)

	// Limpar cookie do dispositivo atual
	clearTrustedDeviceCookie(c)

	c.Status(http.StatusNoContent)
}

// @Summary      Logout All Other Sessions
// @Description  Logs out the user from all devices *except* the current one (identified by the refresh token in the body).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        refresh_request body schemas.RefreshTokenRequest true "Current Session Refresh Token"
// @Success      204 "Logout successful"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      403 {object} map[string]string "Forbidden (Invalid token)"
// @Failure      422 {object} map[string]string "Validation error on input"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/sessions/all-except-current [post]
func LogoutAllExceptCurrentSession(c *gin.Context) {
	var input schemas.RefreshTokenRequest // Pega o token atual do corpo
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": "Refresh token required in body."})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	tokenHashToExclude := services.HashToken(input.RefreshToken)

	// Validar se o token a excluir pertence ao usuário (opcional mas bom)
	activeSessions, err := services.GetActiveSessionsForUser(currentUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to validate current session."})
		return
	}
	isValidToken := false
	for _, s := range activeSessions {
		if s.TokenHash == tokenHashToExclude {
			isValidToken = true
			break
		}
	}
	if !isValidToken {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Provided refresh token is invalid or does not belong to this user."})
		return
	}


	revokedCount, err := services.RevokeAllRefreshTokensForUser(currentUser.ID, tokenHashToExclude)
	if err != nil {
		log.Printf("Erro ao revogar outras sessoes para user ID %d: %v", currentUser.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to revoke other sessions."})
		return
	}
	log.Printf("Utilizador %s revogou %d outras sessoes.", currentUser.Email, revokedCount)

	c.Status(http.StatusNoContent)
}

// @Summary      Logout Specific Session
// @Description  Logs out a specific session by its ID.
// @Tags         Authentication
// @Produce      json
// @Param        session_id path int true "Session ID"
// @Success      204 "Logout successful"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      404 {object} map[string]string "Session not found or doesn't belong to user"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/sessions/{session_id} [delete]
func LogoutSpecificSession(c *gin.Context) {
	sessionIDStr := c.Param("session_id")
	sessionID, err := strconv.ParseUint(sessionIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid session ID format."})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	dbToken, err := services.GetRefreshTokenByIDForUser(uint(sessionID), currentUser.ID) // Chama a função correta
	if err != nil {
		// Erro já indica se não encontrado ou não pertence ao usuário
		c.JSON(http.StatusNotFound, gin.H{"detail": err.Error()})
		return
	}

	revoked, errRevoke := services.RevokeRefreshTokenByID(dbToken) // Chama a função correta
	if errRevoke != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to revoke session."})
		return
	}

	if revoked {
		log.Printf("Utilizador %s revogou a sessao ID %d.", currentUser.Email, sessionID)
	} else {
		log.Printf("Sessao ID %d já estava revogada ou não foi encontrada para user %s.", sessionID, currentUser.Email)
	}

	c.Status(http.StatusNoContent)
}


// @Summary      Get Trusted Devices
// @Description  Lists all devices marked as "trusted" for the authenticated user.
// @Tags         Authentication
// @Produce      json
// @Success      200 {array} schemas.TrustedDeviceInfo "List of trusted devices"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/devices [get]
func GetTrustedDevices(c *gin.Context) {
	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	devices, err := services.GetTrustedDevicesForUser(currentUser.ID) // Chama a função correta
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to retrieve trusted devices."})
		return
	}

	// Mapear para o schema de resposta
	responseDevices := make([]schemas.TrustedDeviceInfo, len(devices))
	for i, d := range devices {
		responseDevices[i] = schemas.TrustedDeviceInfo{
			ID:          d.ID,
			Description: d.Description,
			IPAddress:   d.IPAddress,
			UserAgent:   d.UserAgent,
			CreatedAt:   d.CreatedAt,
			LastUsedAt:  d.LastUsedAt,
		}
	}

	c.JSON(http.StatusOK, responseDevices)
}

// @Summary      Forget Trusted Device
// @Description  Removes a specific device from the trusted list by its ID. Clears the cookie if it matches the current device.
// @Tags         Authentication
// @Produce      json
// @Param        device_id path int true "Device ID"
// @Success      204 "Device forgotten successfully"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      404 {object} map[string]string "Device not found or doesn't belong to user"
// @Failure      500 {object} map[string]string "Internal server error"
// @Security     BearerAuth
// @Router       /auth/devices/{device_id} [delete]
func ForgetTrustedDevice(c *gin.Context) {
	deviceIDStr := c.Param("device_id")
	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid device ID format."})
		return
	}

	currentUserInterface, _ := c.Get("currentUser")
	currentUser := currentUserInterface.(*models.User)

	dbDevice, err := services.GetTrustedDeviceByIDForUser(uint(deviceID), currentUser.ID) // Chama a função correta
	if err != nil {
		// Erro já indica se não encontrado ou não pertence ao usuário
		c.JSON(http.StatusNotFound, gin.H{"detail": err.Error()})
		return
	}

	// Verificar se o cookie atual corresponde ao dispositivo a ser removido
	cfg := config.AppConfig
	currentCookie, _ := c.Cookie(cfg.CookieName) // Ignora erro se cookie não existir
	shouldClearCookie := false
	if currentCookie != "" {
		currentHash := services.HashToken(currentCookie)
		if currentHash == dbDevice.DeviceTokenHash {
			shouldClearCookie = true
		}
	}

	errDelete := services.DeleteTrustedDevice(dbDevice) // Chama a função correta
	if errDelete != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to forget trusted device."})
		return
	}
	log.Printf("Utilizador %s removeu o dispositivo confiavel ID %d.", currentUser.Email, deviceID)

	// Limpar o cookie SE ele corresponder ao dispositivo removido
	if shouldClearCookie {
		clearTrustedDeviceCookie(c)
	}

	c.Status(http.StatusNoContent)
}